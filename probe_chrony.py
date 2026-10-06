"""Bounded isolated NTS diagnostic. Never establishes production or clock-gate standing."""
import argparse
import hashlib
import json
import os
import pwd
from pathlib import Path
import shutil
import subprocess
import tempfile
import time


def assess(ntpdata, authdata):
    fields = {}
    for line in ntpdata.splitlines():
        if ':' in line:
            key, value = line.split(':', 1)
            key = key.strip()
            if key in fields:
                raise ValueError('duplicate ntpdata field')
            fields[key] = value.strip()
    rows = [line.split() for line in authdata.splitlines()
            if len(line.split()) == 10 and line.split()[1] == 'NTS']
    good = int(fields.get('Total good RX', '0'))
    valid = int(fields.get('Total valid RX', '0'))
    authenticated = (len(rows) == 1 and fields.get('Authenticated') == 'Yes'
                     and int(rows[0][2]) > 0 and int(rows[0][7]) == 0
                     and int(rows[0][8]) > 0 and 0 < good <= valid
                     and fields.get('Mode') == 'Server'
                     and 0 < int(fields.get('Stratum', '0')) < 16
                     and fields.get('Leap status') in ('Normal', 'Insert second', 'Delete second')
                     and rows[0][0] == fields.get('Remote address', '').split()[0])
    return {'authenticated_provider_response_observed': authenticated,
            'total_good_rx': good, 'total_valid_rx': valid,
            'fresh_dispatch_sample_established': False,
            'production_competence': False}


def collect(timeout=45):
    if not 1 <= timeout <= 50:
        raise ValueError('timeout must be 1..50 seconds')
    base = {'provider': 'time.cloudflare.com', 'production_competence': False,
            'status': 'PROBE_UNAVAILABLE', 'changes_system_clock': False}
    if not shutil.which('chronyd') or not shutil.which('chronyc'):
        return dict(base, reason='CHRONY_NOT_INSTALLED')
    with tempfile.TemporaryDirectory(prefix='nts-probe-') as directory:
        root = Path(directory)
        sock = root / 'command.sock'
        config = ('server time.cloudflare.com iburst nts\n'
                  'port 0\ncmdport 0\n'
                  f'bindcmdaddress {sock}\npidfile {root / "pid"}\n')
        (root / 'chrony.conf').write_text(config)
        # -x prohibits clock adjustment; -d keeps this owned process in foreground.
        log = open(root / 'daemon.log', 'w+')
        process = subprocess.Popen(['chronyd', '-x', '-U', '-u', pwd.getpwuid(os.getuid()).pw_name, '-d', '-f', str(root / 'chrony.conf')],
                                   stdout=log, stderr=subprocess.STDOUT)
        snapshots = []
        try:
            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline and process.poll() is None:
                snapshot = {'wall_ns': time.time_ns(), 'mono_ns': time.monotonic_ns()}
                for command in ('ntpdata', 'authdata', 'tracking', 'sources'):
                    try:
                        result = subprocess.run(['chronyc', '-n', '-h', str(sock), command],
                                                capture_output=True, text=True, timeout=2,
                                                env=dict(os.environ, LC_ALL='C'))
                        snapshot[command] = result.stdout
                        snapshot[command + '_returncode'] = result.returncode
                    except subprocess.TimeoutExpired:
                        snapshot[command] = ''
                        snapshot[command + '_returncode'] = -1
                try:
                    snapshot['assessment'] = assess(snapshot['ntpdata'], snapshot['authdata'])
                except (ValueError, IndexError):
                    snapshot['assessment'] = {'authenticated_provider_response_observed': False}
                snapshots.append(snapshot)
                if snapshot['assessment']['authenticated_provider_response_observed']:
                    break
                time.sleep(min(1, max(0, deadline - time.monotonic())))
        finally:
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait()
            log.seek(0)
            daemon_log = log.read()
            log.close()
        observed = bool(snapshots and snapshots[-1]['assessment']['authenticated_provider_response_observed'])
        return dict(base, status='AUTHENTICATED_DIAGNOSTIC_OBSERVED' if observed else 'PROBE_UNAVAILABLE',
                    snapshots=snapshots, daemon_log=daemon_log,
                    configuration_sha256=hashlib.sha256(config.encode()).hexdigest(),
                    qualification='OPEN_REQUIRES_FRESHNESS_UNCERTAINTY_AND_END_TO_END_REVIEW')


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--timeout', type=int, default=45)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    args.output.write_text(json.dumps(collect(args.timeout), indent=2) + '\n')
