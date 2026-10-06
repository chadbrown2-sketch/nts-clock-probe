"""Non-live chrony NTS adapter. Local chrony is the packet-authentication boundary."""
from dataclasses import asdict, replace
from datetime import datetime, timezone
from decimal import Decimal, InvalidOperation, ROUND_CEILING
import hashlib
import ipaddress
import json
import re

from clock_gate import ClockEvidence, ClockGate


def fields(text):
    result = {}
    for line in text.splitlines():
        if ':' not in line:
            continue
        key, value = line.split(':', 1)
        key = key.strip()
        if key in result:
            raise ValueError('DUPLICATE_FIELD')
        result[key] = value.strip()
    return result


def ns(value):
    number = Decimal(value.split()[0])
    if not number.is_finite():
        raise ValueError('NONFINITE_MEASUREMENT')
    return int((number * 1_000_000_000).to_integral_value(rounding=ROUND_CEILING))


def adapt(snapshot):
    """Caller owns the sole configured-source daemon; arbitrary text is not trusted input."""
    if any(snapshot.get(c + '_returncode') != 0 for c in ('ntpdata', 'authdata', 'tracking', 'sources')):
        raise ValueError('COMMAND_FAILED')
    p, t = fields(snapshot['ntpdata']), fields(snapshot['tracking'])
    address = p['Remote address'].split()[0]
    ipaddress.ip_address(address)
    auth = [row.split() for row in snapshot['authdata'].splitlines()
            if len(row.split()) == 10 and row.split()[0] == address]
    if len(auth) != 1 or auth[0][1] != 'NTS' or int(auth[0][2]) <= 0:
        raise ValueError('NTS_KEY_ESTABLISHMENT_ABSENT')
    if int(auth[0][7]) != 0 or int(auth[0][8]) <= 0 or int(auth[0][3]) not in (15, 30):
        raise ValueError('NTS_AUTHENTICATION_DEGRADED')
    if p['Authenticated'] != 'Yes' or p['Mode'] != 'Server' or p['Version'] != '4':
        raise ValueError('PACKET_NOT_AUTHENTICATED_SERVER_NTP4')
    good, valid = int(p['Total good RX']), int(p['Total valid RX'])
    if not 0 < good <= valid:
        raise ValueError('NO_GOOD_MEASUREMENT')
    source_rows = [row.split() for row in snapshot['sources'].splitlines()
                   if row.startswith('^*')]
    if len(source_rows) != 1 or source_rows[0][1] != address:
        raise ValueError('PROVIDER_NOT_SELECTED')
    source = source_rows[0]
    if not source[5].isdigit() or int(source[5]) > 5:
        raise ValueError('SOURCE_MEASUREMENT_STALE')
    if not 0 < int(p['Stratum']) < 15 or int(t['Stratum']) != int(p['Stratum']) + 1:
        raise ValueError('STRATUM_CORRESPONDENCE_INVALID')
    expected_id = p['Remote address'].split('(')[1].split(')')[0]
    if t['Reference ID'].split()[0] != expected_id:
        raise ValueError('TRACKING_SOURCE_MISMATCH')
    leaps = {'Normal': 'NO_WARNING', 'Insert second': 'INSERT_SECOND', 'Delete second': 'DELETE_SECOND'}
    if t['Leap status'] not in leaps or t['Leap status'] != p['Leap status']:
        raise ValueError('LEAP_OR_SYNCHRONIZATION_UNESTABLISHED')
    ref_ns = int(datetime.strptime(t['Ref time (UTC)'], '%a %b %d %H:%M:%S %Y')
                 .replace(tzinfo=timezone.utc).timestamp()) * 1_000_000_000
    age = snapshot['captured_wall_ns'] - ref_ns
    # Tracking display rounds to seconds. Permit only this explicit one-second granularity.
    if age < -1_000_000_000 or age > 5_000_000_000:
        raise ValueError('TRACKING_MEASUREMENT_STALE_OR_FUTURE')
    match = re.fullmatch(r'([0-9.]+) seconds (fast|slow) of NTP time', t['System time'])
    if not match:
        raise ValueError('OFFSET_FORMAT_UNKNOWN')
    offset = ns(match.group(1)) * (-1 if match.group(2) == 'fast' else 1)
    delay, dispersion = ns(t['Root delay']), ns(t['Root dispersion'])
    skew = Decimal(t['Skew'].split()[0])
    if delay < 0 or dispersion < 0 or not skew.is_finite() or skew < 0:
        raise ValueError('UNCERTAINTY_INVALID')
    elapsed = snapshot['captured_mono_ns'] - snapshot['mono_ns']
    if elapsed < 0 or elapsed > 1_000_000_000:
        raise ValueError('ACQUISITION_TOO_SLOW')
    growth = int((skew * max(0, age) / 1_000_000).to_integral_value(rounding=ROUND_CEILING))
    # Conservative host-clock error bound from chrony: |offset| + root distance.
    uncertainty = abs(offset) + dispersion + (delay + 1) // 2 + elapsed + growth
    ref = hashlib.sha256(json.dumps(snapshot, sort_keys=True).encode()).hexdigest()
    # Backdate gate capture to the measurement, including display granularity.
    # Reading cached chrony state must not refresh the underlying sample's age.
    measured_age = max(0, age) + 1_000_000_000
    sample_wall = snapshot['captured_wall_ns'] - measured_age
    sample_mono = snapshot['captured_mono_ns'] - measured_age
    if sample_mono < 0:
        raise ValueError('MONOTONIC_MEASUREMENT_TIME_INVALID')
    sample = ClockEvidence('time.cloudflare.com', sample_wall + offset,
                           sample_wall, sample_mono, uncertainty,
                           True, 'HEALTHY', 'UTC', leaps[t['Leap status']], 'sha256:' + ref,
                           True, 'OWNED_CHRONY_NTS_DAEMON')
    return sample, {'address': address, 'good_rx': good, 'reference_time_ns': ref_ns,
                    'measurement_age_upper_ns': measured_age, 'uncertainty_ns': uncertainty,
                    'trust_boundary': 'owned sole-source chronyd with certificate verification enabled',
                    'production_competence': False}


def qualify_pair(capture, fresh, wall_ns, mono_ns):
    a, ar = adapt(capture)
    b, br = adapt(fresh)
    if ar['address'] != br['address'] or br['good_rx'] <= ar['good_rx']:
        raise ValueError('NEW_AUTHENTICATED_MEASUREMENT_REQUIRED')
    gate = ClockGate(provider='time.cloudflare.com', appointment={'scope': 'NONLIVE_TEST_ONLY'})
    result = gate.dispatch_check(a, b, wall_ns=wall_ns, mono_ns=mono_ns)
    return dict(result, capture=asdict(a), fresh=asdict(b), capture_details=ar, fresh_details=br,
                qualified_scope='CLOCK_ONLY_NONLIVE_NO_APPLICATION_SOURCE_INTEGRATION')


def rejection_checks(sample):
    gate = ClockGate(provider='time.cloudflare.com', appointment={'scope': 'NONLIVE_TEST_ONLY'})
    variants = {'unauthenticated': replace(sample, authenticated=False),
                'degraded': replace(sample, degradation='DEGRADED'),
                'unsynchronized': replace(sample, synchronized=False),
                'uncertainty': replace(sample, uncertainty_ns=501_000_000),
                'unknown_leap': replace(sample, leap_mode='UNKNOWN'),
                'wrong_provider': replace(sample, provider='other')}
    result = {}
    for name, bad in variants.items():
        try:
            gate.validate(bad, wall_ns=sample.captured_wall_ns, mono_ns=sample.captured_mono_ns)
        except PermissionError as exc:
            result[name] = str(exc)
        else:
            raise AssertionError('gate accepted ' + name)
    for name, wall, mono in [('stale', sample.captured_wall_ns + 6_000_000_000, sample.captured_mono_ns + 6_000_000_000),
                             ('clock_step', sample.captured_wall_ns + 200_000_000, sample.captured_mono_ns)]:
        try:
            gate.validate(sample, wall_ns=wall, mono_ns=mono)
        except PermissionError as exc:
            result[name] = str(exc)
        else:
            raise AssertionError('gate accepted ' + name)
    try:
        gate.dispatch_check(sample, sample, wall_ns=sample.captured_wall_ns, mono_ns=sample.captured_mono_ns)
    except PermissionError as exc:
        result['reused_evidence'] = str(exc)
    else:
        raise AssertionError('gate accepted reused evidence')
    return result
