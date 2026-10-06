"""Synthetic adverse checks; these never establish provider qualification."""
import copy
from datetime import datetime, timezone
import unittest
from clock_adapter import adapt, qualify_pair, rejection_checks
from clock_gate import ClockGate


def fixture(good=4):
    stamp = int(datetime(2026, 10, 6, 5, 0, 0, tzinfo=timezone.utc).timestamp()) * 1_000_000_000
    return {'wall_ns': stamp, 'mono_ns': 10_000_000_000,
            'captured_wall_ns': stamp + 10_000_000, 'captured_mono_ns': 10_010_000_000,
            'ntpdata': f'Remote address : 162.159.200.123 (A29FC87B)\nAuthenticated : Yes\nMode : Server\nVersion : 4\nStratum : 3\nTotal good RX : {good}\nTotal valid RX : {good}\nLeap status : Normal\n',
            'authdata': '162.159.200.123 NTS 1 30 128 1 0 0 8 64\n',
            'tracking': 'Reference ID : A29FC87B (162.159.200.123)\nStratum : 4\nRef time (UTC) : Tue Oct 06 05:00:00 2026\nSystem time : 0.001000000 seconds slow of NTP time\nRoot delay : 0.020000000 seconds\nRoot dispersion : 0.001000000 seconds\nSkew : 1.0 ppm\nLeap status : Normal\n',
            'sources': '^* 162.159.200.123 3 0 377 0 +1ms[+1ms] +/- 20ms\n',
            **{c+'_returncode':0 for c in ('ntpdata','authdata','tracking','sources')}}


class AdapterTests(unittest.TestCase):
    def test_offset_bound_and_nonlive_pair(self):
        a, detail = adapt(fixture())
        self.assertEqual(a.observed_utc_ns - a.captured_wall_ns, 1_000_000)
        self.assertGreaterEqual(a.uncertainty_ns, 22_000_000)
        b = fixture(5)
        result = qualify_pair(fixture(), b, b['captured_wall_ns'], b['captured_mono_ns'])
        self.assertFalse(result['production_competence'])
        self.assertEqual(len(rejection_checks(a)), 9)

    def test_denial_vectors(self):
        vectors = [
            ('ntpdata','Yes','No'),('ntpdata','Mode : Server','Mode : Client'),
            ('ntpdata','Version : 4','Version : 3'),('ntpdata','Stratum : 3','Stratum : 0'),
            ('ntpdata','good RX : 4','good RX : 0'),
            ('authdata',' NTS ',' SK '),('authdata','NTS 1','NTS 0'),
            ('authdata','1 30 128 1 0 0 8 64','1 30 128 1 0 1 8 64'),
            ('tracking','A29FC87B','00000000'),('tracking','Normal','Not synchronised'),
            ('tracking','0.020000000','-0.020000000'),('tracking','0.001000000 seconds\\nSkew','NaN seconds\\nSkew'),
            ('sources','^*','^?'),('sources','377 0','377 6')]
        for field, old, new in vectors:
            with self.subTest(field=field, old=old):
                s = fixture()
                old, new = old.replace('\\n','\n'), new.replace('\\n','\n')
                self.assertIn(old,s[field])
                s[field] = s[field].replace(old,new)
                with self.assertRaises((ValueError, KeyError)): adapt(s)

    def test_replayed_packet_counter(self):
        s=fixture()
        with self.assertRaises(ValueError): qualify_pair(s,copy.deepcopy(s),s['captured_wall_ns'],s['captured_mono_ns'])

    def test_failed_command_duplicate_and_stale(self):
        for change in ('command','duplicate','stale','slow','future'):
            s=fixture()
            if change=='command':s['tracking_returncode']=1
            if change=='duplicate':s['ntpdata']+='Authenticated : Yes\n'
            if change=='stale':s['captured_wall_ns']+=6_000_000_000
            if change=='slow':s['captured_mono_ns']+=2_000_000_000
            if change=='future':s['captured_wall_ns']-=2_000_000_000
            with self.subTest(change=change),self.assertRaises(ValueError):adapt(s)

if __name__=='__main__': unittest.main()
