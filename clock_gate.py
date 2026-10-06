"""Generic non-live clock gate; proposed limits remain unratified."""
from dataclasses import dataclass

@dataclass(frozen=True)
class ClockEvidence:
    provider: str
    observed_utc_ns: int
    captured_wall_ns: int
    captured_mono_ns: int
    uncertainty_ns: int
    synchronized: bool
    degradation: str
    time_scale: str
    leap_mode: str
    evidence_ref: str
    authenticated: bool
    origin: str


@dataclass(frozen=True)
class CandidatePolicy:
    max_age_ns: int = 5_000_000_000
    max_uncertainty_ns: int = 500_000_000
    max_clock_step_ns: int = 100_000_000
    status: str = 'PROPOSED_NONLIVE_TEST_VALUES_NOT_RATIFIED'


class ClockGate:
    def __init__(self, *, provider, appointment, policy=CandidatePolicy(), allow_fixture=False):
        self.provider, self.appointment, self.policy = provider, appointment, policy
        self.allow_fixture = allow_fixture

    def validate(self, sample, *, wall_ns, mono_ns):
        if not self.appointment or self.appointment.get('scope') != 'NONLIVE_TEST_ONLY':
            raise PermissionError('CLOCK_CUSTODY_ABSENT')
        if type(sample) is not ClockEvidence or sample.provider != self.provider:
            raise PermissionError('CLOCK_SOURCE_UNAVAILABLE_OR_WRONG')
        if not sample.synchronized or sample.degradation != 'HEALTHY':
            raise PermissionError('CLOCK_UNSYNCHRONIZED_OR_DEGRADED')
        if sample.time_scale != 'UTC' or sample.leap_mode not in ('NO_WARNING', 'INSERT_SECOND', 'DELETE_SECOND'):
            raise PermissionError('CLOCK_SCALE_OR_LEAP_UNKNOWN')
        if not sample.authenticated or (sample.origin == 'DETERMINISTIC_FIXTURE' and not self.allow_fixture):
            raise PermissionError('CLOCK_AUTHENTICATION_UNESTABLISHED')
        fields = [sample.observed_utc_ns, sample.captured_wall_ns, sample.captured_mono_ns, sample.uncertainty_ns]
        if any(type(v) is not int or v < 0 for v in fields) or not sample.evidence_ref:
            raise PermissionError('CLOCK_EVIDENCE_INVALID')
        age = mono_ns - sample.captured_mono_ns
        if age < 0 or age > self.policy.max_age_ns:
            raise PermissionError('CLOCK_SAMPLE_STALE_OR_FUTURE')
        if sample.uncertainty_ns > self.policy.max_uncertainty_ns:
            raise PermissionError('CLOCK_UNCERTAINTY_EXCEEDED')
        if abs((wall_ns - sample.captured_wall_ns) - age) > self.policy.max_clock_step_ns:
            raise PermissionError('CLOCK_DISCONTINUITY')
        if abs(sample.observed_utc_ns - sample.captured_wall_ns) > sample.uncertainty_ns + self.policy.max_clock_step_ns:
            raise PermissionError('CLOCK_FUTURE_OR_UNBOUNDED_OFFSET')
        return sample.observed_utc_ns + age

    def dispatch_check(self, captured, fresh, *, wall_ns, mono_ns):
        self.validate(captured, wall_ns=wall_ns, mono_ns=mono_ns)
        self.validate(fresh, wall_ns=wall_ns, mono_ns=mono_ns)
        if fresh.evidence_ref == captured.evidence_ref:
            raise PermissionError('CLOCK_REACQUISITION_REQUIRED')
        return {'gate': 'NONLIVE_CLOCK_PASS', 'capture_ref': captured.evidence_ref,
                'dispatch_ref': fresh.evidence_ref, 'numeric_policy': self.policy.status,
                'production_competence': False}

