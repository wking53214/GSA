"""
ure_engine.py — operational-health regime engine for the GSA gateway
====================================================================
This consolidates the multi-module URE redesign into a single drop-in module
(the gateway imports GatewayHealthEngine + ClassificationResult from here).

Kept from the redesign (genuine improvements):
  * StateVector — six normalized [0,1] "pressure" dimensions. Mapping raw gateway
    telemetry onto pressures is a cleaner seam than the old SystemMetricsTelemetry
    and avoids the count-vs-rate scale problem.
  * TelemetryAdapter — telemetry dict -> StateVector.
  * SystemRegime + health_status, TrajectoryEngine.

Fixed here:
  1. ENERGY RECENTERED. The redesign used 1.5*sigmoid(Σ pressure²), whose floor is
     0.75 at zero load, which made NOMINAL and RECOVERING mathematically unreachable.
     Energy is now 1.5*tanh(Σ pressure²/2): exactly 0 at zero pressure, saturating
     toward 1.5. The regime bands are recalibrated so all six regimes are reachable
     and there is no UNKNOWN dead zone (verified in __main__).
  2. DEAD SUBSYSTEMS REMOVED. AttackMemoryExchange / BehavioralVaccineEngine /
     RecoveryPlanner were instantiated but never called. Adversarial *learning*
     feeds the risk score, not operational-health classification — it belongs in a
     risk/policy adapter, not here. Recovery planning is a response concern, not a
     classification one. Both are out; this module does one thing.
  3. ZERO is a real class constant, not an accidental dataclass field.
  4. Trend is computed once (TrajectoryEngine), not twice.
"""
from __future__ import annotations

import math
import time
from collections import deque
from dataclasses import asdict, dataclass
from enum import Enum
from typing import Any, Deque, Dict, Tuple


def _clamp(x: float, lo: float = 0.0, hi: float = 1.0) -> float:
    return max(lo, min(hi, x))


# ---------------------------------------------------------------------------
# State vector: six normalized pressures
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class StateVector:
    threat_pressure: float
    latency_pressure: float
    failure_pressure: float
    drift_pressure: float
    adversarial_pressure: float
    resource_pressure: float
    timestamp: float


# class constant (assigned AFTER the class so it is NOT a dataclass field)
StateVector.ZERO = StateVector(0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0)


# ---------------------------------------------------------------------------
# Regimes
# ---------------------------------------------------------------------------
class SystemRegime(str, Enum):
    NOMINAL = "NOMINAL"
    ADAPTING = "ADAPTING"
    RECOVERING = "RECOVERING"
    STRESSED = "STRESSED"
    ATTACKED = "ATTACKED"
    CASCADING = "CASCADING"
    UNKNOWN = "UNKNOWN"

    @property
    def health_status(self) -> str:
        if self in (SystemRegime.NOMINAL, SystemRegime.RECOVERING, SystemRegime.ADAPTING):
            return "NEUTRAL"
        if self in (SystemRegime.STRESSED, SystemRegime.ATTACKED):
            return "RISK_INCREASING"
        if self is SystemRegime.CASCADING:
            return "REGRESSIVE"
        return "UNKNOWN"


# ---------------------------------------------------------------------------
# Energy (recentered) + trajectory
# ---------------------------------------------------------------------------
# weights per pressure (security-weighted: threat/adversarial/failure dominate)
_ENERGY_WEIGHTS = (1.4, 0.8, 1.3, 0.7, 1.5, 0.9)
_ENERGY_MAX = 1.5


def compute_energy(s: StateVector) -> float:
    """0 at zero pressure, saturating toward _ENERGY_MAX. tanh(e/2) == 2*(sigmoid(e)-0.5),
    i.e. the redesign's sigmoid with its 0.5 baseline removed."""
    e = (_ENERGY_WEIGHTS[0] * s.threat_pressure ** 2 +
         _ENERGY_WEIGHTS[1] * s.latency_pressure ** 2 +
         _ENERGY_WEIGHTS[2] * s.failure_pressure ** 2 +
         _ENERGY_WEIGHTS[3] * s.drift_pressure ** 2 +
         _ENERGY_WEIGHTS[4] * s.adversarial_pressure ** 2 +
         _ENERGY_WEIGHTS[5] * s.resource_pressure ** 2)
    return _ENERGY_MAX * math.tanh(e / 2.0)


@dataclass(frozen=True)
class TrajectorySnapshot:
    energy: float
    trend: float
    velocity: float
    acceleration: float
    volatility: float


class TrajectoryEngine:
    def __init__(self, window: int = 64) -> None:
        self._history: Deque[Tuple[float, float]] = deque(maxlen=window)

    def update(self, ts: float, energy: float) -> TrajectorySnapshot:
        self._history.append((ts, energy))
        if len(self._history) < 2:
            return TrajectorySnapshot(energy, 0.0, 0.0, 0.0, 0.0)
        t_prev, e_prev = self._history[-2]
        dt = max(1e-3, ts - t_prev)
        velocity = (energy - e_prev) / dt
        if len(self._history) < 3:
            return TrajectorySnapshot(energy, velocity, velocity, 0.0, 0.0)
        t_prev2, e_prev2 = self._history[-3]
        v_prev = (e_prev - e_prev2) / max(1e-3, t_prev - t_prev2)
        acceleration = (velocity - v_prev) / dt
        es = [e for _, e in self._history]
        mean = sum(es) / len(es)
        volatility = (sum((e - mean) ** 2 for e in es) / len(es)) ** 0.5
        return TrajectorySnapshot(energy, velocity, velocity, acceleration, volatility)


# ---------------------------------------------------------------------------
# Telemetry -> pressures (kept from the redesign)
# ---------------------------------------------------------------------------
class TelemetryAdapter:
    def to_state_vector(self, t: Dict[str, Any], ts: float) -> StateVector:
        risk = float(t.get("risk_score", 0.0))
        blocked_rate = float(t.get("blocked_rate", 0.0))
        retry_rate = float(t.get("retry_rate", 0.0))
        latency_ms = float(t.get("latency_ms", 0.0))
        latency_vol = float(t.get("latency_volatility", 0.0))
        queue_sat = float(t.get("queue_saturation", 0.0))
        substrate = float(t.get("substrate_health", 1.0))
        circuit = str(t.get("circuit_state", "CLOSED"))
        adversarial = float(t.get("adversarial_events", 0.0))
        drift = float(t.get("drift_metric", 0.0))
        return StateVector(
            threat_pressure=_clamp(risk * 0.7 + blocked_rate * 0.3),
            latency_pressure=_clamp(latency_ms / 1000.0 + latency_vol),
            failure_pressure=_clamp(retry_rate + (0.5 if circuit == "OPEN" else 0.0)),
            drift_pressure=_clamp(drift),
            adversarial_pressure=_clamp(adversarial),
            resource_pressure=_clamp(queue_sat + (1.0 - substrate)),
            timestamp=ts,
        )


# ---------------------------------------------------------------------------
# Result
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class ClassificationResult:
    status: str
    regime: SystemRegime
    energy: float
    trend: float
    resilience: float
    details: Dict[str, Any]

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["regime"] = self.regime.value
        return d


# ---------------------------------------------------------------------------
# Engine
# ---------------------------------------------------------------------------
class GatewayHealthEngine:
    def __init__(self, backlog_capacity: int = 256, history_window: int = 64) -> None:
        self.backlog_capacity = backlog_capacity
        self._telemetry = TelemetryAdapter()
        self._trajectory = TrajectoryEngine(window=history_window)

    def classify(self, telemetry: Dict[str, Any]) -> ClassificationResult:
        ts = time.time()
        s = self._telemetry.to_state_vector(telemetry, ts)
        energy = compute_energy(s)
        traj = self._trajectory.update(ts, energy)
        regime = self._regime(s, energy, traj.trend, traj.volatility)
        resilience = self._resilience(energy, traj.trend)
        details = {
            "pressures": {
                "threat": round(s.threat_pressure, 4),
                "latency": round(s.latency_pressure, 4),
                "failure": round(s.failure_pressure, 4),
                "drift": round(s.drift_pressure, 4),
                "adversarial": round(s.adversarial_pressure, 4),
                "resource": round(s.resource_pressure, 4),
            },
            "trajectory": {
                "trend": round(traj.trend, 4),
                "acceleration": round(traj.acceleration, 4),
                "volatility": round(traj.volatility, 4),
            },
        }
        return ClassificationResult(
            status=regime.health_status,
            regime=regime,
            energy=round(energy, 4),
            trend=round(traj.trend, 4),
            resilience=round(resilience, 4),
            details=details,
        )

    # convenience aliases (same signature; no fake flexibility)
    evaluate = classify
    __call__ = classify

    @staticmethod
    def _regime(s: StateVector, energy: float, trend: float, volatility: float) -> SystemRegime:
        high_threat = s.threat_pressure > 0.7 or s.adversarial_pressure > 0.7
        high_failure = s.failure_pressure > 0.6
        high_latency = s.latency_pressure > 0.6
        high_resource = s.resource_pressure > 0.7
        rising = trend > 0.02
        falling = trend < -0.02
        stable = abs(trend) <= 0.02

        # severe -> benign cascade; total coverage (no UNKNOWN dead zone)
        if energy >= 1.0 and rising and (high_failure or high_resource):
            return SystemRegime.CASCADING
        if high_threat and not falling:
            return SystemRegime.ATTACKED              # threat>0.7 already implies energy>=~0.5
        if energy >= 0.60 and (high_latency or high_failure or high_resource):
            return SystemRegime.STRESSED
        if falling and energy < 0.90:
            return SystemRegime.RECOVERING
        if energy < 0.35:
            return SystemRegime.NOMINAL
        if energy >= 0.75:
            return SystemRegime.STRESSED              # elevated, no specific high pressure
        if 0.35 <= energy < 0.75 and stable and volatility < 0.10:
            return SystemRegime.ADAPTING
        return SystemRegime.ADAPTING                  # mid band w/ mild trend wobble

    @staticmethod
    def _resilience(energy: float, trend: float) -> float:
        base = 1.0 - _clamp(energy / _ENERGY_MAX)
        if trend > 0:
            base -= _clamp(trend * 5.0, 0.0, 0.4)     # rising stress erodes resilience
        else:
            base += _clamp(-trend * 2.0, 0.0, 0.2)    # recovery rebuilds it
        return _clamp(base)


# ---------------------------------------------------------------------------
# Calibration check
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import itertools

    eng = GatewayHealthEngine()
    print("=== health on representative telemetry ===")
    cases = {
        "idle/healthy": dict(risk_score=0.0, blocked_rate=0.0, retry_rate=0.0, latency_ms=1, queue_saturation=0.0, substrate_health=1.0),
        "light":        dict(risk_score=0.05, blocked_rate=0.02, retry_rate=0.05, latency_ms=20, queue_saturation=0.02, substrate_health=1.0),
        "under attack": dict(risk_score=0.95, blocked_rate=0.8, retry_rate=0.1, latency_ms=50, queue_saturation=0.1, substrate_health=0.9),
        "overloaded":   dict(risk_score=0.2, blocked_rate=0.1, retry_rate=0.7, latency_ms=900, queue_saturation=0.9, substrate_health=0.3, circuit_state="OPEN"),
    }
    for name, t in cases.items():
        # two calls so trajectory has history
        eng.classify(t); r = eng.classify(t)
        print(f"  {name:13}: status={r.status:16} regime={r.regime.value:11} energy={r.energy:.3f} resilience={r.resilience:.3f}")

    print("\n=== regime reachability sweep (all six must be reachable, no UNKNOWN) ===")
    seen = {}
    vals = [0.0, 0.2, 0.4, 0.6, 0.8, 1.0]
    e2 = GatewayHealthEngine()
    for combo in itertools.product(vals, repeat=6):
        s = StateVector(*combo, 0.0)
        en = compute_energy(s)
        for tr in (-0.05, -0.005, 0.0, 0.005, 0.05):
            for vol in (0.0, 0.2):
                seen[GatewayHealthEngine._regime(s, en, tr, vol).value] = 1
    for r in ["NOMINAL", "ADAPTING", "RECOVERING", "STRESSED", "ATTACKED", "CASCADING", "UNKNOWN"]:
        mark = "reachable" if r in seen else ("UNREACHABLE" if r != "UNKNOWN" else "absent (good)")
        print(f"  {r:11}: {mark}")
    idle = eng.classify(cases["idle/healthy"]); idle = eng.classify(cases["idle/healthy"])
    print(f"\nidle -> {idle.regime.value}/{idle.status} (energy {idle.energy}); "
          f"NOMINAL reachable: {'NOMINAL' in seen}; UNKNOWN absent: {'UNKNOWN' not in seen}")
