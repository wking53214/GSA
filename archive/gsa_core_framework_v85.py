import time, logging, copy, uuid, random, statistics, collections
from enum import IntEnum
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Deque
logging.basicConfig(level=logging.INFO, format='%(asctime)s | %(levelname)s | %(message)s')
logger = logging.getLogger("GSA_CORE")

class SystemSeverity(IntEnum):
    OPTIMAL=0; ANOMALY=1; PATTERN=2; MANDATE=3; CRITICAL=4
class GSAExecutionStatus(IntEnum):
    SUCCESS=0; REJECTED=1; STASIS=2; RECOVERY=3
class Intent(IntEnum):
    INFORMATIONAL=10; TRANSACTIONAL=11; FINANCIAL_DISTRESS=12; ACCOUNT_MAINTENANCE=13

class GSAPersistenceLayer:
    def __init__(self):
        self.archive_history=collections.deque(maxlen=1000)
        self.lock_active=False; self.lock_timestamp=0; self.COOLDOWN_PERIOD=60
    def archive_snapshot(self, state_data):
        snap={"timestamp":time.time(),"snapshot_id":str(uuid.uuid4()),"data":copy.deepcopy(state_data)}
        self.archive_history.append(snap); return snap
    def trigger_lockdown(self):
        self.lock_active=True; self.lock_timestamp=time.time()
        logger.critical("CITADEL: Lockdown triggered. System entering STASIS.")
    def verify_lock(self):
        if self.lock_active:
            if (time.time()-self.lock_timestamp)>self.COOLDOWN_PERIOD:
                self.lock_active=False; logger.info("CITADEL: Recovery period complete. Resuming."); return False
            return True
        return False

class FDRCalibrationEngine:
    def __init__(self, target_fdr=0.05):
        self.target_fdr=target_fdr; self.total_mandates=0; self.false_discoveries=0; self.dynamic_threshold=0.95
    def audit(self, is_mandate, is_true_signal):
        if is_mandate:
            self.total_mandates+=1
            if not is_true_signal: self.false_discoveries+=1
            fdr=self.false_discoveries/max(1,self.total_mandates)
            if fdr>self.target_fdr:
                self.dynamic_threshold=min(0.99,self.dynamic_threshold+0.02)
                logger.warning(f"FDR Exceeded ({fdr:.2%}). Tightening threshold to {self.dynamic_threshold:.2f}")

class BBC2_Evaluator:
    def __init__(self):
        self.baseline={"stability":0.5,"volatility":0.05}; self.learning_threshold=0.20
    def is_drifting(self, metrics):
        return abs(metrics["risk"]-self.baseline["stability"])>self.learning_threshold
    def update_baseline(self, metrics, alpha=0.1):
        for k in self.baseline:
            self.baseline[k]=(1-alpha)*self.baseline[k]+alpha*metrics.get(k,0)

class GovernanceEngine:
    def __init__(self):
        self.fdr=FDRCalibrationEngine(); self.bbc=BBC2_Evaluator(); self.reentry_tracker=collections.defaultdict(int)
    def process(self, telemetry, reality_check=True):
        ambiguity=0.8 if telemetry.get("is_complex") else 0.2
        action="DEGRADE" if ambiguity>0.6 else "ACT"
        metrics={"risk":ambiguity,"stability":0.5}
        if self.bbc.is_drifting(metrics):
            logger.info("BBC: Baseline drift detected. Updating models.")
            self.bbc.update_baseline(metrics)
        self.fdr.audit(action=="MANDATE", reality_check)
        return action

class GSA_FullStack:
    def __init__(self):
        self.citadel=GSAPersistenceLayer(); self.runtime=GovernanceEngine(); self.status=GSAExecutionStatus.SUCCESS
    def execute_lifecycle(self, telemetry, actual_reality=True):
        if self.citadel.verify_lock(): return GSAExecutionStatus.RECOVERY
        try:
            action=self.runtime.process(telemetry, actual_reality)
            self.citadel.archive_snapshot({"telemetry":telemetry,"action":action})
            self.status=GSAExecutionStatus.SUCCESS; return action
        except Exception as e:
            logger.error(f"GSA FATAL: Runtime Exception {e}")
            self.citadel.trigger_lockdown(); self.status=GSAExecutionStatus.RECOVERY; return self.status

if __name__=="__main__":
    Stack=GSA_FullStack()
    logger.info("GSA Stack Initialized. Starting stress test...")
    for i in range(20):
        telemetry={"is_complex":(i%4==0),"id":i}
        reality=not telemetry["is_complex"]
        action=Stack.execute_lifecycle(telemetry, reality)
        logger.info(f"Cycle {i:02} | Input_Complexity: {telemetry['is_complex']} | Action: {action}")
    # ---- PROBES (post-run state inspection) ----
    fdr=Stack.runtime.fdr; bbc=Stack.runtime.bbc
    print("\n=== STATE AFTER 20 CYCLES ===")
    print(f"FDR: total_mandates={fdr.total_mandates}  false_discoveries={fdr.false_discoveries}  dynamic_threshold={fdr.dynamic_threshold}")
    print(f"BBC baseline: {bbc.baseline}  (started stability=0.5, volatility=0.05)")
    print(f"Citadel: lock_active={Stack.citadel.lock_active}  snapshots={len(Stack.citadel.archive_history)}")
    print(f"reentry_tracker entries: {len(Stack.runtime.reentry_tracker)}")
