"""
ml/v2/serving — FihhGuard v2 serving layer.

Public API:
    from ml.v2.serving import Detector
    from ml.v2.serving.detector import Detector
    from ml.v2.serving.shadow_eval import log_verdict, run_weekly_drift_check
"""

from .detector import Detector

__all__ = ["Detector"]
