"""
ml/v2/training — FihhGuard v2 training + evaluation pipeline.

Public API::

    from ml.v2.training.dataset import PhishDataset
    from ml.v2.training.splitter import time_domain_split, leave_one_source_out_split
    from ml.v2.training.train import train
    from ml.v2.training.calibrate import calibrate
    from ml.v2.training.evaluate import evaluate_gates
    from ml.v2.training.bundle import ModelBundle
"""

from .dataset import PhishDataset
from .splitter import time_domain_split, leave_one_source_out_split
from .train import train
from .calibrate import calibrate
from .evaluate import evaluate_gates
from .bundle import ModelBundle

__all__ = [
    "PhishDataset",
    "time_domain_split",
    "leave_one_source_out_split",
    "train",
    "calibrate",
    "evaluate_gates",
    "ModelBundle",
]
