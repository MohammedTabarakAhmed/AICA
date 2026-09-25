"""Fine-tuning and domain adaptation (BRD section 13).

``trajectories`` extracts agent runs and screens them; ``curation`` holds the approved
collection and builds versioned datasets; ``training`` validates configurations and writes
job specs for a GPU trainer; ``registry`` keeps adapters separate from base models and
gates, promotes and rolls them back. Nothing in this package trains a model.
"""

from aica.adaptation.curation import (
    AdaptationError,
    CandidateState,
    CandidateStore,
    DatasetManifest,
    build_dataset,
    list_datasets,
    verify_dataset,
)
from aica.adaptation.registry import AdapterRegistry, AdapterStatus, security_gate
from aica.adaptation.training import Method, TrainingConfig, plan_training
from aica.adaptation.trajectories import Trajectory, extract, screen

__all__ = [
    "AdaptationError",
    "AdapterRegistry",
    "AdapterStatus",
    "CandidateState",
    "CandidateStore",
    "DatasetManifest",
    "Method",
    "TrainingConfig",
    "Trajectory",
    "build_dataset",
    "extract",
    "list_datasets",
    "plan_training",
    "screen",
    "security_gate",
    "verify_dataset",
]
