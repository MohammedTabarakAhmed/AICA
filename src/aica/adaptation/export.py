"""Export a planned training job for an external trainer, reviewed before it leaves (BRD 13).

Training runs off this machine (on Kaggle, for this project). Everything that leaves is
staged here first, in one directory a person can read end to end before uploading it:

* ``train.jsonl``, ``manifest.json`` - the dataset, verified against its manifest;
* ``job.json`` - the job spec, **without** the local dataset path (it names the developer's
  home directory, which is personal data and useless to a trainer);
* ``review.md`` - every example rendered as plain text, the "show me exactly what goes in";
* ``dataset-metadata.json`` and ``kernel/`` - what the Kaggle CLI needs to create a
  *private* dataset and a *private* notebook run from them.

Staging never uploads and never reads a credential. The last check before anything is
written is the same one the collection screen applies: if any staged text looks like a
secret or names a path inside a home directory, the export is refused outright.
"""

from __future__ import annotations

import json
import re
import shutil
from pathlib import Path
from typing import Any

from aica.adaptation.curation import AdaptationError, datasets_dir, verify_dataset
from aica.adaptation.training import load_job
from aica.adaptation.trajectories import _HOME_PATH
from aica.admin.rbac import Permission, Principal
from aica.safety.redaction import redact

NOTEBOOK = Path(__file__).parents[3] / "training" / "kaggle" / "qlora_adapter.ipynb"
_KAGGLE_USER = re.compile(r"^[a-z0-9][a-z0-9-]{1,48}[a-z0-9]$")


def _render(examples: list[dict[str, Any]]) -> str:
    parts = [f"# Training examples ({len(examples)})\n"]
    for number, example in enumerate(examples, start=1):
        meta = example.get("meta", {})
        parts.append(
            f"\n## {number}. {meta.get('kind', 'plan')} - trajectory {meta.get('trajectory')}\n"
        )
        for message in example["messages"]:
            parts.append(f"\n### {message['role']}\n\n```\n{message['content']}\n```\n")
    return "".join(parts)


def _refuse_if_sensitive(name: str, text: str) -> None:
    found = redact(text)
    if found.redacted:
        raise AdaptationError(
            f"{name} contains secret-like content ({', '.join(found.kinds)}); nothing was exported"
        )
    if _HOME_PATH.search(text):
        raise AdaptationError(f"{name} names a path inside a home directory; nothing was exported")


def export_for_kaggle(
    root: str | Path,
    config_version: str,
    out: str | Path,
    kaggle_user: str,
    principal: Principal,
    *,
    notebook: Path = NOTEBOOK,
) -> dict[str, Any]:
    """Stage a job for Kaggle in ``out``. Returns a summary; uploads nothing."""
    principal.require(Permission.ADMINISTER, "export a training job")
    if not _KAGGLE_USER.match(kaggle_user):
        raise AdaptationError(f"{kaggle_user!r} is not a Kaggle username")
    job = load_job(root, config_version)
    if job.get("produces") != "adapter":
        raise AdaptationError("only adapter jobs are exported; this one trains a new base model")
    manifest = verify_dataset(root, job["dataset"]["version"])
    body = (datasets_dir(root) / manifest.version / "train.jsonl").read_text(encoding="utf-8")
    examples = [json.loads(line) for line in body.splitlines() if line.strip()]

    shipped_job = {**job, "dataset": {k: v for k, v in job["dataset"].items() if k != "path"}}
    slug = f"aica-train-{manifest.version}"
    kernel_slug = f"aica-qlora-{config_version}"
    files: dict[str, str] = {
        "train.jsonl": body,
        "manifest.json": json.dumps(manifest.to_json(), indent=1, ensure_ascii=False),
        "job.json": json.dumps(shipped_job, indent=1, ensure_ascii=False),
        "dataset-metadata.json": json.dumps(
            {
                "title": slug,
                "id": f"{kaggle_user}/{slug}",
                "licenses": [{"name": "other"}],
            },
            indent=1,
        ),
        "kernel/kernel-metadata.json": json.dumps(
            {
                "id": f"{kaggle_user}/{kernel_slug}",
                "title": kernel_slug,
                "code_file": notebook.name,
                "language": "python",
                "kernel_type": "notebook",
                "is_private": True,
                "enable_gpu": True,
                "enable_internet": True,
                "dataset_sources": [f"{kaggle_user}/{slug}"],
            },
            indent=1,
        ),
        f"kernel/{notebook.name}": notebook.read_text(encoding="utf-8"),
        "review.md": _render(examples),
    }
    for name, text in files.items():
        _refuse_if_sensitive(name, text)

    target = Path(out)
    if target.exists():
        shutil.rmtree(target)
    for name, text in files.items():
        path = target / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8", newline="\n")
    kinds: dict[str, int] = {}
    for example in examples:
        kind = str(example.get("meta", {}).get("kind", "plan"))
        kinds[kind] = kinds.get(kind, 0) + 1
    return {
        "out": str(target),
        "dataset": manifest.version,
        "sha256": manifest.sha256,
        "examples": len(examples),
        "kinds": kinds,
        "trajectories": len(manifest.trajectory_ids),
        "kaggle_dataset": f"{kaggle_user}/{slug}",
        "kaggle_kernel": f"{kaggle_user}/{kernel_slug}",
    }
