# src/config.py
import os
from dataclasses import dataclass
from pathlib import Path

import yaml


@dataclass
class Config:
    org: str
    clone_dir: str
    report_path: str
    opencode_binary: str
    github_pat: str


def load_config(config_path: str = "config.yaml") -> Config:
    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")

    with open(path) as f:
        data = yaml.safe_load(f)

    github_pat = os.environ.get("GITHUB_PAT")
    if not github_pat:
        raise ValueError("GITHUB_PAT environment variable is required")

    return Config(
        org=data.get("org", ""),
        clone_dir=data.get("clone_dir", ".repos"),
        report_path=data.get("report_path", "report.html"),
        opencode_binary=data.get("opencode_binary", "opencode"),
        github_pat=github_pat,
    )
