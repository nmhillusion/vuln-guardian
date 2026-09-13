# src/config.py
import os
from dataclasses import dataclass, field
from pathlib import Path

import yaml


@dataclass
class Config:
    org: str
    clone_dir: str
    report_path: str
    github_pat: str
    ai_agent_args: list[str] = field(default_factory=lambda: ["kilo", "run", "--auto", "{prompt}"])
    ai_agent_model: str = ""
    ai_agent_stdin: bool = False


def load_config(config_path: str = "config.yaml") -> Config:
    path = Path(config_path)
    if not path.exists():
        raise FileNotFoundError(f"Config file not found: {config_path}")

    with open(path) as f:
        data = yaml.safe_load(f)

    github_pat = os.environ.get("GITHUB_PAT") or os.environ.get("GITHUB_TOKEN")
    if not github_pat:
        raise ValueError("GITHUB_PAT or GITHUB_TOKEN environment variable is required")

    return Config(
        org=data.get("org", ""),
        clone_dir=data.get("clone_dir", "../.repos"),
        report_path=data.get("report_path", "report.html"),
        ai_agent_args=data.get("ai_agent_args", ["kilo", "run", "--auto", "{prompt}"]),
        ai_agent_model=data.get("ai_agent_model", ""),
        ai_agent_stdin=bool(data.get("ai_agent_stdin", False)),
        github_pat=github_pat,
    )
