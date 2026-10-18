# src/modelcheck.py
import subprocess

from src.config import Config

_PROBES = ("models", "--model-list")


def _list_models(agent: str, timeout: float) -> tuple[list[str] | None, str | None]:
    """Ask the agent for its model list. Returns (tokens, None) on success, (None, reason) fail-closed."""
    details: list[str] = []
    for arg in _PROBES:
        try:
            proc = subprocess.run(
                [agent, arg],
                capture_output=True, text=True, encoding="utf-8", errors="replace",
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            return None, f"timeout:{timeout:g}"
        except OSError:
            return None, "not-runnable"
        if proc.returncode == 0:
            return proc.stdout.split(), None
        details.append(f"'{arg}': exit {proc.returncode}")
    return None, ",".join(details)


def validate_model(config: Config, timeout: float = 30.0) -> str | None:
    """Static + live check of ai_agent_model. Returns a failure reason or None."""
    if not config.ai_agent_args or "{model}" not in config.ai_agent_args:
        return None

    # YAML `ai_agent_model:` (blank) parses to None; non-strings are treated as empty
    model = config.ai_agent_model if isinstance(config.ai_agent_model, str) else ""
    if not model.strip():
        return "ai_agent_args uses {model} but ai_agent_model is empty. Fix 'ai_agent_model' in config.yaml."

    if any(c.isspace() or ord(c) < 32 or ord(c) == 127 for c in model):
        return f"model '{model}' contains whitespace or control characters. Fix 'ai_agent_model' in config.yaml."

    agent = config.ai_agent_args[0]
    tokens, err = _list_models(agent, timeout)
    if err == "not-runnable":
        return (
            f"cannot verify model '{model}' — agent binary '{agent}' is not runnable. "
            "Fix 'ai_agent_args' in config.yaml."
        )
    if err is not None and err.startswith("timeout:"):
        return (
            f"cannot verify model '{model}' — agent model-list timed out after {err.split(':', 1)[1]}s. "
            "Fix 'ai_agent_model' in config.yaml or check the agent binary."
        )
    if tokens is None:
        return (
            f"cannot verify model '{model}' — agent '{agent}' has no model-list capability ({err}). "
            "Fix 'ai_agent_model' in config.yaml or check the agent binary."
        )
    if model.strip() in tokens:
        return None
    free = [t for t in tokens if ":free" in t.lower()][:10]
    if free:
        suffix = "Free models available: " + ", ".join(free) + "."
    else:
        suffix = f"No free models found in agent '{agent}' model list."
    return (
        f"model '{model}' not offered by agent '{agent}'. Fix 'ai_agent_model' in config.yaml. {suffix}"
    )
