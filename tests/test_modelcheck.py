# tests/test_modelcheck.py
from unittest.mock import patch
from src.config import Config
from src.modelcheck import validate_model


def _config(args=None, model=""):
    return Config(
        org="test-org", clone_dir=".repos", report_path="report.html",
        github_pat="ghp_test",
        ai_agent_args=args if args is not None else ["kilo", "run", "-m", "{model}", "{prompt}"],
        ai_agent_model=model,
    )


def test_validate_model_empty_when_placeholder_required():
    reason = validate_model(_config(model=""))
    assert reason is not None
    assert "ai_agent_args uses {model} but ai_agent_model is empty" in reason
    assert "Fix 'ai_agent_model' in config.yaml." in reason


def test_validate_model_rejects_whitespace():
    reason = validate_model(_config(model="bad model"))
    assert reason is not None
    assert "'bad model' contains whitespace" in reason


def test_validate_model_rejects_control_chars():
    reason = validate_model(_config(model="kilo\x00model"))
    assert reason is not None
    assert "control characters" in reason


def test_validate_model_skips_all_checks_without_placeholder():
    cfg = _config(args=["kilo", "run", "{prompt}"], model="")
    with patch("src.modelcheck.subprocess.run") as mock_run:
        assert validate_model(cfg) is None
    mock_run.assert_not_called()


def test_validate_model_empty_args_skipped():
    with patch("src.modelcheck.subprocess.run") as mock_run:
        assert validate_model(_config(args=[])) is None
    mock_run.assert_not_called()


def _completed(stdout="", returncode=0):
    import subprocess as sp
    return sp.CompletedProcess(["probe"], returncode, stdout=stdout, stderr="")


def test_validate_model_match_passes():
    with patch("src.modelcheck.subprocess.run",
               return_value=_completed("kilo/stepfun/step-3.7-flash:free\nother/model\n")) as mock_run:
        assert validate_model(_config(model="kilo/stepfun/step-3.7-flash:free")) is None
    mock_run.assert_called_once()


def test_validate_model_matches_token_in_table_row():
    out = "kilo/stepfun/step-3.7-flash:free  128k  free\nkilo/other/model  32k  paid\n"
    with patch("src.modelcheck.subprocess.run", return_value=_completed(out)) as mock_run:
        assert validate_model(_config(model="kilo/stepfun/step-3.7-flash:free")) is None
    mock_run.assert_called_once()


def test_validate_model_not_offered_fail_closed():
    with patch("src.modelcheck.subprocess.run",
               return_value=_completed("kilo/other/model\n")):
        reason = validate_model(_config(model="kilo/stepfun/step-3.7-flas"))
    assert reason is not None
    assert "not offered by agent 'kilo'" in reason
    assert "Fix 'ai_agent_model' in config.yaml." in reason


def test_validate_model_not_offered_lists_free_models():
    out = (
        "kilo/qwen/qwen3-4b:free\n"
        "kilo/stepfun/step-3.7-flash:free\n"
        "kilo/other/paid-model\n"
        "kilo/meta/llama-free-fusion\n"
    )
    with patch("src.modelcheck.subprocess.run", return_value=_completed(out)):
        reason = validate_model(_config(model="kilo/stepfun/step-3.7-flas"))
    assert reason is not None
    assert "Free models available:" in reason
    assert "kilo/qwen/qwen3-4b:free" in reason
    assert "kilo/stepfun/step-3.7-flash:free" in reason
    # ":free" marker is the only free signal — names without it are not listed
    assert "kilo/other/paid-model" not in reason
    assert "kilo/meta/llama-free-fusion" not in reason


def test_validate_model_not_offered_no_free_models_message():
    with patch("src.modelcheck.subprocess.run",
               return_value=_completed("kilo/other/paid-model\n")):
        reason = validate_model(_config(model="kilo/stepfun/step-3.7-flas"))
    assert reason is not None
    assert "No free models found in agent 'kilo' model list." in reason


def test_validate_model_timeout_fail_closed():
    import subprocess as sp
    with patch("src.modelcheck.subprocess.run", side_effect=sp.TimeoutExpired(cmd="kilo", timeout=10)):
        reason = validate_model(_config(model="kilo/stepfun/step-3.7-flash:free"), timeout=10)
    assert reason is not None
    assert "timed out after 10s" in reason


def test_validate_model_agent_not_runnable():
    with patch("src.modelcheck.subprocess.run", side_effect=FileNotFoundError("kilo")):
        reason = validate_model(_config(model="kilo/stepfun/step-3.7-flash:free"))
    assert reason is not None
    assert "agent binary 'kilo' is not runnable" in reason
    assert "Fix 'ai_agent_args' in config.yaml." in reason


def test_validate_model_all_probes_fail_closed():
    with patch("src.modelcheck.subprocess.run",
               side_effect=[_completed(returncode=1), _completed(returncode=2)]):
        reason = validate_model(_config(model="kilo/stepfun/step-3.7-flash:free"))
    assert reason is not None
    assert "has no model-list capability" in reason
    assert "'models': exit 1" in reason and "'--model-list': exit 2" in reason


def test_validate_model_none_model_fail_closed():
    # YAML `ai_agent_model:` (blank) parses to None — must give the pinned error line, not a traceback
    with patch("src.modelcheck.subprocess.run") as mock_run:
        reason = validate_model(_config(model=None))
    assert reason is not None
    assert "ai_agent_model is empty" in reason
    mock_run.assert_not_called()


def test_validate_model_non_string_model_fail_closed():
    with patch("src.modelcheck.subprocess.run") as mock_run:
        reason = validate_model(_config(model=123))
    assert reason is not None
    assert "ai_agent_model is empty" in reason
    mock_run.assert_not_called()


def test_validate_model_default_timeout_is_30s():
    # real agent measured at ~7.2-7.5s per probe on this machine; 10s was too tight
    with patch("src.modelcheck.subprocess.run",
               return_value=_completed("kilo/stepfun/step-3.7-flash:free")) as mock_run:
        assert validate_model(_config(model="kilo/stepfun/step-3.7-flash:free")) is None
    assert mock_run.call_args.kwargs["timeout"] == 30.0
