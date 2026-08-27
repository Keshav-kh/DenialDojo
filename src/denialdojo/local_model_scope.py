"""Authorized local-model checkpoint labels for frozen qualification runners."""

_CHECKPOINT_BY_MODEL = {"gpt-oss:20b": "checkpoint1d", "qwen3:8b": "checkpoint1e"}
AUTHORIZED_LOCAL_MODELS = tuple(sorted(_CHECKPOINT_BY_MODEL))


def checkpoint_for_model(model: str) -> str:
    try:
        return _CHECKPOINT_BY_MODEL[model]
    except KeyError as error:
        raise ValueError(f"model is not authorized for a frozen local gate: {model}") from error


def readiness_scope_for_model(model: str) -> str:
    return f"{checkpoint_for_model(model)}_benign_readiness_gate"


def pilot_scope_for_model(model: str) -> str:
    return f"{checkpoint_for_model(model)}_non_statistical_workspace_pilot"


__all__ = [
    "AUTHORIZED_LOCAL_MODELS",
    "checkpoint_for_model",
    "pilot_scope_for_model",
    "readiness_scope_for_model",
]
