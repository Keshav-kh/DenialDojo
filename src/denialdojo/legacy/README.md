# Legacy: local Ollama model path

This is the local-model path from the project's first checkpoints (1C to 1E),
when the benchmark ran on models served by a local Ollama runtime
(`gpt-oss:20b`, then `qwen3:8b`). The project then moved to hosted APIs
(OpenAI, Anthropic, and Google through `denialdojo.api_adapter`).

The code is kept so the early records and checkpoints remain reproducible. It
is **not used for any reported result**.

| Module | Purpose |
| --- | --- |
| `ollama_runtime.py` | Read-only inspection of the local Ollama runtime and model |
| `local_model_scope.py` | Checkpoint labels for the two authorized local models |
| `run_ollama_preflight.py` | Sequential tool-calling preflight (Checkpoint 1C) |
| `run_ollama_readiness.py` | Eight-record matched-benign readiness gate (Checkpoints 1D, 1E) |
| `run_ollama_pilot.py` | Eight-condition local infrastructure pilot |
| `checkpoint1c_audit.py` | Read-only audit of the Checkpoint 1C local pilot records |

Run them as `python -m denialdojo.legacy.<module>`, for example
`python -m denialdojo.legacy.run_ollama_readiness --help`.

Two pieces stay in the main package because the hosted path uses them:

- `denialdojo/ollama_adapter.py`: the shared condition runner
  (`denialdojo.local_pilot.run_workspace_ollama_condition`) and
  `local_artifacts.execute_immutable_matrix` take `OllamaAdapter` as the default
  `adapter_factory`. Hosted runs pass `ApiAdapter` explicitly.
- `denialdojo/provenance.py`: `repository_state`, `working_tree_digest`, and
  `collect_hardware_metadata`, which used to live in `ollama_runtime.py`.

See `docs/local_model_readiness.md`, `docs/checkpoint1c_pilot_audit.md`, and
`docs/checkpoint1e_qwen_qualification.md` for what these runs found.
