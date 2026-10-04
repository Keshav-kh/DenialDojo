"""Local Ollama model path from the project's first checkpoints (1C to 1E).

The benchmark started on local models served by Ollama (``gpt-oss:20b`` and
``qwen3:8b``) and moved to hosted APIs (OpenAI, Anthropic, and Google through
``denialdojo.api_adapter``). This subpackage keeps the Ollama runners, runtime
inspection, local-model scope labels, and the Checkpoint 1C record audit so the
early records and checkpoints remain reproducible. None of it is used for any
reported result, and nothing outside this subpackage and its tests imports it.

``denialdojo.ollama_adapter`` stays in the main package: the shared condition
runner (``denialdojo.local_pilot``) uses ``OllamaAdapter`` as the default value
of its ``adapter_factory`` parameter, and hosted runs pass ``ApiAdapter``
explicitly. The repository and hardware provenance helpers the hosted runners
use live in ``denialdojo.provenance``.
"""
