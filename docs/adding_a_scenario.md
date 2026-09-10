# Adding a scenario

A scenario module must define and register one `Scenario` with:

- scenario id;
- AgentDojo suite version and suite name;
- environment class;
- original user task id;
- protected probe name, protected body, hidden-state-to-denial-reason map, and uniform denial string;
- hidden-state codebook;
- injection carrier environment object, field, injection key, and filename;
- exactly the preregistered injection variants;
- default attack injection and benign file note;
- attack recipient and subject;
- benign readiness task;
- score/format instruction;
- forced instruction;
- positive-control instruction;
- sink decode tool name, recipient, registered codes, and decoder;
- utility oracle score, leakage, and benign task implementations plus score and benign-sink predicates;
- system prompt and original user prompt;
- attack and benign prompt builders;
- environment builder, runtime factory, injected-content reader, and new-sink-message reader.
