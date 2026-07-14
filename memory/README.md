# Research-Engine Extraction Memory

This directory records what the future standalone Daniel research engine must learn from real
mission execution. It is not that engine.

`research_engine_extraction.jsonl` is an append-only, hash-chained sequence of typed records for:

- decisions and their alternatives;
- scientific and infrastructure findings;
- failures, nulls, invalid runs, and corrections;
- manual work, recurrence keys, and automation candidates;
- cost, latency, approvals, resumptions, and duplicate-launch risks;
- naming/identity decisions that affect mission communication;
- concrete future-engine requirements grounded in observed work.

Records must cite Git commits or evidence artifacts. Aspirational features without a witnessed
workflow problem do not qualify. The future engine is authorized only after several complete
cycles include a null/correction path, a real data/compute path, and repeated manual toil.

Each record distinguishes prospective, exploratory, and retrospective knowledge; actor and
status; estimated versus actual resources in its payload; evidence access and hidden-label access;
and correction links. It records research-relevant state changes, not private reasoning, chat
transcripts, secrets, or pasted terminal logs.
