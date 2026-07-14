# Iteration 000 Result

**Verdict: `BLOCKED_EVIDENCE`**

This is a corpus and construct-readiness result, not a diagnosis benchmark.

| Gate | Status | Observed | Requirement |
|---|---|---|---|
| `source-integrity` | **PASS** | `{"failures": [], "locked_resources": 2, "receipt_resources": 2}` | Every resource matches its frozen SHA-256 and byte count. |
| `parser-integrity` | **PASS** | `{"exact_join": true, "expected": 16, "integrity_failures": [], "parsed": 16}` | Every discovered experiment is parsed exactly once with an exact evidence/truth join. |
| `truth-separation` | **PASS** | `{"leakage_markers": []}` | Fault metadata and injection-internal rows are absent from model-visible evidence. |
| `minimum-count` | **BLOCKED** | `0` | At least 30 incidents have independently identified mechanisms. |
| `ambiguity` | **BLOCKED** | `0` | At least 30 incidents carry two or more pre-outcome plausible hypotheses. |
| `discriminating-action` | **BLOCKED** | `0` | At least 30 incidents have an independently reviewed safe discriminating test. |
| `transfer-support` | **BLOCKED** | `{"fault_families": ["abrupt", "discrete", "incipient/abrupt"], "hardware_families": ["NASA ADAPT electrical power system"], "hardware_identities": ["NASA Ames ADAPT EPS"], "leakage_components": 1}` | At least two hardware families, two hardware identities, and two fault families permit grouped transfer. |
| `evidence-usefulness` | **BLOCKED** | `{"total_incidents": 16, "useful_incidents": 16}` | At least 30 incidents have two operational channels with explicit clock domains. |

## Authorized next action

Acquire additional independently verified physical incidents and reviewed safe test actions; ADAPT remains parser and evidence-plane validation only.

## Forbidden conclusions

- GPU or learned-model training
- active-diagnosis performance claim
- recovery or safety claim
- cross-hardware transfer claim
- product or economic-value claim

NASA does not endorse this project. No model, recovery, safety, transfer, product, state-of-the-art, or economic claim is authorized by this iteration.
