# Extension contracts (Phase 1: INTERFACE_ONLY)

These modules define the shapes and rules that later phases implement. They
contain **no execution capability**. Each file states its implementation status.

| Contract | File | Status | Implemented in |
|---|---|---|---|
| Defensive actions | `defensive-action.ts` | INTERFACE_ONLY (executor permanently disabled) | Phase 3 |
| Evidence references and provenance | `evidence.ts` | INTERFACE_ONLY (classification rules are tested) | Phase 2 |
| Verification results | `verification.ts` | INTERFACE_ONLY (aggregation rules are tested) | Phase 3 |
| Policy definitions | `policy.ts` | INTERFACE_ONLY | Phase 3 |
| Resource budgets | `resource-budget.ts` | PARTIALLY_IMPLEMENTED (enforced for background jobs) | Phase 4 for agents |
| SENTINEL observations | `sentinel.ts` | INTERFACE_ONLY | Phase 3 |
| Recovery readiness | `recovery.ts` | INTERFACE_ONLY | Phase 3 |

Defining an interface here is not the same as implementing the feature.
