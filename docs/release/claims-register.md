# Claims register (contract K2)

Every statement made about the product outside this repository must appear
here with the evidence record that supports it. A row without a validated
record under `evidence/releases/<id>/` may not be published.

| # | Claim (exact wording permitted) | Evidence record(s) | Status |
|---|---|---|---|
| 1 | "Every outreach message is approved by a person with a passkey before it is sent." | H1, H6, H7 | Not publishable — H1/H6 Implemented, not independently verified |
| 2 | "A reply of STOP blocks further messages immediately." | C5, C6, C7 | Not publishable — Implemented, not independently verified |
| 3 | "Customer messages and notes are never used as instructions." | P3, A5, A6 | Not publishable — A5/A6 Not demonstrated |
| 4 | "Progress toward production" (the only status wording permitted today) | `docs/production-acceptance.md` §11 | Publishable |
| — | Any comparative or market-superiority wording | K1 | **Prohibited** until K1 passes; then only the sentence `tools/qualification/k1_analysis.py` prints |
| — | "production-ready", "enterprise-grade", "secure" as adjectives | — | **Prohibited** by the contract until READY is recorded |

Adding a row requires: the exact wording, the record ids, and a reviewer other
than the author confirming that the record supports the wording as written.
