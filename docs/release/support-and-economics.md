# Support and economics (contract M3/M4, WP12)

**Status: Not demonstrated** (no support owner named, no costs measured, no
price approved). The structure below is what must be filled before any paying
customer; `tools/release/margin.py` computes the 70 % gross-margin test from
measured figures and refuses estimates that are not labelled as such.

## M4 — support readiness

| Requirement | Where it is published | Owner | Status |
|---|---|---|---|
| Support hours and escalation instructions | | | Not demonstrated |
| Named support ownership (primary + backup) | | | Not demonstrated |
| Onboarding documentation | | | Not demonstrated |
| Failure recovery (consultant-facing) | | | Not demonstrated |
| Privacy, export, deletion, opt-out documentation | `docs/data-retention-and-deletion.md` is the engineering source; customer-facing text pending | | Not demonstrated |
| Cancellation and billing correction | | | Not demonstrated |
| Tenant spending limits and abuse limits | **not implemented** (see O2 per-tenant limits) | | Not demonstrated |
| Message-related charge disclosure before approval | approval screen shows the message; cost line **not implemented** | | Not demonstrated |

## M3 — economics

Measured recurring operating cost per tenant-month, each line from an invoice
or metered export (not a list price): provider (per segment × measured
volume), hosting (ECS/RDS/ElastiCache/ALB/NAT/S3 from Cost Explorer),
model (per-token metered), observability (AMP/Grafana/CloudWatch), storage
(S3 + backups), support labour (hours × loaded rate). Product-development
expenditure is excluded and disclosed separately.

```sh
python -I tools/release/margin.py costs.yaml
```

`costs.yaml` schema and an example are in the tool's docstring. The tool
prints the gross margin at the *proposed* price and exits 0 only at ≥ 70 %
with every line marked `measured: true`. Pricing approval by the business
owner is a commercial authorization recorded in `evidence/releases/<id>/M3.yaml`;
billing stays disabled (`BILLING_ENFORCED=false`, no `STRIPE_PRICES`) until
that record exists.
