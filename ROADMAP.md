# MK Copilot — Product Roadmap
*Last updated: June 24, 2026. This is a living document — reorder by what the data says.*

Roadmap priorities are driven by two things: what the STRATEGY.md growth plan needs,
and what the `ConsultantProfile` analytics tell us consultants actually use. Ship the
thing that drives a paid conversion or prevents a churn first.

---

## Now (next release — 1.2.0)

These are the features that directly move retention and conversion.

- [ ] **Revenue-impact surfacing.** After a Power Hour contact, show the consultant the
      estimated revenue recovered ("this customer last ordered 90 days ago — a reorder is
      worth ~$X"). Makes the value visible, which is the #1 retention driver per STRATEGY.
- [x] **Billing & subscription tiers.** Shipped v1.3.0 — Stripe Checkout (annual-first,
      90-day trial), `Subscription` model + webhook lifecycle, customer portal, and the
      referral-credit flywheel ($5 on referred first payment). Set `STRIPE_PRICES` + keys
      to go live; flip `BILLING_ENFORCED=1` to gate AI on an active sub.
- [x] **Consent capture (skin).** Shipped v1.2.0 — `ConsentRecord` + `/api/consent/skin`,
      operator + per-customer, gate before photo read. See SECURITY-PRIVACY.md.
- [x] **Data deletion / export endpoints.** Shipped v1.2.0 — `DELETE /api/me/skin-data`
      (purge + receipt) and `GET /api/me/skin-data/export` (MHMDA access/portability).
- [x] **Photo retention policy enforcement.** Shipped v1.2.0 — raw + sanitized buffers
      dropped after use; `AuditLog skin.analyze photo_discarded=1`. No raw image persisted.
- [ ] **Chat-UI AI disclosure banner** (California SB 243) — frontend "you're talking to AI".
      (Skin-output disclosure already ships; this is the chat surface.)
- [ ] **Usage-metering dashboard.** Token cost per user/team, visible to tenant admins —
      needed for margin visibility and the Studio/Director tiers.
- [ ] **Redis rate limiting.** Swap the in-process sliding-window store (`ratelimit.py`)
      for Redis so we can run multiple replicas. Interface is already Redis-shaped.
- [ ] **Mobile device test.** Expo EAS build, real iOS + Android. Camera skin-analysis flow
      is code-complete but never run on a physical device.

> See `MONSTER-MOVE.md` for the scale-up/exit thesis and the 90-day sprint these ladder into.
> Two items there (repo merge, provisional patent) are **open decisions** — not scheduled work.

## Next (1.3.0 – 1.4.0)

- [ ] **Director dashboard.** Team-level analytics for Director tier — unit activity,
      who's using which skills, aggregate (anonymized) compliance health. This is the
      feature that makes Directors evangelize to their units.
- [ ] **Social content calendar.** Generate a week of MK-specific organic posts at once,
      scheduled. Replaces the Buffer use case without leaving the app. Organic only —
      no paid-ad copy (compliance boundary held).
- [ ] **Live-selling assistant.** Real-time prompt support for TikTok/Instagram Live
      selling — product talking points, objection responses, on-the-fly compliance
      checking. (Live selling is where 2026 beauty-rep growth is — see TRENDS.md.)
- [ ] **Onboarding flow for new consultants.** First-session guided setup that produces
      immediate value (first follow-up draft, first social post) before they hit a paywall.

## Later (1.5.0+)

- [ ] **Network-effects model improvements.** Use aggregated, anonymized cross-consultant
      data to improve skill prompts and skin→product recommendation accuracy. This is the
      moat compounding (see STRATEGY.md "The Moat").
- [ ] **Brand expansion framework hardening.** Tooling/CLI to scaffold a new brand config,
      validate it, and run the brand-specific test matrix — so adding brand #3, #4 takes
      hours not days.
- [ ] **AvonNow / InTouch-style read-only integrations** *if and when* official APIs exist.
      Do not build against unofficial/scraped endpoints — flag as blocked until official.
- [ ] **Voice/phone follow-up drafting** for consultants who prefer calling over texting.

---

## Explicitly Not Doing (and why)

These are recorded so they don't get re-litigated every planning cycle.

- **Accounting/tax/inventory.** Pink Office and Direct Sidekick own this. Different
  product, different regulatory surface. We stay on the customer-relationship side.
- **Paid-ad copy generation.** Platform ad-policy compliance changes constantly and we
  can't fully control it. Organic content only.
- **Replicating MK's own free apps** (Mirror Me, Interactive Catalog). Brand-locked,
  free, not our lane. We're the AI intelligence layer, not a catalog.
- **Income projections / earnings calculators.** Any feature that outputs a predicted
  income is an FTC income claim. Never build it.

---

## Versioning Discipline

- `VERSION` at repo root is the source of truth. Bump it, then sync `main.py`,
  `web/package.json`, `mobile/app.json`.
- Tag every release: `git tag -a v1.2.0 -m "..."` and push tags.
- Every release gets a CHANGELOG.md entry before the tag.
- Breaking schema changes require Alembic (see CLAUDE.md) — no silent `create_all` drift.
