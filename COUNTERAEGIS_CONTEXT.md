# CounterAegis Context

This document is the canonical state of strategic and architectural decisions for the CounterAegis project. AI tooling (Cursor, Claude Code, Copilot) should read this before generating output. Humans (current and future team) should treat it as the single source of truth for "where are we, what did we decide, and why."

Last updated: May 2026
Maintainer: David Cooper

---

## Founder

David Cooper. CCIE #14019. 25 years in network and cybersecurity, including classified Air Force network experience and Fortune 500 enterprise infrastructure. Author of 40+ technical books across AI safety, agent infrastructure, blockchain validators, and cryptographic security.

Currently solo on the build, leveraging agentic IDE tooling (Cursor primary) for velocity. Based in Austin, Texas. Public profiles: github.com/RunTimeAdmin, linkedin.com/in/david-c-192601240, X @DeFiAuditCCIE.

Operating mode: bootstrapped, pre-revenue, design-partner stage. Speedrun (a16z accelerator) application in progress.

---

## What CounterAegis Is

CounterAegis is the trust infrastructure suite for autonomous AI operations. The thesis is that when AI agents make decisions on their own, three questions become operationally critical for any regulated enterprise: who acted, what was touched, and can we prove what happened. CounterAegis answers all three under one integrated platform.

**One-line positioning:** "Trust infrastructure for autonomous AI. Cryptographic identity, content provenance, and forensic governance evidence that survives adversarial review."

**Enemy framing:** point tools that answer one of the three questions (compliance dashboards, observability platforms, identity vendors). They cannot produce the integrated proof chain.

**The closed loop is the moat.** CounterAudit signals to Countersig when an agent's rolling debt index crosses a threshold; Countersig auto-creates a flag policy gated behind manual admin restore. No competitor has all three layers and therefore cannot build the loop.

---

## The Three Products

### Countersig (Identity + Policy)

- Cryptographic identity for AI agents
- Multiple credential types: Ed25519, OAuth2/OIDC, Entra ID federation, API keys, A2A JWT (60s TTL), PKI challenge-response
- Hash-chained audit log with policy-driven criticality and advisory-lock fast path
- Receives policy events from CounterAudit at `/integrations/counteraudit/debt-events` with HMAC verification, timestamp freshness, and Redis-backed idempotency
- Manual-restore gate on auto-created policies (no auto-restore, ever)
- Production stack: PostgreSQL, Redis, Caddy
- Public site: countersig.com
- npm: @countersig/sdk, @countersig/mcp, @countersig/verify, @countersig/react, @countersig/policy-client

### ProvenanceAI (Content + Provenance)

- Multi-algorithm content fingerprinting (basic, DCT, color, multi-scale) computed after format normalization to PNG (defeats format-conversion attacks)
- Per-hour deduplication of verification records by requester IP
- C2PA-compatible manifests
- EU AI Act-aligned compliance reports via ComplianceService
- /verify endpoint fails closed on database unavailability (returns 503 with reason, no silent fallback)
- Production stack: Prisma + PostgreSQL, Stripe billing
- Public site: provenanceai.network

### CounterAudit (Forensic Governance Evidence)

- AES-256-GCM packet sealing with per-organization data encryption keys
- SHA-256 hash chain per organization with genesis at 64 zeros
- RFC 3161 trusted timestamping via FreeTSA (verified through openssl)
- Built-in connectors: LangChain, AutoGen, OpenAI Assistants, Bedrock, Foundry, countersig-native, provenanceai-native
- Custom connectors via JSONPath-style field_map (no code changes needed)
- Seal key envelope architecture: per-org DEK, optionally KMS-held KEK
- Rotation with dry-run, batched mode, resumable checkpoints, full audit log (`ca_seal_rotation_runs`)
- Idempotent ingest via unique index on `(org_id, raw_event_hash)` with race-safe ON CONFLICT
- Compliance mapper: EU AI Act, SOX, NIST AI RMF with role-based sensitivity multipliers and configurable risk bands
- Agentic debt index with tunable per-org weights (env JSON or DB table source)
- Closed-loop scheduler runs independent of dashboard traffic
- Production stack: SQLite with WAL (Postgres migration designed), background scheduler
- Public site: counteraudit.io (developer-tier) and counteraudit.com (currently in flux; pending URL strategy decision)
- npm: @counteraudit/sdk; PyPI: counteraudit

---

## Current Build State

What's shipped and production-defensible:

- All three platforms running with CI-gated integration tests
- Closed-loop sender (CounterAudit) and receiver (Countersig) wired end to end
- Seal key rotation with chain-integrity-preserved test in CI
- Manual-restore policy enforcement (Countersig refuses auto-restore by design)
- Scheduler for debt-policy-loop runs independent of UI
- Compliance mapper with role-sensitivity multipliers (not just one article per category)
- Idempotent ingest with race-safe deduplication
- Prefix-only API key authentication (O(n) bcrypt fallback removed)
- ProvenanceAI /verify fails closed on DB unavailability
- Schema versioning tracked in `SCHEMA_CHANGELOG.md`
- Enterprise smoke test infrastructure with Docker compose, CI workflow, PowerShell runner, and runbook
- Redis-required-in-production toggle for Countersig integrations idempotency

What's pending:

- Postgres migration for CounterAudit (currently SQLite)
- Paid TSA failover (currently FreeTSA only)
- Frontend UX polish for buyer-facing screens (manual-restore review, evidence detail, dashboard hero, audit export wizard, demo screen)
- counteraudit.com URL strategy decision
- counteraegis.com homepage restructure (reducing from 13 sections to 6)
- Compliance posture content (SOC 2 status, GDPR DPA, sub-processors)
- Contact form endpoint at api.counteraudit.io/v1/contact/lead is live (returns 201 on valid POST)

---

## Buyer Profile

**Primary buyer:** CISO, VP of Security, Head of Security Engineering at a 500-to-5000 person enterprise.

**Strong influencer:** VP of Engineering, CTO, Head of AI/ML, Head of Platform Engineering.

**Compliance backstop:** Chief Compliance Officer, VP of Risk, Head of GRC.

**ICP criteria (4 of 5 must be true):**

1. 500-5000 employees
2. Has shipped AI features into production in the last 18 months, or has publicly announced an AI initiative
3. Operates in EU or sells to EU customers (AI Act applies), or US regulated industry (financial services, healthcare, energy)
4. Has a named CISO or VP of Security
5. Has had a publicly reported security incident, regulatory inquiry, or AI-related controversy in last 24 months

**Avoid:** procurement-only contacts, legal counsel, Director of IT without "Security" in title.

---

## Sales Motion and Pricing

**Public pricing anchor:** $30,000/year starting price on counteraegis.com. No tiered comparison table publicly. Pilot and production scopes quoted individually.

**Internal tier guideline (not published):**

- Core (≈ $30K/year): Single environment, single org, one connector type, community support, no SLA, no SSO. Pilot or small production deployment.
- Pro (≈ $80K/year): Up to 3 environments, multiple orgs, all connectors, business-hours support with named contact, 99.5% SLA, SIEM integration, one-time custom compliance mapping. Mid-market security team running AI agents in production.
- Enterprise (≈ $180K+/year): Unlimited environments, dedicated VPC or air-gapped, 24/7 support, 99.9% SLA, SSO + SCIM, 40 hours custom integration work, quarterly compliance attestations.

**Walk-away floors:** $25K pilot, $60K annual.

**Pilot pricing:** $15K for 90 days with documented success criteria and automatic conversion to Pro tier annual contract if criteria are met. Success criteria signed at kickoff.

**Multi-year discounts:** 10% off for 2-year commit, 15% off for 3-year. Both with 5% annual escalator built in.

**Sales motion split:**

- Platform sales (CounterAegis bundle): sales-led. Calendly scoping call, Contact Sales, signed annual contract. No Stripe.
- Individual product sales: Stripe self-serve for Developer tier on each product site. Production tier on each product page links back to counteraegis.com scoping call.

**Why no public tier table:** zero closed customers, need 60 days of buyer-conversation data before committing publicly to tier pricing. Decision date for publishing validated tier page: July 13, 2026.

---

## Positioning and Messaging

**Three-question framework (use everywhere):**

- Who acted? Countersig
- What was touched? ProvenanceAI
- Can you prove what happened? CounterAudit

**Five words to use in marketing:** trust, verifiable, accountable, provenance, governance.

**Five words to AVOID:** AI safety, responsible AI, ethical AI, comprehensive, robust. ("Robust" especially. It's a tell.)

**Enterprise positioning line (use as conference closer, deck headline, t-shirt):** "We don't just monitor agent behavior. We create admissible evidence for it."

**Other key lines:**
- "Receipts for autonomous AI"
- "Regulator-ready evidence, not dashboards"
- "Proof, not promises"

**Why now:** EU AI Act enforcement starts August 2026. Up to 7% of global revenue is on the table for inadequate documentation. Procurement cycles are 6-9 months. The companies who pass these audits are the ones building proof chains in 2026, not 2027.

---

## Voice and Style

**Critical for any AI-generated content:**

- No em dashes. Use periods, semicolons, colons, or rephrase. Em dashes are the single biggest AI tell in this voice.
- No asterisks for emphasis (no markdown bold within prose). Use structure (headers) instead.
- No bullet points instead of narrative. Lists are fine in reference docs (like this one). Conversational responses, articles, and marketing copy should be prose.
- No corporate handbook language. No "in conclusion," "in summary," "moreover," "furthermore," "additionally."
- No hype: no "revolutionary," "game-changing," "cutting-edge," "world-class."
- No generic adjectives doing the work of specifics: avoid "robust," "comprehensive," "advanced," "next-generation."

**Tone:**

- Conversational, like talking to a colleague over coffee
- Skeptical but fair: call out industry BS without being mean
- Playfully sarcastic when appropriate, not constant
- Honest about challenges without catastrophizing
- Direct address: "you" and "your"
- Short paragraphs (1-4 sentences typical)
- Active voice
- Contractions are fine
- Specific examples and concrete numbers beat adjectives

**Voice anchors:** 25-year cybersecurity background, military experience, has sat in 2 AM incident response rooms. Author of 40+ technical books. CCIE-level credibility. The voice should sound like someone who has seen things and is sharing what he learned.

**Anti-pattern (AI-slop tells):**

- "X is not Y. It is Z." parallel sentence rhythm repeated throughout
- "It is worth noting that..."
- "I hope this helps!"
- Confirming feedback by restating it back in structured form
- Closing with "Let me know if you need anything else"
- Three-bullet summaries at the end of every response

---

## What NOT to Do

**Architectural:**

- Never auto-restore policies. Manual admin restore is the only path back. This is gated server-side in Countersig and must stay that way.
- Never silently fall back when a database is unavailable. Fail closed with explicit reason.
- Never add features promised on the website that don't exist (no SOC 2 attestation promises until SOC 2 audit is real).

**Product:**

- Don't add a fourth product to the umbrella. Three is the right surface.
- Don't try to force individual products into a managed cloud offering before the self-hosted story is rock solid.
- Don't auto-revoke agent credentials based on debt index. Flag, manual-review, then revoke if appropriate. Destructive actions require humans.

**Sales/marketing:**

- Don't publish public tier pricing until 10 buyer conversations have happened.
- Don't pitch developer-tier customers on enterprise platform. Let them grow.
- Don't add stock photos, logo walls, or "trusted by" sections until real logos exist.
- Don't write "AI safety" or "responsible AI" in any buyer-facing content.
- Don't use em dashes anywhere.

**Operational:**

- Don't grant Cursor or Claude Code unsupervised access to push to main branches on production sites. PRs only, with human review.
- Don't store seal keys without the database backup. The chain is meaningless without both.

---

## Useful References

**Live URLs:**

- counteraegis.com (umbrella platform site)
- countersig.com (Countersig product)
- provenanceai.network (ProvenanceAI product)
- counteraudit.io (CounterAudit developer site)

**Key repo files:**

- `SCHEMA_CHANGELOG.md` in CounterAudit (packet schema evolution)
- `docs/COUNTERAEGIS_MASTER_GUIDE.md` (the master operational reference)
- `docs/ENTERPRISE_TEST_RUNBOOK.md` (CI smoke gate)
- `docs/INTEGRATIONS_SUMMARY.md` (cross-repo specifics)
- `docs/PRICING_INTERNAL.md` (internal quoting guideline; NEVER publish)
- `.env.example` in each repo (env configuration with all toggles documented)

**Critical environment variables (CounterAudit):**

- `CA_DEBT_POLICY_LOOP_ENABLED=1` (closed loop on/off)
- `CA_DEBT_POLICY_LOOP_INTERVAL_SECONDS` (scheduler tuning)
- `CA_DEBT_POLICY_LOOP_INITIAL_DELAY_SECONDS` (boot stagger)
- `CA_COMPLIANCE_RISK_BANDS_JSON` (compliance mapper tuning)
- `CA_COMPLIANCE_ROLE_SENSITIVITY_JSON` (role multipliers)
- `CA_SEAL_KEYS_JSON` (envelope key configuration)

**Critical environment variables (Countersig):**

- `COUNTERAUDIT_REQUIRE_REDIS_IDEMPOTENCY` (production safety toggle)

**External integrations:**

- Calendly: calendly.com/ccie14019/enterprise-consultation
- Email: contact@counteraegis.com
- Stripe: live on Countersig and ProvenanceAI product sites (Developer tier only)

---

## Decision Log (Most Recent First)

**May 2026:** Restructured public pricing. Single $30K anchor on counteraegis.com, no tier comparison table. Individual product sites retain Stripe self-serve Developer tier and link back to umbrella for Production. Internal three-tier quoting guideline maintained privately.

**May 2026:** Confirmed sales-led motion for platform sales. No self-serve checkout for CounterAegis bundle. Enterprise contract, signed MSA, annual or multi-year commitment.

**May 2026:** Decided manual restore as the only path on auto-created policies. No auto-restore under any condition. Trade-off: prevents attacker-wait-out-window pattern.

**May 2026:** Closed-loop scheduler decoupled from dashboard traffic. Runs on configured interval regardless of UI activity.

**May 2026:** Compliance mapper expanded with role sensitivity multipliers and configurable risk bands. Single-article-per-category replaced with priority-classified effective risk scoring.

**May 2026:** Seal key envelope architecture shipped. Per-org DEK, optional KMS-held KEK, rotation with chain integrity preserved (CI test enforces).

**May 2026:** Idempotent ingest with unique constraint on `(org_id, raw_event_hash)` and race-safe ON CONFLICT handling.

**May 2026:** O(n) bcrypt fallback removed from API key authentication. Prefix-only path enforced.

---

## How to Update This File

When a strategic or architectural decision changes, update the relevant section AND add a one-line entry to the Decision Log with date. Commit with message `context: <one-line summary of decision>`. This file is intentionally living; it represents the current state, not a snapshot.

If you're an AI tool reading this: treat the most recent decisions as authoritative. If something in an older section appears to contradict a more recent decision, the recent one wins. If unclear, ask David before generating output that depends on the contradiction.

---

## For AI Tools: Behavior Guidelines

When generating any output that David will use:

1. Read this entire file before responding to your first prompt in a session.
2. Apply the voice and style rules absolutely. Em dashes, asterisks, and corporate language are zero-tolerance.
3. When in doubt about whether to add a feature, recommend cutting first. Most of the next 60 days is editing, not adding.
4. When generating marketing copy, the voice must sound like a 25-year cybersecurity veteran who is mildly skeptical of his own industry. Not corporate, not academic, not breathless.
5. When generating technical content, the audience is sophisticated. Don't over-explain. Reference SHA-256, AES-256-GCM, RFC 3161, Ed25519 without preamble.
6. When generating sales/buyer-facing content, the audience is CISOs and compliance officers at regulated enterprises. They scan, they don't read. Lead with the value prop, support with proof, end with one clear next step.
7. If you're unsure whether something in this document is still current, ask before generating output that depends on it.
