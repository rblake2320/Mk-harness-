# MK Copilot — Business Strategy
*Last updated: June 24, 2026*

---

## What We Are Building and Why It Wins

MK Copilot is a subscription AI assistant built specifically for Mary Kay
independent beauty consultants. The key word is *specifically*. Generic AI tools
(ChatGPT, Claude) hallucinate Mary Kay prices, generate income claims that violate
FTC law, and forget every customer conversation the moment the chat ends. We do
none of those things. That specificity is the product.

---

## The Money: How We Make It

### Pricing Tiers

| Tier | Price | Who It's For |
|------|-------|-------------|
| **Solo** | $9.99/mo or $89/yr | Individual consultant |
| **Director** | $24.99/mo or $219/yr | Director + up to 12 downline reps |
| **Studio** | $79/mo | Area/regional manager, 50+ reps |

**Annual pricing** is the right default to push. A consultant who pays annually is 8x
less likely to churn. The $89/yr price ($7.42/mo effective) makes the "is it worth it"
math undeniable.

### Revenue Math at Scale

| Active Subscribers | Monthly Revenue | Annual Revenue |
|-------------------|-----------------|----------------|
| 500 | $4,995 | $59,940 |
| 2,000 | $19,980 | $239,760 |
| 5,000 | $49,950 | $599,400 |
| 10,000 | $99,900 | $1,198,800 |

Mary Kay has approximately 200,000–400,000 active US consultants. 2% penetration
at the Solo tier = 4,000–8,000 subs. That's $480K–$960K ARR at $9.99/mo.
Directors are fewer in number but 2.5x the revenue per seat and they bring their teams.

### What Drives the Number Up

1. **Director conversion** — One director switching brings their whole downline with them.
   Sell the director, get 10–15 consultants. Team pricing is the leverage point.
2. **Annual prepay** — Push annual at every touchpoint. Monthly churn in this market
   is high. Annual locks in the relationship.
3. **Referral credit** — $5 account credit for every referred consultant who activates.
   Costs us ~$5, acquires a customer worth $120/yr. Best CAC in the stack.
4. **Avon and future brands** — Same infrastructure. Marginal cost to add a brand is
   one config file. Revenue multiplies, costs don't.

---

## The Value Proposition: Why They Pay and Why They Stay

### What We Replace (and what that costs them now)

| Tool | What It Does | Monthly Cost |
|------|-------------|-------------|
| Teamzy | CRM + daily contact suggestions + scripts | $29.99 ($24.99 annual) |
| ChatGPT Plus | Social content, message drafting | $20.00 |
| Buffer (paid) | Social scheduling — free tier exists but limited | $0–$15 |
| **Total** | | **$50–65/mo** |

Note: Mary Kay provides free apps (Mirror Me skin analyzer, Interactive Catalog, Mobile
Learning). We're not competing with those — they're brand-locked feature tools, not AI.
We compete with the third-party stack above.

Also watch: **Penny CRM** ($6.99/mo, annual) is a newer, lighter-weight Teamzy
alternative. Lower price, less feature depth. If consultants migrate to Penny to save
on CRM cost, we still replace their ChatGPT usage ($20) and add things Penny can't do.

**We cost $9.99/mo and replace the core value of the expensive half of that stack.**

- Our daily suggestions endpoint (Power Hour) = Teamzy's main feature at 1/3 the price
- Our social content skill generates custom MK-specific captions = ChatGPT + Buffer,
  but without hallucinated prices or FTC-violating income claims
- Our follow-up writer generates the actual message, not just the reminder to send one

The pitch is one sentence: *"You're paying $50+ a month for tools that don't know Mary
Kay. We charge $10 and we know it cold."*

### What We Do That Nothing Else Does

1. **Prices that are actually right.** ChatGPT will tell a consultant the TimeWise Miracle
   Set is $89. It's $116. A consultant who quotes the wrong price to a customer loses the
   sale and the trust. We never invent a price.

2. **FTC compliance built in.** Our income claim filter (58 patterns) blocks the AI from
   generating content that violates FTC Act §5. A single FTC complaint can cost a
   consultant their business. No other tool in this price range does this.

3. **Skin profile follows the customer.** When a consultant runs a skin analysis on a
   customer, we store her undertone (warm/cool/neutral) and Fitzpatrick type in the CRM.
   Six months later, when that customer's name comes up in the follow-up writer, the AI
   knows her skin type and recommends the right Anew product variant. No other tool
   connects these dots.

4. **Runs on local hardware.** When `SKIN_ANALYSIS_URL` points to the local PanDerm
   instance, skin analyses cost zero API dollars and the photo never leaves the machine.
   That's a real privacy argument for consultants who are cautious about uploading
   customer photos to cloud services.

### Why They Don't Cancel

The tools consultants cancel first are tools that feel abstract — they're paying for
*potential* value. Our tool delivers value on the first use: the first follow-up message
it drafts is better and faster than writing it yourself. The first time the compliance
filter catches something the model was about to send, it proves it's working.

The tools consultants keep even when money is tight are tools tied to real revenue.
Our Power Hour (daily suggestions) directly prompts conversations that turn into orders.
One reorder from a customer who would have gone cold pays for 3 months of subscription.
Make that math visible in the product: show consultants the estimated revenue impact
of the customers they contacted.

---

## How We Grow

### Phase 1 — Find the Community (Months 1–3)

Mary Kay has an active digital rep community:
- Facebook groups: "Mary Kay Consultants" (largest), director-specific groups
- YouTube: beauty rep channels with 10K–100K subscribers
- Instagram: consultants posting under #marykay #mkconsultant #marykayrepresentative
- TikTok: growing live-selling community

**Tactic:** Offer 60-day free trials (not 30) to active rep bloggers and YouTubers in
exchange for honest reviews. One mid-size creator driving 50 trials is worth more than
$5,000 in paid ads. The content lives forever.

**Do not:** run generic Meta ads. They convert poorly in this audience and the targeting
options for "Mary Kay consultant" are weak. Community-first is the only path that works.

### Phase 2 — Own the Director Channel (Months 3–6)

Directors are the distribution network. A National Sales Director manages hundreds of
consultants. If she recommends a tool, her team uses it.

**Tactic:** Identify 50 active Mary Kay directors on social media. Offer each a free
Director account for 90 days. No pitch — just use it. Directors who see value will
share it with their units without being asked, because it makes their unit perform better
(and unit performance is how directors earn).

### Phase 3 — Make the Data Work (Months 6–12)

By this point we have:
- Skill usage patterns: what consultants ask most (tells us what to improve)
- Compliance flag data: what income claims are still being generated (tells us what the
  model needs more guardrail on)
- Skin profile data: aggregate undertone/Fitzpatrick distribution across the customer base
  (market research that has never existed before)
- Conversation length and return rate: which skills drive re-engagement

Use this data two ways:
1. **Improve the product** — skills that get low engagement get better prompts
2. **Build the pitch for the next brand** — when we approach Avon or Tupperware,
   we bring real data about how AI-assisted consultants perform vs. those without

---

## What We Don't Do (and Why That's Right)

**We don't do accounting.** Pink Office ($11.95/mo) owns that market and does it well.
An accounting tool is a different product with different regulatory exposure. Our lane is
the *sales and customer relationship* side. Tell consultants explicitly: "For taxes and
inventory, use Pink Office. We handle everything that touches customers."

**We don't replace InTouch ordering.** Mary Kay's systems are not available to us.
Don't promise integration that can't exist.

**We don't run paid social ads.** Generating Meta/TikTok ad copy involves compliance
rules we can't fully control (platform-level rules change constantly). Our social skill
generates organic content only. Be explicit about this boundary.

**We don't promise income outcomes.** We help consultants have better conversations.
Better conversations lead to more sales. That's the causal chain we can defend. We never
say "use us and earn more" — that's an income claim.

---

## The Moat: Why This Gets Harder to Copy Over Time

Month 1: Anyone can build a chatbot for Mary Kay reps. The brand config is not the moat.

Month 6: We have 2,000 consultants' worth of conversation data. We know what questions
come up most. We know which follow-up templates get used and which get ignored. We know
which compliance patterns the model still gets wrong. A competitor starting fresh has none
of this.

Month 12: We have skin profile data on tens of thousands of customers. The relationship
between undertone, concern category, and product recommendation is trained into the model.
Our skin-to-product recommendations are more accurate than a new entrant's.

Month 18: We have Avon data alongside MK data. The cross-brand skin analysis model is
better than either brand-only model. A new entrant building for one brand is fighting
our two-brand training set.

The moat is data. Every paying subscriber makes the product better for every other
subscriber. That's the network effect that direct sales tool companies — Teamzy, Pink
Office, AV4 — never built because they never tried.

---

## Unit Economics Summary

| Metric | Target |
|--------|--------|
| Monthly price (Solo) | $9.99 |
| Annual price (Solo) | $89 |
| Monthly churn (annual sub) | <2% |
| Monthly churn (monthly sub) | <8% |
| CAC via referral | ~$5 |
| CAC via creator/influencer | ~$15 |
| LTV (annual sub, 18mo avg) | $134 |
| LTV:CAC ratio | 9:1 (referral) / 3:1 (influencer) |
| Gross margin | ~85% (infra cost per user is minimal on local hardware) |

The business is good at scale and great at Director tier. Push annual, push Directors,
let the referral engine run.
