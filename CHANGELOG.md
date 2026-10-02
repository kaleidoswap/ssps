# Changelog

## Draft 2 — 2026-09-29

Breaking rewrite into a single document, [ssps.md](ssps.md), replacing draft 1
(a separate core, bindings and research documents, never published).

- One model: a route of legs locked on one hash, recipient-owned preimage and
  deadlines decreasing towards the recipient. Swaps, payments and chains
  across providers are routes of different lengths; the submarine, reverse
  and chain flows become examples.
- Rails as a table (`btc`, `liquid`, `ark`, `ln`, `rgb-ln`) instead of separate
  asset documents.
- Ten safety rules carried over from draft 1's core and condensed.
- Five messages (`card`, `rfq`, `quote`, `refusal`, `status`); funding a quote
  accepts it. Quotes bind the exact request by digest.
- Nostr cards follow Electrum swap-server offers; RFQs follow Arkade Intents.
- BOLT12 in the core: verified invoices for offers, held single-use offers,
  rails listed in an offer, and offers hosted for wallets without a node.
- Scenarios section.
- Not carried over: open intents, provider-LN-first flow, requote, portable
  backup format, reputation; zero-conf only on `liquid`, at the provider's
  risk.
- Draft 1 fixtures do not apply to draft 2. New vectors in
  `test-vectors/draft2.json`, generated and checked by `tools/`, with negative
  cases and NIP-44 checked against official vectors.
- Chain locks are specified exactly (the draft 1 leaves, internal key
  aggregated in Boltz's order, lock publisher first), and quotes carry
  `in.lock.claim_key` and `out.refund` so both payer and payee can rebuild
  their locks. Both gaps surfaced while writing the vectors.
- Revised after a review against Boltz: rule 10 no longer forbids the payer
  of a reverse or chain swap from paying an `H` whose `P` it chose; rule 2
  allows `0` confirmations on `liquid` when the quote states it; `ark` locks
  carry the VHTLC's four timeouts; hosted offers (§5.4) are registered with a
  signed `offer` message and need an `offer_issuer_id`.
- Then corrected: `ark` stays on the Unix time clock (Ark servers reject
  height-based refund locktimes; the unilateral delays are BIP-68 seconds);
  a hosted-offer quote carries the blinded payment paths, and a wallet builds
  its own only when the provider says its node accepts that (LDK
  authenticates its receive data, so it does not); a chain or Ark leg between
  two providers is published by the upstream provider, since its refund key is
  not known when the downstream one is asked, and "publisher" is defined as
  whoever chose the lock's terms.
- A lock funded by the route's first payer may use Boltz's submarine claim
  leaf, without the size check, flagged by `in.lock.size_check: false`;
  provider-funded locks keep the check.

## Scope clarification — self-swap and paythrough

Added the pair/rail matrix and two payment topologies: taker/provider self-swap,
and Alice paying BTC while Bob receives stablecoins. Defined candidate common-hash
flow, payer/recipient permissions, recipient authentication, net-amount and fee
requirements, refund paths and early-disclosure assumptions. General stablecoin
paythrough remains a new-profile design, not a silent native-schema extension.
Documentation only; no implementation or fixture format changes.

## Review draft 1 — 2026-09-27

Breaking proposal revision; protocolVersion 1 now explicitly requires draftRevision
1 and settlementProfile ssps-htlc-v1. Existing swaps retain their original profile.

- Core: flow-specific preimage ownership; expected-script and funded-output checks;
  separate receiving/opposing reveal gates; explicit cross-clock assumptions.
- Quote: signed chain/rail identity, request/client binding, exact decimal-string
  arithmetic, domain separation and distinct quote/funding deadlines.
- REST: new proposed /ssps/v1 namespace, signed creation request, private capability,
  persistent idempotency, explicit signing sessions and versioned events.
- SSPS5: proposed Nostr discovery/private RFQ/open RFQ; signed participation evidence,
  privacy rules, anti-duplication and local ranking without compulsory global scores.
- SSPS7: separate bilateral selection, funded open intents and provider-LN-first
  research flow; concurrency, cancel/fill, partial-fill and failover constraints.
- SSPS3: withdraw invalid TLV namespaces/duplicates and amountless invoices;
  retain correctly framed experimental building blocks, explicitly research-only.
- SSPS4: introduce asset validity/recovery gates; historical amendments no longer
  override current core, missing SSPS6 dependencies removed.
- Structured fixtures/schema, reference negative checks and optional independent
  signature/JCS/schema checks; document remaining E2E gaps.

New draft text supersedes the reviewed draft-0 contract.
