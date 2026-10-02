# SSPS — Swap Service Provider Specification

```
Status: Draft 2 (proposal), 2026-09-29. Not a finalized standard or bLIP.
License: CC0-1.0
```

SSPS lets a wallet get prices from swap providers, lock funds with one of them,
and end up paid in another asset (a **swap**) or having paid someone else in
another asset (a **payment**). Nobody holds anyone else's funds: a **route** is
a list of **legs** that all lock on one payment hash `H`, each claimed with its
preimage or refunded after a deadline.

## 1. Model

### 1.1 Leg

A leg moves `amount` of an asset on a `rail` from a payer to a payee:

- **lock(H, amount, deadline)**: only the preimage `P` of `H` releases the funds;
- **claim(P)**: the payee takes them, revealing `P`;
- **refund**: after `deadline`, the payer takes them back alone.

| Rail | Lock | `P` revealed by | Refund | Clock |
|---|---|---|---|---|
| `btc` | P2TR: claim leaf (hash + payee key), refund leaf (CLTV + payer key), MuSig2 key path | claim witness | refund leaf | Bitcoin height |
| `liquid` | the same on Elements, L-BTC or an issued asset | claim witness | refund leaf | Liquid height |
| `ark` | `VHTLC.ScriptV2` on an Ark server | claim leaf | refund leaf, or the unilateral leaves after an exit | Unix time |
| `ln` | payment held for `H`: BOLT11 hold invoice, BOLT12 invoice | settlement | HTLC expiry | Bitcoin height |
| `rgb-ln` | RGB Lightning payment held for `H` | settlement | HTLC expiry | Bitcoin height |

Rail ids name the network and, where one exists, the service or asset:
`btc:mainnet`, `liquid:mainnet/<asset id>`, `ark:<server x-only pubkey>`,
`ln:mainnet`, `rgb-ln:mainnet/<contract id>`.

- `liquid` locks are unconfidential or share their blinding key, so the other
  party can verify them.
- `btc` and `liquid` locks use exactly two leaves, with minimal script numbers:

  ```
  claim:  OP_SIZE 32 OP_EQUALVERIFY OP_HASH160 <RIPEMD160(H)> OP_EQUALVERIFY
          <xonly(payee key)> OP_CHECKSIG
  refund: <xonly(payer key)> OP_CHECKSIGVERIFY <deadline> OP_CHECKLOCKTIMEVERIFY
  ```

  The internal key is the BIP-327 `KeyAgg` of the two keys, not sorted: first
  the key of the party that published the lock, then the other party's. The
  publisher is whoever chose the lock's terms: the provider whose quote gives
  its address in `in.lock`, the payer when it builds the lock from the payee's
  `out.claim` and its own `out.refund`, the issuer for an `ssps_lock` (§5.3).
  This is Boltz's order, and with Boltz's leaves a Boltz client rebuilds the
  same address.

  A lock funded by the route's first payer may drop `OP_SIZE 32 OP_EQUALVERIFY`
  from its claim leaf, which is Boltz's submarine leaf; its quote then says
  `"size_check": false` in `in.lock`. That payer never has to reuse `P`. A
  lock funded by a provider keeps the check: the provider settles its own
  incoming leg with the `P` it learns, and Lightning accepts only 32-byte
  preimages.
  Leaf version and tagged hashes are BIP-341's on `btc` (`0xc0`) and Elements'
  on `liquid` (`0xc4`, `TapLeaf/elements`, `TapBranch/elements`,
  `TapTweak/elements`).
- An `ark` lock is Arkade's six-leaf `VHTLC.ScriptV2`: the `VHTLC.Script`
  leaves with `OP_SIZE 32 OP_EQUALVERIFY` ahead of the preimage check on
  `claim` and `unilateralClaim`, whoever funds it. `VHTLC.Script` (v1) checks
  no length, so a payee could claim a provider's lock with a longer preimage
  that no Lightning payment or size-checked lock can be settled with.
- An `ark` lock has four timeouts: `refund`, an absolute Unix time, is the
  leg's deadline (Ark servers reject height-based refund locktimes);
  `unilateral_claim`, `unilateral_refund` and `unilateral_refund_without_receiver`
  are the BIP-68 relative delays, in seconds, of the leaves that spend without
  the server. A quote or `ssps_lock` carries all four and the server key, and
  each of them resolves before the VTXO expires:

  ```json
  "server": "<x-only server pubkey>",
  "timeouts": { "refund": 1790000000, "unilateral_claim": 86528,
                "unilateral_refund": 86528, "unilateral_refund_without_receiver": 86528 }
  ```

  `refund` equals the leg's `deadline`; the delays are multiples of 512.
- An `rgb-ln` amount is the asset amount; the HTLC's BTC is not value.

### 1.2 Route and preimage

A route is legs `L1 … Ln` from the payer to the final recipient. Each provider
sits between its incoming leg `Li` and its outgoing leg `Li+1`. In a swap the
payer is also the recipient; in a payment the recipient is someone else,
identified by what it asked to be paid with (an invoice, an offer, a claim key).

The **recipient** chooses `P` and gives out only `H`. It claims `Ln`, revealing
`P`; each provider then claims its incoming leg with `P`; the payer ends up
holding `P` as proof of payment. No one else may know `P` before the recipient
claims.

### 1.3 Deadlines

Deadlines decrease towards the recipient. When a provider locks its outgoing
leg:

```
deadline(incoming) >= deadline(outgoing) + margin(incoming rail)
```

`margin(rail)` is what the provider needs, once `P` appears on its outgoing
leg, to make its incoming claim final: observation delay, confirmations,
fee-bumping room and reorg depth on chain rails, a unilateral exit on `ark`, an
on-chain HTLC resolution on `ln` if the peer is offline. Providers publish
margins (§3.1) and refuse, never clamp, a route that breaks them.

Chain and Ark deadlines are fixed in the lock. An `ln` deadline is the HTLC
expiry, known only on arrival: a provider receiving on `ln` requires a
`min_final_cltv` and checks the expiry it got; a provider paying on `ln` caps
the route's CLTV below its incoming deadline minus the margin.

Across clocks, convert with the published block intervals, round in the safe
direction and add margin.

## 2. Safety rules

These are the protocol; the messages only carry them. Every implementation MUST
follow them.

1. **Verify locks yourself.** Rebuild the expected lock from `H`, keys, amount,
   asset and deadline, and compare it with what is funded or held.
2. **Act only on ready legs.** A chain leg is ready at the confirmations the
   quote states. A provider may state `0` on `liquid` only; it then carries the
   risk itself and ignores a transaction that signals RBF or pays below its
   fee estimate. A Lightning leg is ready when the full
   amount is held and its earliest HTLC expiry satisfies §1.3. A partial
   multi-part set is failed back as a whole after at most 60 s.
3. **Lock outgoing only after incoming is ready**, rechecking §1.3 with actual
   values.
4. **Reveal gate.** The recipient reveals `P` only if its incoming leg is ready
   and can still be claimed before its refund opens.
5. **Claim at once.** A provider that learns `P` claims its incoming leg
   immediately.
6. **Hold until the outgoing leg is dead.** Never fail back a held incoming leg
   while the outgoing leg can still be claimed.
7. **Refunds are unilateral.** Every lock is refundable by its payer after the
   deadline without the payee. Cooperative refunds are optional, and refused by
   a party with unresolved exposure.
8. **Persist before funding.** Store everything needed to refund before
   funding, and the funding outpoint as soon as it is known.
9. **No secrets before the lock.** Requests and quotes carry no preimage and
   nothing that can spend.
10. **One hash, one route.** A fresh `H` per attempt, never reused across
    providers or retries. A payer funds at most one lock per `H` and never
    funds again an `H` whose route has ended, whatever it knows of `P`. A
    provider fails back any payment on `H` after its route has ended.

## 3. Messages

JSON objects with `"v": 2` and a `"type"`. Amounts are decimal strings in the
asset's smallest unit; deadlines use the leg's clock; unknown fields are
rejected. `JCS` is RFC 8785. Use a fresh `id` and fresh keys per provider asked.

### 3.1 `card`

```json
{ "v": 2, "type": "card", "pubkey": "<x-only identity>", "name": "example",
  "pairs": [{ "from": "ln:mainnet", "to": "liquid:mainnet/<asset id>",
              "min": "10000", "max": "5000000", "fee_ppm": 2500, "fee_base": "0" }],
  "margins": { "btc": 72, "liquid": 120, "ark": 86400, "ln": 40 },
  "block_seconds": { "btc": 600, "liquid": 60 },
  "relays": ["wss://relay.example"], "http": "https://swap.example/ssps" }
```

Indicative only: it reserves nothing and binds no price. `margins` apply to the
rail as the provider's incoming leg, in that rail's clock unit.

### 3.2 `rfq`

```json
{ "v": 2, "type": "rfq", "id": "<random 32-byte hex>",
  "from": "btc:mainnet", "to": "liquid:mainnet/<asset id>",
  "side": "to", "amount": "100000", "payment_hash": "<H>",
  "in":  { "refund": "<payer refund pubkey>" },
  "out": { "claim": { "key": "<payee claim pubkey>", "address": "<payout address>" },
           "deadline": 3511440 } }
```

- `side` fixes `from` (what the payer locks) or `to` (what the payee gets).
- `in.refund` is the payer's refund key for chain and Ark rails. On `ln` it is
  either absent, for a BOLT11 hold invoice, or a BOLT12 refund (`lnr1…`) that
  the provider answers with an invoice held on `H` (§5.2).
- `out.claim` is the payee: its claim key and payout address on chain and Ark
  rails (a plain address cannot be claimed with `P`, so it is not a valid
  payout; a provider payee may omit the address), an invoice or offer (§5) on
  `ln` and `rgb-ln`. `out.deadline` is required on chain and Ark rails.
- `payment_hash` may be omitted when `out.claim` commits to one; if both are
  given they must match.

### 3.3 `quote`

```json
{ "v": 2, "type": "quote", "id": "<rfq id>", "request": "<hex SHA256(JCS(rfq))>",
  "pubkey": "<provider identity>", "payment_hash": "<H>",
  "from_amount": "100250", "to_amount": "100000", "valid_until": 1790000120,
  "in":  { "lock": { "claim_key": "<provider claim pubkey>", "address": "<lock address>" },
           "deadline": 921300, "confirmations": 1 },
  "out": { "refund": "<provider refund pubkey>", "deadline": 3511440, "confirmations": 2 },
  "sig": "<BIP-340>" }
```

- `request` binds the quote to the exact `rfq`.
- `in.lock` lets the payer rebuild the incoming lock: the provider's claim key
  and the resulting address on chain and Ark rails, plus `server` and
  `timeouts` (§1.1) on `ark`; the hold invoice on `ln` and `rgb-ln`.
  `out.refund` is the provider's refund key for an outgoing chain or Ark lock,
  so the payee can rebuild it; an outgoing Ark lock adds `server` and
  `timeouts` to `out`.
- An `ln` leg carries `min_final_cltv` (incoming) or `max_expiry` (outgoing)
  instead of `deadline`.
- `out.invoice` is present when `out.claim` was an offer (§5).
- The fee is `from_amount` minus the value of `to_amount`; nothing else is
  charged.
- `sig` is by `pubkey`, the card's key, over
  `SHA256("SSPS/quote/v2:" || JCS(quote without sig))`.

**Funding the incoming lock before `valid_until` accepts the quote**; there is
no accept message. The provider then honours it, subject only to §2. A late,
short or wrong deposit is refunded, never repriced. Until `valid_until` the
payer holds a free option, so providers keep it short and cap open quotes.

### 3.4 `refusal` and `status`

```
{ "v": 2, "type": "refusal", "id": "<rfq id>", "reason": "amount_out_of_range" }
{ "v": 2, "type": "status", "id": "<rfq id>", "state": "out_locked", "detail": "<txid, ...>" }
```

`reason`: `unsupported_pair`, `amount_out_of_range`, `exposure_cap`,
`deadline_too_short`, `invalid_request`, `pricing_unavailable`.

`state`: `quoted`, `in_locked`, `out_locked`, `claimed`, `refunded`, `expired`,
`stuck` (a human is needed). A `status` without `state` is a request. Status is
informational; every party checks its chain or node itself.

## 4. Routes across providers

Build the route backwards from the recipient:

1. The recipient gives `H` and its request.
2. Ask providers for the last hop with `out.claim` set to that request; the
   chosen quote's `in` becomes the previous hop's `out`. Repeat towards the
   payer.

On a chain or Ark leg between two providers the upstream provider publishes
the lock: the downstream quote gives only `in.lock.claim_key`, its deadline and
confirmations, the upstream provider builds the lock with its own key and
states it as `out.refund`, and the downstream provider rebuilds it before
acting (rule 1). The downstream quote cannot give an address, because the
upstream provider's refund key is not known when it is asked. An `ln` leg needs
neither.
3. Verify the whole route (amounts, `H`, deadlines, signatures, `request`),
   then lock `L1`. The route arms from the payer and settles from the
   recipient.

Downstream quotes are accepted only when an upstream provider funds them, so
their `valid_until` must cover the upstream confirmations; a provider never
funds a quote that will expire before its lock is ready.

Ask several providers per hop, fund one. An uncertain funding is resolved with
that provider, never by funding another with the same `H`.

## 5. BOLT12

### 5.1 Paying an offer

An `ln` leg that pays an offer is bound to one invoice before anything is
funded: the provider fetches the invoice and returns it as `quote.out.invoice`.
The payer checks that it is signed by the offer's `offer_issuer_id` or, if
there is none, by the last node of one of the offer's blinded message paths,
and that its amount and `invoice_payment_hash` match the quote.

### 5.2 Receiving on an offer

A provider receiving on `ln` may present the hold as a BOLT12 offer or refund
invoice committing to `H`, for BOLT12-only payers. All invoices of such an
offer share `H`, so it is single-use (rule 10).

### 5.3 Rails in an offer

An offer can list the rails its issuer accepts, so a payer can pay directly on
one of them, or through providers when it has none. Three odd TLVs carry this,
so other wallets see a normal offer; their types sit in BOLT12's experimental
ranges until allocated. Values are UTF-8 JCS JSON.

| Stream | Type | Value |
|---|---|---|
| offer | 1000000385 | `ssps_rails`: accepted rail ids, most preferred first; `ln` is always accepted, last unless listed |
| invoice_request | 2000000385 | `ssps_rail`: `{ "rail", "refund" }` chosen by the payer |
| invoice | 3000000385 | `ssps_lock`: `{ "rail", "amount", "key", "address", "deadline", "confirmations" }` for `invoice_payment_hash` |

The invoice signature authenticates `ssps_lock` as the issuer's.
`invoice_amount` stays the Lightning price; `ssps_lock.amount` is the price on
that rail.

The payer takes the first listed rail it can pay on, requests an invoice with
`ssps_rail`, and locks `ssps_lock` directly: a one-leg route. If it can pay on
none, it requests an invoice for a listed rail and builds a route (§4) ending
in that `ssps_lock`, or in the invoice itself for `ln`. The order is a
preference, not an obligation. The issuer watches each listed rail for a
matching lock and claims it under rule 4.

### 5.4 Offers for wallets without a node

A provider can host the offer of a wallet that has no Lightning node, if its
node can hold a payment for a hash the wallet chose. The offer carries an
`offer_issuer_id`, which is how the provider recognises it, and its blinded
message path enters at the provider's node. Each payment is a two-leg route
from `ln` to the wallet's rail:

1. The wallet registers the offer with
   `{ "v": 2, "type": "offer", "offer": "lno1...", "sig": "<BIP-340>" }`, `sig`
   by the issuer key over `SHA256("SSPS/offer/v2:" || JCS(offer without sig))`.
   With `"remove": true` the same message unregisters it. On HTTP it also
   carries a `url` the provider calls with each `invreq`, and that answers
   with the `invoice`.
2. For each invoice request, the provider finds the offer by the request's
   issuer key and relays
   `{ "v": 2, "type": "invreq", "offer": "lno1...", "invoice_request": "<hex>" }`.
3. The wallet picks a fresh `P` and sends an `rfq` from `ln` to its rail.
4. The `quote`'s `in.lock` carries the provider's node id and `min_final_cltv`,
   and blinded payment paths for `H` ending at the provider. A provider whose
   node authenticates its own receive data, as LDK does, must supply the
   paths. Only a provider that states it accepts a wallet-built path may leave
   them out, and the wallet then builds a one-hop path entering at its node.
5. The wallet signs an invoice with those paths using the issuer key and returns
   `{ "v": 2, "type": "invoice", "invoice": "<hex>" }` for the payer.

The provider holds the payment and settles as in §4.

## 6. Transports

The same messages travel on every transport.

**Nostr.** Kind `38384` carries `card` as an addressable event (`d` = `ssps`);
kind `28384` carries every other message as an ephemeral event. Both kinds are
unallocated experimental values.

- Cards, as Electrum swap-server offers: authored by `card.pubkey`, tagged
  `["n","<network>"]` and `["expiration","<unix>"]`, republished before expiry.
  Providers MAY add NIP-13 proof of work, and clients MAY rank by it.
- Messages, as Arkade Intents RFQs: NIP-44 encrypted to the receiver, tagged
  `["p","<receiver>"]`, `["expiration","<unix>"]` and on replies
  `["e","<request id>"]`. Clients use a fresh key per request; providers keep
  subscriptions open, since relays store nothing.
- A quote is verified by its `sig`, not by the event carrying it.

**HTTP.**

| Request | Response |
|---|---|
| `GET {http}/card` | `card` with `sig` over `SHA256("SSPS/card/v2:" \|\| JCS(card))` |
| `POST {http}/rfq` | `quote` or `refusal` |
| `POST {http}/offer` | `status` |
| `GET {http}/status/{id}` | `status` |

Cooperative MuSig2 claims and refunds are optional per rail and never needed
for safety.

## 7. Limits

SSPS does not make providers honest (a provider that does not deliver never
learns `P` and is refunded against), does not rank them, and does not hide the
route from them: every hop sees the same `H`.

## 8. Scenarios

Each scenario lists the route from payer to recipient. Locks go down, in that
order; `P` goes back up, as the claims.

### 8.1 Swaps

Classic swaps are two-leg routes where the payer is also the recipient, so the
payer chooses `P`, except when it pays a third-party invoice.

```
submarine            reverse              chain
Alice                Alice                Alice
  │ btc HTLC           │ ln hold             │ btc HTLC
  ▼                    ▼                     ▼
Provider             Provider             Provider
  │ ln payment         │ liquid HTLC         │ liquid HTLC
  ▼                    ▼                     ▼
invoice payee        Alice                Alice
```

### 8.2 Direct payment on another rail (§5.3)

```
Alice (has L-USDT)
  │ liquid HTLC, L-USDT, from Bob's ssps_lock
  ▼
Bob (offer: ssps_rails = [liquid:mainnet/<USDt>, ln])
```

Alice requests an invoice with `ssps_rail = liquid`, verifies the `ssps_lock`
it carries, and locks it. Bob claims and `P` is Alice's receipt. No provider.

### 8.3 Payment through a provider (§4, §5.3)

```
Alice (has BTC on Ark)
  │ ark VHTLC, BTC, deadline t2
  ▼
Maker
  │ rgb-ln hold, USDT, deadline t1        t2 >= t1 + margin(ark)
  ▼
Merchant (offer: ssps_rails = [rgb-ln:mainnet/<USDT>, ln])
```

Alice cannot pay on any listed rail. She requests an invoice for `rgb-ln`,
asks makers for `ark → rgb-ln` with `out.claim` = that invoice, and locks the
chosen maker's VHTLC. The maker locks the RGB payment once the VHTLC is ready.

### 8.4 Swap between two Ark servers (§4, §5.1, §5.2)

```
Alice on Ark A
  │ ark VHTLC on A, deadline t3
  ▼
Maker 1
  │ ln, BOLT12 invoice held on H, deadline t2
  ▼
Maker 2
  │ ark VHTLC on B, deadline t1           t3 > t2 > t1
  ▼
Alice on Ark B
```

Alice chooses `P`. She asks Maker 2 for `ln → ark B` with her claim key on B;
its quote's `in.lock` is a single-use offer for `H`. She asks Maker 1 for
`ark A → ln` with `out.claim` = that offer, verifies the whole route, and
locks on Ark A. Her claim on Ark B releases every leg.

### 8.5 Offer for a wallet without a node (§5.4)

```
Payer (any BOLT12 wallet)
  │ ln, BOLT12 invoice held on H, deadline t2
  ▼
Provider (hosts the offer)
  │ liquid HTLC, L-BTC, deadline t1
  ▼
Carla (Liquid wallet, signs the invoice)
```

For each invoice request the provider relays, Carla picks a fresh `P`, gets
the entry node and `min_final_cltv` for `H` in a quote, and signs the invoice.
The payer sees an ordinary BOLT12 payment.

