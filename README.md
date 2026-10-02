# SSPS — Swap Service Provider Specification

**Draft 2 (proposal), 2026-09-29. Not a finalized standard or bLIP.** CC0-1.0.

SSPS lets a wallet swap between rails, or pay someone on another rail, through
providers that never hold its funds. Every route is a list of legs locked on one
payment hash: BTC and Liquid HTLCs, Ark VHTLCs, Lightning and RGB Lightning
hold payments. BOLT12 offers can list the rails their issuer accepts, so a payer
pays directly when it shares one, and through providers when it does not.

The whole specification is one document: [ssps.md](ssps.md).

| Section | Content |
|---|---|
| 1–2 | Model (legs, routes, preimage ownership, deadlines) and safety rules |
| 3–4 | Messages and routes across providers |
| 5 | BOLT12: paying offers, held offers, rails in an offer, hosted offers |
| 6 | Transports: Nostr (Electrum-style cards, Arkade Intents-style RFQs) and HTTP |
| 8 | Scenarios |

Draft 2 replaces two earlier private drafts; the [changelog](CHANGELOG.md) says
what changed.

## Test vectors

[test-vectors/draft2.json](test-vectors/draft2.json) covers the `btc` and
`liquid` locks, a signed card (HTTP and Nostr), an `rfq` and the `quote` that
binds it, NIP-44 encrypted Nostr messages, and the three BOLT12 TLVs. All keys
are public test keys; the pure-Python primitives in `tools/ssps_ref.py` are for
fixtures only. NIP-44 is also checked against a subset of the
[official vectors](test-vectors/nip44-official-subset.json).

```
python3 tools/gen_vectors.py --check
python3 tools/check_vectors.py
python3 tools/check_links.py
```

With `tools/requirements-check.txt` installed, `check_vectors.py` also verifies
signatures, JCS and ChaCha20 with independent libraries.

Open for review: issues and pull requests welcome. [Contributing](CONTRIBUTING.md) ·
[CC0-1.0](LICENSE).
