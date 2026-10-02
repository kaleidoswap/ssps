#!/usr/bin/env python3
"""Generate test-vectors/draft2.json deterministically (public test keys only).

python3 tools/gen_vectors.py --write   rewrite the fixture
python3 tools/gen_vectors.py --check   fail if the fixture is stale
"""
import argparse
import json
import sys
from pathlib import Path

import ssps_ref as r

ROOT = Path(__file__).resolve().parents[1]
FIXTURE = ROOT / 'test-vectors/draft2.json'
QUOTE_DOMAIN = b'SSPS/quote/v2:'
CARD_DOMAIN = b'SSPS/card/v2:'
KIND_CARD, KIND_MESSAGE = 38384, 28384
TLV_RAILS, TLV_RAIL, TLV_LOCK = 1000000385, 2000000385, 3000000385
USDT = 'ce091c998b83c78bb71a632313ba3760f1763d9cfcffae02258ffa9865a37bd2'


def secret(byte): return int.from_bytes(bytes([byte]) * 32, 'big')
def xonly(s): return r.xbytes(r.pubkey(s)).hex()
def compressed(s): return r.cbytes(r.pubkey(s)).hex()


def signed(domain, value, key):
    digest = r.signed_digest(domain, value)
    return {**value, 'sig': r.schnorr_sign(digest, key).hex()}


def tlv(record_type, value):
    raw = r.jcs(value)
    return (r.bigsize(record_type) + r.bigsize(len(raw)) + raw).hex()


# An `ark` VHTLC.ScriptV2 lock as @arkade-os/sdk 0.4.60 builds it (six leaves, no
# covenants). Copied from the SDK, not derived here: the tools rebuild only the
# claim leaf; the output key is the SDK's tweakedPublicKey for these inputs.
ARK_V2 = {
    'source': '@arkade-os/sdk 0.4.60 VHTLC.ScriptV2, regtest',
    'sender': '79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798',
    'receiver': 'c6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5',
    'server': 'f9308a019258c31049344f85f89d5229b531c845836f99b08601f113bce036f9',
    'preimage_hash160': '6f0e2b1c9a3d4e5f60718293a4b5c6d7e8f90a1b',
    'timeouts': {'refund': 1800003600, 'unilateral_claim': 512, 'unilateral_refund': 1024,
                 'unilateral_refund_without_receiver': 1536},
    'claim_leaf': '82012088a9146f0e2b1c9a3d4e5f60718293a4b5c6d7e8f90a1b876920c6047f9441ed7d6d'
                  '3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5ad20f9308a019258c31049344f'
                  '85f89d5229b531c845836f99b08601f113bce036f9ac',
    'output_key': '205fcd2eb2a6c08273f7e2a7853112b64c8511bc3af199548e426dac83068455',
}


def generate():
    identity, client_nostr = secret(0x04), secret(0x05)
    payer_refund, provider_claim = secret(0x02), secret(0x01)
    recipient_claim, provider_refund = secret(0x07), secret(0x08)
    preimage = bytes([0x11]) * 32
    payment_hash = r.sha256(preimage)
    H = payment_hash.hex()
    tips = {'btc': 921000, 'liquid': 3510000}
    in_deadline, out_deadline = tips['btc'] + 300, tips['liquid'] + 1440

    btc_lock = r.htlc('btc', payment_hash, bytes.fromhex(compressed(provider_claim)),
                      bytes.fromhex(compressed(payer_refund)), in_deadline, publisher='claim')
    btc_address = r.bech32m('bc', 1, bytes.fromhex(btc_lock['output_key']))
    liquid_lock = r.htlc('liquid', payment_hash, bytes.fromhex(compressed(recipient_claim)),
                         bytes.fromhex(compressed(provider_refund)), out_deadline,
                         publisher='refund')
    payout = r.bech32m('ex', 1, bytes.fromhex(xonly(secret(0x09))))

    card_body = {'v': 2, 'type': 'card', 'pubkey': xonly(identity), 'name': 'example',
                 'pairs': [{'from': 'btc:mainnet', 'to': 'liquid:mainnet/' + USDT,
                            'min': '10000', 'max': '5000000', 'fee_ppm': 2500, 'fee_base': '0'}],
                 'margins': {'btc': 72, 'liquid': 120, 'ark': 86400, 'ln': 40},
                 'block_seconds': {'btc': 600, 'liquid': 60},
                 'relays': ['wss://relay.example'], 'http': 'https://swap.example/ssps'}
    card = signed(CARD_DOMAIN, card_body, identity)
    card_event = r.nostr_event(identity, KIND_CARD,
                               [['d', 'ssps'], ['n', 'mainnet'], ['expiration', '1790003600']],
                               r.jcs(card_body).decode(), 1790000000)

    rfq = {'v': 2, 'type': 'rfq', 'id': 'cd' * 32,
           'from': 'btc:mainnet', 'to': 'liquid:mainnet/' + USDT,
           'side': 'to', 'amount': '100000', 'payment_hash': H,
           'in': {'refund': compressed(payer_refund)},
           'out': {'claim': {'key': compressed(recipient_claim), 'address': payout},
                   'deadline': out_deadline}}
    quote_body = {'v': 2, 'type': 'quote', 'id': rfq['id'],
                  'request': r.sha256(r.jcs(rfq)).hex(), 'pubkey': xonly(identity),
                  'payment_hash': H, 'from_amount': '100250', 'to_amount': '100000',
                  'valid_until': 1790000120,
                  'in': {'lock': {'claim_key': compressed(provider_claim), 'address': btc_address},
                         'deadline': in_deadline, 'confirmations': 1},
                  'out': {'refund': compressed(provider_refund), 'deadline': out_deadline,
                          'confirmations': 2}}
    quote = signed(QUOTE_DOMAIN, quote_body, identity)

    conversation = r.nip44_conversation_key(client_nostr, xonly(identity))
    rfq_event = r.nostr_event(client_nostr, KIND_MESSAGE,
                              [['p', xonly(identity)], ['expiration', '1790000300']],
                              r.nip44_encrypt(r.jcs(rfq).decode(), conversation, bytes([0x22]) * 32),
                              1790000000)
    quote_event = r.nostr_event(identity, KIND_MESSAGE,
                                [['p', xonly(client_nostr)], ['e', rfq_event['id']],
                                 ['expiration', '1790000300']],
                                r.nip44_encrypt(r.jcs(quote).decode(), conversation, bytes([0x33]) * 32),
                                1790000001)

    rails = ['liquid:mainnet/' + USDT, 'ln:mainnet']
    rail_choice = {'rail': rails[0], 'refund': compressed(payer_refund)}
    lock_offer = {'rail': rails[0], 'amount': '100000', 'key': compressed(recipient_claim),
                  'address': payout, 'deadline': out_deadline, 'confirmations': 2}

    return {
        'metadata': {'draft': 2, 'test_keys_only': True,
                     'secrets': {'identity': '04' * 32, 'client_nostr': '05' * 32,
                                 'payer_refund': '02' * 32, 'provider_claim': '01' * 32,
                                 'recipient_claim': '07' * 32, 'provider_refund': '08' * 32},
                     'preimage': preimage.hex(), 'payment_hash': H, 'tips': tips},
        'locks': {'btc_in': {**btc_lock, 'address': btc_address, 'deadline': in_deadline},
                  'liquid_out': {**liquid_lock, 'deadline': out_deadline},
                  'ark_v2': ARK_V2},
        'deadline_check': {'margin_in_rail_blocks': 72, 'block_seconds': card_body['block_seconds'],
                           'in_remaining_seconds': 300 * 600, 'out_remaining_seconds': 1440 * 60,
                           'ok': 300 * 600 >= 1440 * 60 + 72 * 600},
        'card': {'value': card, 'digest': r.signed_digest(CARD_DOMAIN, card_body).hex(),
                 'nostr_event': card_event},
        'rfq': {'value': rfq, 'jcs': r.jcs(rfq).decode(), 'request_digest': quote_body['request']},
        'quote': {'value': quote, 'digest': r.signed_digest(QUOTE_DOMAIN, quote_body).hex()},
        'refusal': {'v': 2, 'type': 'refusal', 'id': rfq['id'], 'reason': 'amount_out_of_range'},
        'status': {'request': {'v': 2, 'type': 'status', 'id': rfq['id']},
                   'reply': {'v': 2, 'type': 'status', 'id': rfq['id'], 'state': 'in_locked',
                             'detail': btc_address}},
        'nostr_messages': {'conversation_key': conversation.hex(),
                           'rfq_event': rfq_event, 'quote_event': quote_event},
        'bolt12_tlvs': {'ssps_rails': {'type': TLV_RAILS, 'value': rails, 'record': tlv(TLV_RAILS, rails)},
                        'ssps_rail': {'type': TLV_RAIL, 'value': rail_choice,
                                      'record': tlv(TLV_RAIL, rail_choice)},
                        'ssps_lock': {'type': TLV_LOCK, 'value': lock_offer,
                                      'record': tlv(TLV_LOCK, lock_offer)}},
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('--write', action='store_true')
    group.add_argument('--check', action='store_true')
    args = parser.parse_args()
    text = json.dumps(generate(), indent=2, sort_keys=True) + '\n'
    if args.write:
        FIXTURE.parent.mkdir(exist_ok=True)
        FIXTURE.write_text(text)
        print(f'wrote {FIXTURE.relative_to(ROOT)}')
    elif FIXTURE.read_text() != text:
        sys.exit('test-vectors/draft2.json is stale: run tools/gen_vectors.py --write')
    else:
        print('draft2 fixture matches the generator')


if __name__ == '__main__':
    main()
