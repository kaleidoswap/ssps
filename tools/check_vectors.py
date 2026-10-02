#!/usr/bin/env python3
"""Check test-vectors/draft2.json against ssps.md, including negative cases.

Optional independent checks run when coincurve, rfc8785 and cryptography are
installed (tools/requirements-check.txt).
"""
import copy
import json
import re
import unittest
from pathlib import Path

import ssps_ref as r

ROOT = Path(__file__).resolve().parents[1]
FIX = json.loads((ROOT / 'test-vectors/draft2.json').read_text())
NIP44 = json.loads((ROOT / 'test-vectors/nip44-official-subset.json').read_text())
AMOUNT = re.compile(r'^(0|[1-9][0-9]*)$')
HEX32 = re.compile(r'^[0-9a-f]{64}$')
FIELDS = {
    'card': ({'v', 'type', 'pubkey', 'pairs', 'margins', 'block_seconds'},
             {'name', 'relays', 'http', 'sig'}),
    'rfq': ({'v', 'type', 'id', 'from', 'to', 'side', 'amount', 'in', 'out'}, {'payment_hash'}),
    'quote': ({'v', 'type', 'id', 'request', 'pubkey', 'payment_hash', 'from_amount',
               'to_amount', 'valid_until', 'in', 'out', 'sig'}, set()),
    'refusal': ({'v', 'type', 'id', 'reason'}, set()),
    'status': ({'v', 'type', 'id'}, {'state', 'detail'}),
}
REASONS = {'unsupported_pair', 'amount_out_of_range', 'exposure_cap', 'deadline_too_short',
           'invalid_request', 'pricing_unavailable'}
STATES = {'quoted', 'in_locked', 'out_locked', 'claimed', 'refunded', 'expired', 'stuck'}


def validate(msg):
    required, optional = FIELDS[msg['type']]
    keys = set(msg)
    if msg['v'] != 2 or not required <= keys or keys - required - optional:
        raise ValueError('fields')
    for k in ('amount', 'from_amount', 'to_amount'):
        if k in msg and not AMOUNT.fullmatch(msg[k]): raise ValueError('amount encoding')
    if msg['type'] == 'refusal' and msg['reason'] not in REASONS: raise ValueError('reason')
    if msg['type'] == 'status' and msg.get('state', 'quoted') not in STATES: raise ValueError('state')
    if 'id' in msg and not HEX32.fullmatch(msg['id']): raise ValueError('id')


def unsigned(msg): return {k: v for k, v in msg.items() if k != 'sig'}


def verify_signed(domain, msg, pub_hex):
    digest = r.signed_digest(domain, unsigned(msg))
    if not r.schnorr_verify(digest, bytes.fromhex(pub_hex), bytes.fromhex(msg['sig'])):
        raise ValueError('signature')


def verify_quote(rfq, quote, provider):
    validate(rfq); validate(quote)
    if quote['pubkey'] != provider: raise ValueError('not the selected provider')
    verify_signed(b'SSPS/quote/v2:', quote, provider)
    if quote['request'] != r.sha256(r.jcs(rfq)).hex() or quote['id'] != rfq['id']:
        raise ValueError('quote does not bind this rfq')
    if rfq.get('payment_hash', quote['payment_hash']) != quote['payment_hash']:
        raise ValueError('payment hash')
    lock = r.htlc('btc', bytes.fromhex(quote['payment_hash']),
                  bytes.fromhex(quote['in']['lock']['claim_key']), bytes.fromhex(rfq['in']['refund']),
                  quote['in']['deadline'], publisher='claim')
    if r.bech32m('bc', 1, bytes.fromhex(lock['output_key'])) != quote['in']['lock']['address']:
        raise ValueError('incoming lock does not rebuild')
    if quote['out']['deadline'] != rfq['out']['deadline']: raise ValueError('outgoing deadline')


def deadline_ok(in_remaining, out_remaining, margin_seconds):
    return in_remaining >= out_remaining + margin_seconds


def parse_tlv(record_hex):
    raw = bytes.fromhex(record_hex)
    t, i = r.read_bigsize(raw, 0)
    length, i = r.read_bigsize(raw, i)
    if len(raw) != i + length: raise ValueError('length')
    value = json.loads(raw[i:])
    if r.jcs(value) != raw[i:]: raise ValueError('not JCS')
    return t, value


class Vectors(unittest.TestCase):
    rfq, quote, card = FIX['rfq']['value'], FIX['quote']['value'], FIX['card']['value']
    provider = FIX['card']['value']['pubkey']

    def test_messages_validate(self):
        for m in (self.card, self.rfq, self.quote, FIX['refusal'],
                  FIX['status']['request'], FIX['status']['reply']):
            validate(m)

    def test_card_signature_and_event(self):
        verify_signed(b'SSPS/card/v2:', self.card, self.provider)
        ev = FIX['card']['nostr_event']
        self.assertTrue(r.nostr_verify(ev))
        self.assertEqual((ev['kind'], ev['pubkey']), (38384, self.provider))
        self.assertEqual(ev['content'], r.jcs(unsigned(self.card)).decode())
        tags = dict(ev['tags'])
        self.assertEqual(tags['d'], 'ssps')
        self.assertGreater(int(tags['expiration']), ev['created_at'])

    def test_quote_binds_rfq_and_rebuilds_lock(self):
        verify_quote(self.rfq, self.quote, self.provider)
        self.assertEqual(self.quote['request'], FIX['rfq']['request_digest'])

    def test_outgoing_lock_rebuilds_for_recipient(self):
        lock = r.htlc('liquid', bytes.fromhex(self.quote['payment_hash']),
                      bytes.fromhex(self.rfq['out']['claim']['key']),
                      bytes.fromhex(self.quote['out']['refund']), self.quote['out']['deadline'],
                      publisher='refund')
        self.assertEqual(lock['output_key'], FIX['locks']['liquid_out']['output_key'])
        self.assertEqual(lock['leaf_version'], 0xc4)

    def test_preimage_opens_claim_leaf(self):
        leaf = bytes.fromhex(FIX['locks']['btc_in']['claim_leaf'])
        preimage = bytes.fromhex(FIX['metadata']['preimage'])
        self.assertEqual(leaf[6:26], r.rmd160(r.sha256(preimage)))

    def test_ark_v2_claim_leaf(self):
        ark = FIX['locks']['ark_v2']
        leaf = (bytes.fromhex('82012088a914') + bytes.fromhex(ark['preimage_hash160'])
                + bytes.fromhex('876920') + bytes.fromhex(ark['receiver'])
                + bytes.fromhex('ad20') + bytes.fromhex(ark['server']) + bytes.fromhex('ac'))
        self.assertEqual(leaf.hex(), ark['claim_leaf'])
        self.assertEqual(leaf[:4], bytes.fromhex('82012088'), 'ScriptV2 checks the preimage size')
        self.assertTrue(all(v % 512 == 0 for k, v in ark['timeouts'].items() if k != 'refund'))

    def test_deadline_ordering(self):
        d = FIX['deadline_check']
        margin = d['margin_in_rail_blocks'] * d['block_seconds']['btc']
        self.assertTrue(deadline_ok(d['in_remaining_seconds'], d['out_remaining_seconds'], margin))
        self.assertFalse(deadline_ok(d['out_remaining_seconds'], d['in_remaining_seconds'], margin))

    def test_nostr_messages_decrypt_both_ways(self):
        m = FIX['nostr_messages']
        secrets = FIX['metadata']['secrets']
        client = r.nip44_conversation_key(int(secrets['client_nostr'], 16), self.provider)
        provider = r.nip44_conversation_key(int(secrets['identity'], 16), m['rfq_event']['pubkey'])
        self.assertEqual(client, provider)
        self.assertEqual(client.hex(), m['conversation_key'])
        for ev, body in ((m['rfq_event'], self.rfq), (m['quote_event'], self.quote)):
            self.assertTrue(r.nostr_verify(ev))
            self.assertEqual(ev['kind'], 28384)
            self.assertEqual(r.nip44_decrypt(ev['content'], client), r.jcs(body).decode())
        self.assertIn(['e', m['rfq_event']['id']], m['quote_event']['tags'])
        self.assertIn(['p', self.provider], m['rfq_event']['tags'])

    def test_bolt12_tlvs(self):
        ranges = {'ssps_rails': (1000000000, 1999999999), 'ssps_rail': (2000000000, 2999999999),
                  'ssps_lock': (3000000000, 3999999999)}
        for name, v in FIX['bolt12_tlvs'].items():
            t, value = parse_tlv(v['record'])
            lo, hi = ranges[name]
            self.assertTrue(lo <= t <= hi and t % 2 == 1, name)
            self.assertEqual((t, value), (v['type'], v['value']))
        lock = FIX['bolt12_tlvs']['ssps_lock']['value']
        self.assertIn(lock['rail'], FIX['bolt12_tlvs']['ssps_rails']['value'])

    def test_nip44_official_vectors(self):
        for v in NIP44['conversation_key']:
            self.assertEqual(r.nip44_conversation_key(int(v['sec1'], 16), v['pub2']).hex(),
                             v['conversation_key'])
        for v in NIP44['encrypt_decrypt']:
            ck = bytes.fromhex(v['conversation_key'])
            self.assertEqual(r.nip44_encrypt(v['plaintext'], ck, bytes.fromhex(v['nonce'])), v['payload'])
        for v in NIP44['invalid_decrypt']:
            with self.assertRaises(Exception, msg=v['note']):
                r.nip44_decrypt(v['payload'], bytes.fromhex(v['conversation_key']))


class Negative(unittest.TestCase):
    rfq, quote = FIX['rfq']['value'], FIX['quote']['value']
    provider = FIX['card']['value']['pubkey']

    def rejects(self, rfq=None, quote=None, provider=None):
        with self.assertRaises(ValueError):
            verify_quote(rfq or self.rfq, quote or self.quote, provider or self.provider)

    def test_tampered_quote_amount(self):
        q = copy.deepcopy(self.quote); q['to_amount'] = '100001'; self.rejects(quote=q)

    def test_rfq_destination_changed(self):
        f = copy.deepcopy(self.rfq); f['out']['claim']['address'] = 'ex1qchanged'; self.rejects(rfq=f)

    def test_other_provider_key(self):
        self.rejects(provider='00' * 31 + '01')

    def test_wrong_claim_key_in_lock(self):
        q = copy.deepcopy(self.quote); q['in']['lock']['claim_key'] = self.rfq['in']['refund']
        self.rejects(quote=q)

    def test_unknown_field(self):
        f = copy.deepcopy(self.rfq); f['note'] = 'x'
        with self.assertRaises(ValueError): validate(f)

    def test_amount_encoding(self):
        for bad in ('0100', '-1', '1.5', ''):
            f = copy.deepcopy(self.rfq); f['amount'] = bad
            with self.assertRaises(ValueError, msg=bad): validate(f)

    def test_unknown_refusal_reason(self):
        with self.assertRaises(ValueError): validate({**FIX['refusal'], 'reason': 'busy'})

    def test_tampered_nostr_event(self):
        ev = copy.deepcopy(FIX['nostr_messages']['rfq_event']); ev['tags'][0][1] = '00' * 32
        self.assertFalse(r.nostr_verify(ev))


class Independent(unittest.TestCase):
    def test_libraries(self):
        try:
            import coincurve, rfc8785
            from cryptography.hazmat.primitives.ciphers import Cipher, algorithms
        except ImportError:
            self.skipTest('optional libraries not installed')
        quote = FIX['quote']['value']
        self.assertEqual(rfc8785.dumps(unsigned(quote)), r.jcs(unsigned(quote)))
        digest = r.signed_digest(b'SSPS/quote/v2:', unsigned(quote))
        self.assertTrue(coincurve.PublicKeyXOnly(bytes.fromhex(quote['pubkey'])).verify(
            bytes.fromhex(quote['sig']), digest))
        key, nonce, data = b'\x01' * 32, b'\x02' * 12, b'ssps' * 40
        enc = Cipher(algorithms.ChaCha20(key, b'\x00' * 4 + nonce), mode=None).encryptor()
        self.assertEqual(enc.update(data), r.chacha20(key, nonce, data))


if __name__ == '__main__':
    unittest.main(verbosity=2)
