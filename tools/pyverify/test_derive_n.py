"""Independent checks of the draft's multi-output encoding contract."""
import unittest
from collections import Counter
from unittest.mock import patch
import verify as v


class DeriveNTests(unittest.TestCase):
    def test_handshake_counts(self):
        """Execute the Invocation Count / Permutation-Counting Method workload.

        PSK handshake, 32-byte shared secret, accepted early data; omit
        transcript hashing, tickets, updates and exporter requests. The
        generation-zero record DeriveN calls still produce their successors.
        """
        class MeasuredProfile(v.Profile):
            def __init__(self, rounds):
                # Use the independently verified sponge so permutation calls
                # are observable for SHAKE as well as TurboSHAKE.
                super().__init__("measured", rounds, False)
                self.calls = []

            def df(self, data, count):
                self.calls.append((data, count))
                return super().df(data, count)

        for rounds in (24, 12):
            for nk in (16, 32):
                with self.subTest(rounds=rounds, nk=nk):
                    p = MeasuredProfile(rounds)
                    # Distinct synthetic checkpoints, already hashed.
                    ch0, ch, sh, pre_sf, sf, cf = (
                        bytes([i]) * 64 for i in range(1, 7))
                    checkpoints = []

                    def stage_bundle(deck, labels, checkpoint):
                        prefix = v.absorb(deck, b"th__", checkpoint)
                        checkpoints.append(prefix)
                        return v.derive_n(p, deck, [(x, 64) for x in labels],
                                          b"th__", checkpoint)

                    with patch.object(v, "keccak_p", wraps=v.keccak_p) as perm:
                        e = v.absorb(v.init(), b"psk_", b"p" * 64)
                        binder, residue = v.derive_n(
                            p, e, [(b"rbk", 64), (b"drv", 64)])
                        binder_fin = v.derive(p, v.seeded(binder), b"fin")
                        p.mac(binder_fin, ch0, 64)
                        early, _ = stage_bundle(e, (b"cet", b"ees"), ch)
                        v.derive(p, v.seeded(early), b"key", l=nk + 12)

                        h = v.absorb(v.seeded(residue), b"shs_", b"s" * 32)
                        client_hs, server_hs = stage_bundle(h, (b"cht", b"sht"), sh)
                        for secret, checkpoint in ((server_hs, pre_sf), (client_hs, sf)):
                            fin, _ = v.derive_n(p, v.seeded(secret),
                                               [(b"fin", 64), (b"key", nk + 12)])
                            p.mac(fin, checkpoint, 64)
                        t, _ = v.ratchet(p, h)
                        client_ap, server_ap, _ = stage_bundle(
                            t, (b"cat", b"sat", b"exs"), sf)
                        checkpoints.append(v.absorb(t, b"th__", cf))
                        v.derive_secret(p, t, b"rss", cf)
                        for secret in (client_ap, server_ap):
                            v.derive_n(p, v.seeded(secret),
                                       [(b"upd", 64), (b"key", nk + 12)])

                    invocations = len(p.calls)
                    standalone = sum(len(data) // v.RATE + 1 +
                                     (count - 1) // v.RATE
                                     for data, count in p.calls)
                    self.assertEqual((invocations, standalone), (15, 23))
                    self.assertEqual(perm.call_count, standalone)
                    # All trunks are sub-rate. Each full checkpoint prefix
                    # feeds exactly one terminal call, so sharing saves zero.
                    self.assertLess(max(map(len, (e, h, t))), v.RATE)
                    prefix_cost = sum(len(x) // v.RATE for x in checkpoints)
                    terminal_cost = 0
                    for data, count in p.calls:
                        matches = [x for x in checkpoints if data.startswith(x)]
                        self.assertLessEqual(len(matches), 1)
                        consumed = len(matches[0]) // v.RATE if matches else 0
                        terminal_cost += (len(data) // v.RATE - consumed + 1 +
                                          (count - 1) // v.RATE)
                    for prefix in checkpoints:
                        self.assertEqual(sum(data.startswith(prefix)
                                             for data, _ in p.calls), 1)
                    self.assertEqual(prefix_cost + terminal_cost, standalone)
                    # Pin the call shapes, including the extra squeeze of
                    # the 192-byte application bundle and both lookaheads.
                    self.assertEqual(Counter((len(data), count) for data, count in p.calls),
                                     Counter({(120, 128): 1, (95, 64): 1,
                                              (167, 64): 4, (192, 128): 1,
                                              (95, nk + 12): 1, (232, 128): 1,
                                              (120, 64 + nk + 12): 4,
                                              (135, 64): 1, (207, 192): 1}))

    def test_exact_encoding(self):
        class Capture:
            def df(self, data, count):
                self.data = data
                self.count = count
                return bytes(range(count))
        p = Capture()
        first, second = v.derive_n(p, v.init(), [(b"fin", 64), (b"key", 28)])
        self.assertEqual((first, second), (bytes(range(64)), bytes(range(64, 92))))
        self.assertEqual(p.count, 92)
        self.assertEqual(p.data.hex(),
                         "0006746c7331332000046f75747300020002"
                         "000366696e00046f75745f00020040"
                         "00036b657900046f75745f0002001c")

    def test_partition_order_label_and_context(self):
        for p in (v.SHAKE256, v.TURBOSHAKE256):
            d = v.seeded(b"x" * 64)
            spec = [(b"fin", 64), (b"key", 28)]
            base = v.derive_n(p, d, spec)
            for alt in (spec[::-1], [(b"fin", 63), (b"key", 29)],
                        [(b"upd", 64), (b"key", 28)]):
                self.assertNotEqual(b"".join(base), b"".join(v.derive_n(p, d, alt)))
            self.assertEqual(base, v.derive_n(p, d, spec, b"ctx_", b""))
            self.assertNotEqual(base, v.derive_n(p, d, spec, b"ctx_", b"x"))
            self.assertNotEqual(base[0], v.derive(p, d, b"fin"))

    def test_invalid_descriptors_and_reserved_tag(self):
        for spec in ([], [(b"fin", 64)], [(b"fin", 1), (b"fin", 2)],
                     [(b"fin", 0), (b"key", 28)], [(b"fin", -1), (b"key", 28)],
                     [(b"fin", 65536), (b"key", 1)], [(b"fin", 65535), (b"key", 1)],
                     [(b"fin", 64), (b"iv_", 12)], [(b"fin", 64), (b"bad", 12)]):
            with self.assertRaises(ValueError):
                v.derive_n(v.SHAKE256, v.init(), spec)
        with self.assertRaises(ValueError):
            v.absorb(v.init(), b"outs", b"")

    def test_uint16_count_and_total_boundaries(self):
        with self.assertRaises(ValueError):
            v.derive_n(v.SHAKE256, v.init(), [(b"fin", 1)] * 65536)
        values = v.derive_n(v.SHAKE256, v.init(), [(b"fin", 65534), (b"key", 1)])
        self.assertEqual(tuple(map(len, values)), (65534, 1))

    def test_single_output_empty_context(self):
        for p in (v.SHAKE256, v.TURBOSHAKE256):
            d = v.seeded(b"s" * 64)
            absent = v.derive(p, d, b"fin", b"ctx_", None)
            self.assertEqual(absent, v.derive(p, d, b"fin", b"ctx_", b""))
            explicit = v.absorb(d, b"ctx_", b"")
            self.assertNotEqual(absent, v.derive(p, explicit, b"fin", b"ctx_", None))


if __name__ == "__main__":
    unittest.main()
