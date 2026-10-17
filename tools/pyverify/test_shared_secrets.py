import contextlib
import io
import unittest

import verify


EXPECTED = {
    "TLS13_SHAKE256": {
        "c_hs_traffic (PSK-only)": (
            "8002d2845fb5f1b98da952a729e2d1a455802417e6b8b49385c418cd148fb127"
            "fd4dd559b94e308586b0090bb74c2b9163e36f740a1cf53383c6949c91724950"
        ),
        "s_hs_traffic (PSK-only)": (
            "577e01db7d08e1d8356df00beb13f51795864eb02e213c9a58acab3a3bb65923"
            "59df8a8cd0b3cff1e8c140943f4106db60547853d79791a57a348f3f088e4e56"
        ),
        "c_ap_traffic (PSK-only)": (
            "35af7a37f2f35c50428c35486dd8776c1fcb0cb834f77ce8e690b5250754380f"
            "aa40ac0e491b2741ffa2b4b7c2fd132a0a2ea56b1b48bda90b9eb4aa2ed813cc"
        ),
        "c_hs_traffic (hybrid)": (
            "4e725e4687624689defb14a5786f2fc4e76309c28adaa7a5fc266cb1064ab53d"
            "207c7610d43912147b58e619427870be0c5610f42bdd6b1416fa291a330f76af"
        ),
        "s_hs_traffic (hybrid)": (
            "ecd094adf9c38c21fca2ede44fd1abf9f0a806dcf556373d54a58ace6cde91c8"
            "4ac56e31fa9a2fd1ab1c9f9195935a58134d127d60a0127222f6a439a865b6e7"
        ),
        "c_ap_traffic (hybrid)": (
            "9eb5243783dfd08e82d91a5aca6c843a8c6467d852d269d668cbf9fc774438fd"
            "08560544ba42f5d8935fb0cacb450a189d62f556a0cf25c7752082c56a745171"
        ),
    },
    "TLS13_TURBOSHAKE256": {
        "c_hs_traffic (PSK-only)": (
            "6580a4de683ec8c089dac82552e74aa074d89ba694108a6fb2d8bcde0a8f1bb5"
            "042080fd9295ba0e6f0e5840c76f391441b09fdc446fc4ece571b95737ea0144"
        ),
        "s_hs_traffic (PSK-only)": (
            "bcc778a1f97fb32f4c0668ce707bad0eaa989a81ad502dc75095c2364db5ce19"
            "2aab04dc21ec3948d3c76bc9357fe1e17b03ee6db2b6421bbbde1da812ae7760"
        ),
        "c_ap_traffic (PSK-only)": (
            "77463327a3609cfe97ee9c7523c8b071341450fba775a70a7b40bc1a947f064d"
            "add30d198dd1d8bd7f53d29a3b5bd994d44bd065b51e728dcf1a7be5acd66c7d"
        ),
        "c_hs_traffic (hybrid)": (
            "2b199e54700a4992cc8df58b138564777fa58cfdb09a3cf6f474f78e81ac90e3"
            "65a64b68ed75e9818dfe48b43b7b76a0b2ee7e2a596b6027ef960dddddcc63b8"
        ),
        "s_hs_traffic (hybrid)": (
            "ac1e433ba3fd73cb6054ddb95bc43e68a6f98346f5ed157033a38dfa07530c9f"
            "7f5163876821a5d73599f13ea12a74a1c53bb3800f845b7eae61eed000d7f237"
        ),
        "c_ap_traffic (hybrid)": (
            "2c3d56389ed9582a11b61d36ffeee3f78feb25fcd576fa66166314bb465534d4"
            "e0beb9c1685e60cab2084b7db9ab0f77d30ec48a8aa8d6efa90af6250157a2b8"
        ),
    },
}


class SharedSecretFixtureTests(unittest.TestCase):
    def test_psk_only_and_hybrid_vectors(self):
        for p in (verify.SHAKE256, verify.TURBOSHAKE256):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                verify.emit(p)
            values = {
                name: value.strip()
                for line in output.getvalue().splitlines() if ":" in line
                for name, value in [line.split(":", 1)]
            }
            self.assertTrue(set(EXPECTED[p.name]) <= values.keys(),
                            "missing PSK-only or hybrid fixture outputs")
            for name, expected in EXPECTED[p.name].items():
                with self.subTest(profile=p.name, name=name):
                    self.assertEqual(values.get(name), expected)

            # An empty framed input, concatenation, and reversed components
            # are distinct from the documented omission and ordered absorbs.
            a, b = p.th(b"hybrid component 1"), p.th(b"hybrid component 2")
            for fixture, components in [
                    ("PSK-only", [b""]),
                    ("hybrid", [a + b]),
                    ("hybrid", [b, a])]:
                e = verify.absorb(verify.init(), b"psk_", p.th(b"psk"))
                _, residue = verify.derive_n(
                    p, e, [(b"rbk", 64), (b"drv", 64)])
                h = verify.seeded(residue)
                for component in components:
                    h = verify.absorb(h, b"shs_", component)
                t, _ = verify.ratchet(p, h)
                c_hs, s_hs = verify.derive_n(
                    p, h, [(b"cht", 64), (b"sht", 64)], b"th__",
                    p.th(b"ClientHello..ServerHello"))
                c_ap, _, _ = verify.derive_n(
                    p, t, [(b"cat", 64), (b"sat", 64), (b"exs", 64)],
                    b"th__", p.th(b"ClientHello..server Finished"))
                different = {"c_hs_traffic": c_hs,
                             "s_hs_traffic": s_hs,
                             "c_ap_traffic": c_ap}
                for name, value in different.items():
                    with self.subTest(profile=p.name, fixture=fixture,
                                      components=components, name=name):
                        self.assertNotEqual(values[f"{name} ({fixture})"],
                                            value.hex())


if __name__ == "__main__":
    unittest.main()
