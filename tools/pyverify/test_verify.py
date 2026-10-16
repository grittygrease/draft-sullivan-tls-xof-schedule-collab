import contextlib
import io
import unittest

import verify


class ExpansionTests(unittest.TestCase):
    def test_empty_context_is_omitted(self):
        for profile in (verify.SHAKE256, verify.TURBOSHAKE256):
            with self.subTest(profile=profile.name):
                seed = bytes(range(verify.SECRET_LEN))
                missing = verify.expand(profile, seed, b"rsp", None,
                                        verify.SECRET_LEN)
                empty = verify.expand(profile, seed, b"rsp", b"",
                                      verify.SECRET_LEN)
                self.assertEqual(empty, missing)
                self.assertNotEqual(
                    verify.expand(profile, seed, b"rsp", b"\0",
                                  verify.SECRET_LEN), missing)

    def test_server_finished_uses_pre_finished_checkpoint(self):
        for profile in (verify.SHAKE256, verify.TURBOSHAKE256):
            with self.subTest(profile=profile.name):
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    verify.emit(profile)
                values = {
                    name: bytes.fromhex(value.strip())
                    for line in output.getvalue().splitlines()
                    if ":" in line
                    for name, value in [line.split(":", 1)]
                }
                checkpoint = profile.th(b"ClientHello..before server Finished")
                expected = profile.mac(values["finished_key (server)"],
                                       checkpoint, verify.FLEN)
                self.assertEqual(values["server verify_data"], expected)
                self.assertEqual(values["TH_PRE_SF"], checkpoint)


if __name__ == "__main__":
    unittest.main()
