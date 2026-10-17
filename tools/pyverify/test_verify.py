import contextlib
import io
from pathlib import Path
import re
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

    def test_exported_authenticator_hashes_encoded_handshake_messages(self):
        draft = (Path(__file__).resolve().parents[2]
                 / "draft-sullivan-tls-xof-schedule.md").read_text()
        certificate_der = bytes.fromhex(re.search(
            r"EA test certificate \(DER\):\n((?:  [0-9a-f]+\n)+)",
            draft)[1])

        class RecordingProfile(verify.Profile):
            def th(self, message):
                hashed.append(message)
                return super().th(message)

        for profile in (verify.SHAKE256, verify.TURBOSHAKE256):
            with self.subTest(profile=profile.name):
                hashed = []
                recording = RecordingProfile(profile.name, profile.rounds,
                                             profile.use_hashlib)
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    verify.emit(recording)
                values = {
                    name: bytes.fromhex(value.strip())
                    for line in output.getvalue().splitlines()
                    if ":" in line
                    for name, value in [line.split(":", 1)]
                }
                hc = values["Handshake Context"]
                transcripts = [message[len(hc):] for message in hashed
                               if message.startswith(hc)]
                self.assertEqual(len(transcripts), 3)
                certificate, complete, empty = transcripts
                self.assertEqual(certificate[0], 11)
                self.assertEqual(int.from_bytes(certificate[1:4], "big"),
                                 len(certificate) - 4)
                context_end = 5 + certificate[4]
                self.assertEqual(certificate[5:context_end], b"\xa5")
                certificate_list = certificate[context_end + 3:]
                self.assertEqual(int.from_bytes(
                    certificate[context_end:context_end + 3], "big"),
                    len(certificate_list))
                der_length = int.from_bytes(certificate_list[:3], "big")
                self.assertEqual(certificate_list[3:3 + der_length],
                                 certificate_der)
                self.assertEqual(certificate_list[3 + der_length:], b"\0\0")
                self.assertTrue(complete.startswith(certificate))
                cv = complete[len(certificate):]
                self.assertEqual(cv[0], 15)
                self.assertEqual(int.from_bytes(cv[1:4], "big"), len(cv) - 4)
                self.assertEqual(cv[4:6], b"\x08\x07")
                self.assertEqual(int.from_bytes(cv[6:8], "big"), len(cv) - 8)
                self.assertEqual(cv[8:], bytes(64))
                self.assertEqual(empty, b"CertificateRequest"
                                 + bytes.fromhex("0b00000400000000"))
                self.assertEqual(values["TranscriptHash(HC || Certificate)"],
                                 profile.th(hc + certificate))
                self.assertEqual(values["Finished"], profile.mac(
                    values["Finished MAC Key"], profile.th(hc + complete),
                    verify.FLEN))


if __name__ == "__main__":
    unittest.main()
