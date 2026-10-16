import contextlib
import io
import unittest

import verify


# Pin explicit-frame results for both exporter stages and the raw external
# PSK binder, using the appendix fixtures in both profiles.
EXPECTED = {
    "TLS13_SHAKE256": {
        "exporter_label_secret": (
            "55b6277322fba611e66f608cc5c937b961f67868b59e8bc9f29581036e713690"
            "191fbbc656bc9abb53c3e75e13c7f2ddbaf4861bc7d27f10e5027810ec52a15c"
        ),
        "TLS-Exporter (32 octets)": (
            "f09c0f94a9261fb7ab02171f6e9448b47ce6f34e1950b15d3b2be17072620e63"
        ),
        "early_exporter_label_secret": (
            "fe7331c50be5b4b0ead154504e29e23357b283c1b29ee5c6f7779849f3c64f43"
            "3897018a4387f32440173aa2abd92de582ff95e4845e4ea0426f096157b83cf2"
        ),
        "early exporter (32 octets)": (
            "387d4172845fdab9b930d42b49ef82c0ed1758b69c99bed13f98eb091d9be190"
        ),
        "binder_key (ebk)": (
            "c8d18ca9fcc3276e8770b009b077f18a01b6f7442bb3e7afc5b156e6b3cd62bb"
            "e27e0283a69b2c64afcc811779051152d256427104d4c45564d741ed1a7686f1"
        ),
        "finished_key (external binder)": (
            "b31ef8da3c20817cc5b2dc06336671f117edafb5fc276b8d58a3d731e2ae817c"
            "b548150d6591060e4a3c263d9311bee081399b996d96be0c4880e863e56cbb16"
        ),
        "external binder verify_data": (
            "b44c1f511878261b1a2d09379a02ea96674b84ea3e256fe5560c0c86485131c2"
            "bb28fc7140adbd224be3d94f1c33d1915eab87cc23bacaf7e3d6b0c0f851040c"
        ),
    },
    "TLS13_TURBOSHAKE256": {
        "exporter_label_secret": (
            "53399e963826534e9bce0d4470ef56b1c98b5dcc92f6aad5d96e78356829b9aa"
            "51367c6ff1052179d00c42b0ca2c89f47c513fbd24282de25e2c3cabe4693161"
        ),
        "TLS-Exporter (32 octets)": (
            "1d634e39add2a3dac37c86b3756510bcf44cd5994128e47aac63ac7715aa3b98"
        ),
        "early_exporter_label_secret": (
            "9e66133a2c09106cf4e242f7e25e024c3916ba1b9fd2a46dfa34b98f661beaeb"
            "c1f32069641bc5608bf99438c9358da2cd2fda417f6c6b24214714954bc3c732"
        ),
        "early exporter (32 octets)": (
            "55493ef2c04354319cf64592acfd1aa5c344b232a56aa59b6968c0e07b3695e5"
        ),
        "binder_key (ebk)": (
            "d6f420946dd61281511d1b84d37a92411f5750b821fac84a3342b3f46afcfec2"
            "065325d9b53fdfe4e536f276a232b5a4207ed052a88ca786513ce92b38325f36"
        ),
        "finished_key (external binder)": (
            "95f1a8a6ad0c8423a8deb990c3d95ce710eecf06f49850eb71eb40e9417be4ab"
            "aabe557019e508f26a72bce45147d19e2d2d4ba0aa072bdee44cf51d736ae087"
        ),
        "external binder verify_data": (
            "b36ee253e86760f99bd8f4a615aabf88b65133e9947182729a21414193f7957d"
            "7f106e0df8a1261fb03c496c049773054e35f3023200b50ef5ea05820f9cf5fb"
        ),
    },
}


class ExporterAndBinderTests(unittest.TestCase):
    def test_two_stage_exporter_and_external_binder_vectors(self):
        for profile in (verify.SHAKE256, verify.TURBOSHAKE256):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                verify.emit(profile)
            values = {
                name: value.strip()
                for line in output.getvalue().splitlines()
                if ":" in line
                for name, value in [line.split(":", 1)]
            }
            for name, expected in EXPECTED[profile.name].items():
                with self.subTest(profile=profile.name, name=name):
                    self.assertEqual(values.get(name), expected)


if __name__ == "__main__":
    unittest.main()
