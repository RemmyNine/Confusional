import json
import unittest

import jwt_confusion as jwtc


def make_token(header=None, payload=None):
    header = header or {"typ": "JWT", "alg": "RS256"}
    payload = payload or {"sub": "123", "role": "user", "exp": 1000}
    return f"{jwtc.encode_json_part(header)}.{jwtc.encode_json_part(payload)}.signature"


class JwtConfusionTests(unittest.TestCase):
    def test_parse_jwt_returns_header_payload_and_signature(self):
        token = make_token()

        header, payload, signature = jwtc.parse_jwt(token)

        self.assertEqual(header["alg"], "RS256")
        self.assertEqual(payload["sub"], "123")
        self.assertEqual(signature, "signature")

    def test_payload_modifications_parse_types_and_time_offsets(self):
        payload = {"exp": 1000}

        modified = jwtc.apply_modifications(
            payload,
            ["admin=true", "tries=3", 'scope=["read","write"]', "exp=+60"],
            allow_time_offsets=True,
        )

        self.assertTrue(modified["admin"])
        self.assertEqual(modified["tries"], 3)
        self.assertEqual(modified["scope"], ["read", "write"])
        self.assertEqual(modified["exp"], 1060)

    def test_hmac_attack_changes_algorithm_and_signs(self):
        header = {"typ": "JWT", "alg": "RS256"}
        payload = {"role": "admin"}

        token = jwtc.sign_hmac(header, payload, b"public-key-material", "HS384")
        parsed_header, parsed_payload, signature = jwtc.parse_jwt(token)

        self.assertEqual(parsed_header["alg"], "HS384")
        self.assertEqual(parsed_payload["role"], "admin")
        self.assertTrue(signature)

    def test_none_attack_returns_empty_signature(self):
        token = jwtc.none_attack({"alg": "RS256"}, {"sub": "123"})
        header, payload, signature = jwtc.parse_jwt(token)

        self.assertEqual(header["alg"], "none")
        self.assertEqual(payload["sub"], "123")
        self.assertEqual(signature, "")

    def test_kid_attack_sets_kid_without_requiring_key(self):
        token = jwtc.kid_attack({"alg": "RS256"}, {"sub": "123"}, "../../key")
        header, _payload, signature = jwtc.parse_jwt(token)

        self.assertEqual(header["kid"], "../../key")
        self.assertEqual(signature, "")

    def test_print_decoded_mode_accepts_keyless_cli(self):
        token = make_token()
        args = jwtc.parse_args(["--token", token, "--print-decoded"])

        self.assertEqual(args.token, token)
        self.assertTrue(args.print_decoded)


if __name__ == "__main__":
    unittest.main()
