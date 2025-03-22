## Description
This Python script, jwt_confusion.py, is a command-line tool designed to demonstrate and exploit JWT (JSON Web Token) algorithm confusion vulnerabilities. It can generate forged JWTs to test the security of systems that rely on JWT authentication. This tool is for educational and authorized security testing purposes only. Improper use could lead to serious consequences.

![image](https://github.com/user-attachments/assets/ac470f1f-a263-4f1a-b710-3ecb790101c3)


#### The script implements the following attack vectors:
`HMAC Algorithm Switching`: Attempts to use an RSA public key as the secret key for HMAC (HS256, HS384, HS512) algorithms.
`'none'` Algorithm Attack: Sets the JWT algorithm to 'none', effectively bypassing signature verification.
`Key ID (kid) Manipulation`: Modifies the kid header parameter to point to an attacker-controlled key or a system file.
`JWK Header Injection`: Injects a crafted JWK (JSON Web Key) into the JWT header.
`Embedded JWK Attack`: Embeds a JWK directly into the token header.
`X.509 URL (x5u) Attack`: Adds an X.509 certificate URL.
`Key Confusion Attack`: Uses a symmetric key for asymmetric verification.

### Features
`JWT Parsing`: Parses JWT tokens into their header, payload, and signature components.
`Payload Modification`: Allows modification of JWT payload claims. Supports setting string, boolean, numeric, null, and JSON values. Also supports relative modification of exp, nbf, and iat claims by adding or subtracting seconds.
`Header Modification`: Allows modification of JWT header parameters.
`Key Handling`: Reads keys from PEM files. Can also generate RSA key pairs for certain attacks.
`Algorithm Specification`: Allows the user to specify the algorithm to use for forged tokens (e.g., HS256, HS384, HS512).
`Output Options`: Prints the forged JWT to standard output or writes it to a file.
`Verbose Output`: Displays detailed information about the original and forged tokens.
`Token Input from File`: Reads the JWT token from a file.
`Print Decoded Token`: Prints the decoded header and payload of the original token.

### Dependencies
Python 3.6 or higher
base64
json
hmac
hashlib
argparse
sys
os
re
typing
Optional:
cryptography (for RSA key generation and some attacks). Install with pip install cryptography. The script will function without it, but some advanced attacks will be unavailable.

### Installation
Clone this repository:
```
git clone https://github.com/RemmyNine/Confusional
cd Confusional
```

(Optional) Install the cryptography library:
pip install cryptography


Usage
python3 jwt_confusion.py --token <JWT_TOKEN> --key <KEY_FILE> [OPTIONS]


Arguments
`--token, -t`: The JWT token to attack. Required unless --file is used.
`--key, -k`: The key file (in PEM format) for signing or verification. Required for most attack types (except none and kid without key).
`--algorithm, -a`: The algorithm to use for the forged token (default: HS256). Choices depend on the attack.
`--attack`: The type of attack to perform (default: hmac). Choices are:
`hmac`: HMAC algorithm switching.
`none`: 'none' algorithm attack.
`kid`: Key ID (kid) manipulation.
`jwk-injection`: JWK header injection.
`embedded-jwk`: Embed JWK into the header
`x5u`: X.509 URL attack
`key-confusion`: Key confusion attack
`--modify, -m`: Modify payload fields. Format: key=value. Use +/-N for exp, nbf, and iat to adjust by N seconds (e.g., exp=+3600 to add an hour to the expiration). Can be used multiple times.
`--kid-value`: The value to use for the kid parameter in the kid attack (default: ../../../../../dev/null).
`--jwk-url`: The URL to use for the x5u or jku parameter (default: https://attacker.com/jwk.json).
`--gen-key`: Generate a new RSA key pair for embedded-jwk or jwk-injection attacks. If used, the --key argument is not needed.
`--raw-token`: Print only the forged JWT token, without any additional output.
`--verbose, -v`: Enable verbose output, showing details of the original and forged tokens.
`--print-decoded, -p`: Print decoded header and payload of the original token and exit.
`--header`: Add or modify header fields in key=value format.
`--file, -f`: Read the JWT token from a file instead of the command line.
`--output, -o`: Write the forged token to a file instead of printing to standard output.

### Examples
```
python3 jwt_confusion.py --token eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9... --key public.pem
python3 jwt_confusion.py --token eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9... --key public.pem --modify login=admin
python3 jwt_confusion.py --token eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9... --key public.pem --algorithm HS384
python3 jwt_confusion.py --token eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9... --attack none
python3 jwt_confusion.py --token eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9... --attack kid --kid-value ../../../../../dev/null
python3 jwt_confusion.py --token eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9... --attack embedded-jwk --gen-key
python3 jwt_confusion.py --token eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9... --modify exp=+3600 -m admin=true
python3 jwt_confusion.py --file token.txt --key private.key --attack hmac -a HS512 -m user=root
python3 jwt_confusion.py --token <token> --attack jwk-injection --jwk-url https://example.com/my_jwk.json
python3 jwt_confusion.py --token <token> --attack x5u --jwk-url https://example.com/cert.cert
python3 jwt_confusion.py --token <token> --attack key-confusion --key symmetric.key
python3 jwt_confusion.py --token <token> --print-decoded
python3 jwt_confusion.py --token <token> --header typ=JWT -m role=admin
```

### Exploitation Stage
- Make sure you already made your base64url JWT with JWT.io or any other website. This tool only perform algorithm confusion attack
