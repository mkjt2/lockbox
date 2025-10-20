import argparse
import jwt
import time

from lockbox import JWT_ISSUER_LOCKBOX


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Generate an admin token for Lockbox administrative operations"
    )
    parser.add_argument(
        "--duration",
        default=3600,
        type=int,
        help="Token validity duration in seconds (default: 3600)",
    )
    parser.add_argument(
        "--signing-key-file", required=True, help="Path to the signing key file"
    )
    args = parser.parse_args()

    with open(args.signing_key_file) as f:
        signing_key = f.read()

    token = generate_admin_token(args.duration, signing_key)
    print(token)


def generate_admin_token(duration: int, signing_key: str) -> str:
    """Generate an admin token for Lockbox administrative operations.

    Args:
        duration: Token validity duration in seconds
        signing_key: Secret key used to sign the token

    Returns:
        JWT token string
    """
    return jwt.encode(
        {
            "iss": JWT_ISSUER_LOCKBOX,
            "exp": int(time.time() + duration),
            "admin": True,
        },
        signing_key,
        algorithm="HS256",
    )


if __name__ == "__main__":
    main()
