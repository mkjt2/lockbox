import argparse
import jwt
import time

from lockbox import JWT_ISSUER_LOCKBOX


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--service-name", required=True)
    parser.add_argument("--duration", default=3600, type=int)
    parser.add_argument("--signing-key-file", required=True)
    parser.add_argument("--audience", required=True)
    args = parser.parse_args()

    with open(args.signing_key_file) as f:
        signing_key = f.read()

    print(
        generate_service_token(
            args.audience, args.service_name, args.duration, signing_key
        )
    )


def generate_service_token(
    audience: str, service_name: str, duration: int, signing_key: str
) -> str:
    return jwt.encode(
        {
            "iss": JWT_ISSUER_LOCKBOX,
            "exp": int(time.time() + duration),
            "service_name": service_name,
            "aud": audience,
        },
        signing_key,
        algorithm="HS256",
    )


if __name__ == "__main__":
    main()
