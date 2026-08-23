def main() -> None:
    import argparse
    import getpass
    import hashlib
    import math

    from typing import Literal
    from argon2.low_level import Type, hash_secret_raw

    VERSION = "v26.0.0-beta"
    TAG = "KgU00b"

    Preset = Literal[
        "alphanumeric",
        "base64",
        "base64url",
        "full",
    ]

    PRESETS: dict[Preset, str] = {
        "alphanumeric": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
        "base64": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
        "base64url": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_",
        "full": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%^&*()-_=+",
    }

    def encode_password(data: bytes, alphabet: str, length: int) -> str:
        """Encode deterministic bytes into a password using rejection sampling."""

        limit = 256 - (256 % len(alphabet))

        result = []

        for byte in data:
            if byte >= limit:
                continue

            result.append(alphabet[byte % len(alphabet)])

            if len(result) >= length:
                return "".join(result)

        raise RuntimeError("Argon2id did not produce enough usable output bytes.")

    print(f"= kagipass {VERSION} =")

    # ========== argument parsing thingy ========== #

    parser = argparse.ArgumentParser(
        description="Generate deterministic passwords using the kagipass algorithm."
    )

    parser.add_argument(
        "-S",
        "--service",
        required=True,
        help="Service name to generate the password for.",
    )

    parser.add_argument(
        "-L",
        "--length",
        type=int,
        default=50,
        help="Resulting length of the generated password. Defaults to 50.",
    )

    parser.add_argument(
        "-T",
        "--time-cost",
        type=int,
        default=3,
        help="Argon2id time cost. Defaults to 3.",
    )

    parser.add_argument(
        "-M",
        "--memory-cost",
        type=int,
        default=65_536,
        help="Argon2id memory cost in KiB. Defaults to 65,536 (64 MiB).",
    )

    parser.add_argument(
        "-P",
        "--parallelism",
        type=int,
        default=4,
        help="Argon2id parallelism. Defaults to 4.",
    )

    parser.add_argument(
        "--preset",
        choices=list(PRESETS),
        default="full",
        help="Character preset used for password generation. Defaults to full.",
    )

    parser.add_argument(
        "-N",
        "--no-version-tag",
        action="store_true",
        help=(
            "Do not include the kagipass version tag in the generated password. "
            "This is usually not recommended."
        ),
    )

    args = parser.parse_args()

    # ========== argument validation ========== #

    if args.length <= 0:
        parser.error("length must be greater than 0")

    if args.length <= (len(TAG) if not args.no_version_tag else 0):
        parser.error("length is too small")

    if args.length > 200:
        print(
            "WARNING! length is very large, under 200 is recommended for most services."
        )

    if args.time_cost < 1:
        parser.error("time-cost must be at least 1")

    if args.memory_cost < 8:
        parser.error("memory-cost must be at least 8 KiB")

    if args.parallelism < 1:
        parser.error("parallelism must be at least 1")

    service = args.service
    master = getpass.getpass("Master password: ").encode("utf-8")

    tag = "" if args.no_version_tag else TAG
    alphabet = PRESETS[args.preset]

    payload_length = args.length - len(tag)
    limit = 256 - (256 % len(alphabet))
    acceptance_rate = limit / 256

    FAILSAFE = 8

    dklen = math.ceil(payload_length / acceptance_rate) + FAILSAFE

    service_seed = (
        b"kagipass:"
        + VERSION.encode("ascii")
        + b":"
        + hashlib.sha256(service.encode("utf-8")).digest()
        + args.length.to_bytes(4, "big")
    )

    hashed = hash_secret_raw(
        secret=master,
        salt=service_seed,
        time_cost=args.time_cost,
        memory_cost=args.memory_cost,
        parallelism=args.parallelism,
        hash_len=dklen,
        type=Type.ID,
    )

    payload = encode_password(
        hashed,
        alphabet,
        payload_length,
    )

    password = tag + payload

    print(password)
