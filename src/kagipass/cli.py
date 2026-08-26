def main() -> None:
    import argparse
    import getpass
    import hashlib
    import math
    import json
    import secrets
    import string

    from typing import Literal
    from argon2.low_level import Type, hash_secret_raw
    from importlib.metadata import version
    from pathlib import Path
    from platformdirs import user_config_dir

    VERSION = version("kagipass")
    TAG = "KgU12b"

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

    CONFIG_DIR = Path(user_config_dir("kagipass"))
    STATE_FILE = CONFIG_DIR / "state.json"

    def load_state() -> dict:
        if not STATE_FILE.exists():
            return {"pepper_generated": False}
        return json.loads(STATE_FILE.read_text())

    def save_state(state: dict) -> None:
        CONFIG_DIR.mkdir(parents=True, mode=0o700, exist_ok=True)
        STATE_FILE.write_text(json.dumps(state, indent=2))
        STATE_FILE.chmod(0o600)

    def generate_pepper() -> bytes:
        pepper = secrets.token_hex(32)

        print("======== IMPORTANT!! ========")
        print("\033[32mA new pepper has been generated.\033[0m")
        print()
        print(pepper)
        print()
        print("You will need it every time you run kagipass.")
        print(
            "We recommend keeping the pepper in a password manager or as a physical copy."
        )
        print(
            "\033[31mIF YOU LOSE ACCESS TO THIS PEPPER, YOU WON'T BE ABLE TO REGENERATE YOUR PASSWORDS!\033[0m",
        )
        print("=============================")

        state = load_state()
        state["pepper_generated"] = True
        save_state(state)

        return pepper.encode()

    def ask_pepper() -> bytes:
        while True:
            pepper = (
                getpass.getpass(
                    "Please enter the 64-character hexadecimal pepper. "
                    "(case-insensitive, surrounding whitespace is ignored)\n> "
                )
                .strip()
                .lower()
            )

            if pepper == "":
                return b""

            if len(pepper) != 64:
                print(
                    "\033[31mPepper must be exactly 64 hexadecimal characters.\033[0m "
                    "Please try again."
                )
                continue

            if not all(c in string.hexdigits for c in pepper):
                print(
                    "\033[31mPepper must contain only hexadecimal characters.\033[0m "
                    "Please try again."
                )
                continue

            return bytes.fromhex(pepper)

    def get_pepper(force: bool = False) -> bytes:
        state = load_state()

        if force or not state.get("pepper_generated"):
            return generate_pepper()

        return ask_pepper()

    def encode_password(data: bytes, alphabet: str, length: int) -> str:
        limit = 256 - (256 % len(alphabet))

        result = []

        for byte in data:
            if byte >= limit:
                continue

            result.append(alphabet[byte % len(alphabet)])

            if len(result) >= length:
                return "".join(result)

        raise RuntimeError("Argon2id did not produce enough usable output bytes.")

    # ========== argument parsing thingy ========== #

    parser = argparse.ArgumentParser(
        description="Generate deterministic passwords using the kagipass algorithm."
    )

    parser.add_argument(
        "-v",
        "--version",
        action="version",
        version=f"kagipass {VERSION}",
    )

    parser.add_argument(
        "-S",
        "--service",
        help="Service name to generate the password for. Case-insensitive.",
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
        default=6,
        help="Argon2id time cost. Defaults to 6.",
    )

    parser.add_argument(
        "-M",
        "--memory-cost",
        type=int,
        default=262_144,
        help="Argon2id memory cost in KiB. Defaults to 262144 (256 MiB). ",
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

    parser.add_argument(
        "--generate-pepper",
        action="store_true",
        help="Force generation of a new pepper (overwrites the previous one).",
    )

    args = parser.parse_args()

    # ========== argument validation ========== #

    if not args.generate_pepper and not args.service:
        parser.error("the following arguments are required: -S/--service")

    if args.service is None and not args.generate_pepper:
        parser.error("service is required unless --generate-pepper is used")

    if args.length <= 0:
        parser.error("length must be greater than 0")

    if args.length <= (len(TAG) if not args.no_version_tag else 0):
        parser.error("length is too small")

    if args.length > 200:
        print(
            "WARNING! length is very large, under 200 is recommended for most services."
        )

    if args.time_cost < 2:
        parser.error("time cost must be at least 2")

    if args.memory_cost < 131072:
        parser.error("memory cost must be at least 131072 KiB (128 MiB)")

    if args.parallelism < 2:
        parser.error("parallelism must be at least 2")

    if args.generate_pepper:
        generate_pepper()
        return

    service: str = args.service.strip().lower()

    master = (
        getpass.getpass(
            "Please enter your master password. (case-sensitive, surrounding whitespace is ignored)\n> "
        )
        .strip()
        .encode("utf-8")
    )

    state = load_state()
    if not state.get("pepper_generated"):
        pepper = generate_pepper()
    else:
        pepper = ask_pepper()

    tag = "" if args.no_version_tag else TAG
    alphabet = PRESETS[args.preset]
    payload_length = args.length - len(tag)

    limit = 256 - (256 % len(alphabet))
    acceptance_rate = limit / 256
    FAILSAFE = 8
    password_length = math.ceil(payload_length / acceptance_rate) + FAILSAFE

    service_seed = (
        b"<kagipass>:"
        + hashlib.sha256(service.encode("utf-8")).digest()
        + args.length.to_bytes(4, "big")
        + pepper
    )

    hashed = hash_secret_raw(
        secret=master,
        salt=service_seed,
        time_cost=args.time_cost,
        memory_cost=args.memory_cost,
        parallelism=args.parallelism,
        hash_len=password_length,
        type=Type.ID,
    )

    payload = encode_password(hashed, alphabet, payload_length)
    password = tag + payload
    print(password)
