import hashlib, random, unicodedata

ITERATIONS = 1_000_000  # change this if the program doesn't perform well on your device
# DO NOTE THAT CHANGES TO THIS CONSTANT *WILL* SHUFFLE ALL OF THE PASSWORDS


def shuffle(text, seed):
    result = random.Random(seed)
    ce = list(text)
    result.shuffle(ce)
    return "".join(ce)


def randomize_case(text, seed):
    reh = random.Random(seed)
    result = []
    for char in text:
        result.append(
            char.upper()
            if reh.randint(0, 1)
            else char.lower() if char.isalpha() else char
        )
    return "".join(result)


print("Tzepak Algorithm v0.2-beta")

service = unicodedata.normalize(
    "NFKC", input("Please enter the service name:\n> ").strip()
).lower()
master = unicodedata.normalize(
    "NFKC", input("Please enter your master passkey:\n> ").strip()
).encode("utf-8")

service_seed = b"tzepak:" + hashlib.sha256(service.encode()).digest()

hashed = hashlib.pbkdf2_hmac(
    "sha256",
    master,
    service_seed,
    ITERATIONS,
    dklen=32,
)

fragment = hashed.hex()[:15]

seed = int.from_bytes(hashlib.sha256(hashed).digest(), "big")

a1 = "!~"
a2 = "~!"
a3 = "cysfigr"
a4 = "tzepak"
a5 = fragment
a6 = "@@@!"
a7 = "!!@@"

a3 = shuffle(a3, seed)
a4 = shuffle(a4, seed)

parts = [a1, a2, a3, a4, a5, a6, a7]

rn = random.Random(seed)
rn.shuffle(parts)

password = "TZU0.1B" + randomize_case("".join(parts), seed)

print(password)
