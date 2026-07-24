l = __import__("hashlib")
rm = __import__("random")


def rf(t, se):
    rah = rm.Random(se)
    ce = list(t)
    rah.shuffle(ce)
    return "".join(ce)


def rc(text, seed):
    rah = rm.Random(seed)
    r = []
    for c in text:
        r.append(c.upper() if rah.randint(0, 1) else c.lower() if c.isalpha() else c)
    return "".join(r)


def r(t, s):
    r = ""
    p = 26
    b = __import__("builtins")
    o = b.ord
    h = b.chr

    for c in t:
        r += (
            h((o(c) - o("a") + s) % p + o("a"))
            if c.islower()
            else h((o(c) - o("A") + s) % p + o("A")) if c.isupper() else c
        )

    return r


a = input("service name:\n> ").strip().lower()
am = a[-1] + a[0]
amp = r(am, 1)
amq = r(am, 2147483647)
amr = r(am, 21474836472147483647)
an = (amp[0] + amq[0] + amr[0] + amp[1] + amq[1] + amr[1]).lower()
anp = r(an, 20)
anq = r(an, 0x8FACDEBB)
anr = r(an, 0x7FFFFFFF)
ao = (anp[0] + anq[0] + anr[0] + anp[-1] + anq[-1] + anr[-1]).lower()
aop = r(ao, 0x2918FACF)
aoq = r(ao, 0xFACAFACA)
aor = r(ao, 0xBACABACA)
ap = (aop[0] + aoq[0] + aor[0] + aop[-1] + aoq[-1] + aor[-1]).lower()


m = input("master:\n> ").strip()
mas = m.encode("utf-8")
seed = f"tzepak:{a}:{ap}:{ao}:{an}:{am}".encode("utf-8")

h = l.pbkdf2_hmac(
    "sha256",
    mas,
    seed,
    600_000,
    dklen=32,
)

r = h.hex()[:10]

su = int.from_bytes(l.sha256(h).digest()[:8], "big")

a1 = "!~"
a2 = "~!"
a3 = "cysfigr"
a4 = "tzepak"
a5 = r
a6 = "@@!"
a7 = "!@@"

a3 = rf(a3, su)
a4 = rf(a4, su)

parts = [a1, a2, a3, a4, a5, a6, a7]

rn = rm.Random(su)
rn.shuffle(parts)

r = "TZU0.1B" + rc("".join(parts), su)

print(r)
