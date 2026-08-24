# kagipass

> **This project is still experimental.** Not intended for production use without proper security review and testing.

**kagipass** (鍵 / _kagi_ = "key" in Japanese) is a deterministic password generator based on Argon2id.

It creates strong, reproducible passwords from:

- a **service name** (e.g. `github`, `discord`)
- a **master password**
- an optional **pepper**

Given the same inputs and version, kagipass always produces the same password. This lets you regenerate passwords without storing them.

## Installation

### pipx

```sh
pipx install kagipass
```

### uv

```sh
uv tool install kagipass
```

# Quick Start

```sh
# Generate a password for a service
kagipass -S github

# Force generation of a new pepper
kagipass --generate-pepper
```

On first run, kagipass will generate a high-entropy pepper.

You must save this pepper, losing it means you can no longer recreate your passwords.

# How it works

1. You provide a master password and a service name.
2. kagipass derives a salt from the service name, version, length, and optional pepper.
3. Argon2id is used to derive a high-entropy key. You can customize the Argon2id encryption parameters with arguments.
4. The key is encoded into a password using the selected character preset.

# Security Notice

kagipass is experimental and has not been independently audited.
The security of generated passwords depends on:

- the strength of your master password
- keeping the pepper secret
- the correctness of this implementation
- the underlying cryptographic libraries

Do not use kagipass for important accounts unless you fully understand the risks and have reviewed the code yourself.
