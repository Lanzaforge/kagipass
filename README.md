# kagipass

> This is still an experimental project. It is not intended for production use without proper security review, testing, and validation.

> kagi (鍵、かぎ) means "key" in japanese.

## Installation

### Using pipx

```sh
pipx install kagipass
```

### Using uv

```sh
uv tool install kagipass
```

## Overview

kagipass is a deterministic password generator using Argon2id that creates unique, reproducible passwords using two primary inputs:

- A service identifier (such as a website or application name)
- A user-provided master secret

Given the same inputs and generator version, kagipass will always generate the same password. This allows passwords to be regenerated without storing each password individually.

## Security Notice

kagipass is an experimental project and has not been independently audited.

The security of generated passwords depends heavily on:

- the strength and secrecy of the master secret
- the correctness of the implementation
- the security of the underlying cryptographic primitives

Do not use kagipass for important accounts unless you fully understand the risks and have independently verified the implementation.

```

```
