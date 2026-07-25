# TZEPak Password Generator

> This is an experimental project. It is not intended for production use without proper security review, testing, and validation.

> TZEPak (more specifically, `tžepak`) means "security" in one of my older conlangs.

## Overview

TZEPak is a deterministic password generator that creates unique, reproducible passwords using two primary inputs:

- A service identifier (such as a website or application name)
- A user-provided master secret

Given the same inputs and generator version, TZEPak will always generate the same password. This allows passwords to be regenerated without storing each password individually.

# _Make your own TZEPak variant!_

**We strongly recommend reviewing and modifying the generator to your own liking before using it for any real-world passwords. Any changes to the generator should be assigned an unique identifier to prevent compatibility issues with previously generated passwords.**

## How It Works

TZEPak generates passwords using a deterministic process:

1. The service identifier is normalized and incorporated into a unique salt.
2. The master secret and salt are processed using PBKDF2-HMAC-SHA256 to derive a 256-bit key.
3. The derived key is used to produce deterministic formatting information, including:
    - component ordering
    - character case randomization
    - fixed password fragments

4. A version identifier is prepended to the generated password.

Service identifiers and master secrets are processed as UTF-8, allowing TZEPak to support arbitrary Unicode input.

## Reproducing Passwords

The output will remain identical as long as:

- the master secret remains unchanged
- the service identifier remains unchanged
- the TZEPak version remains unchanged

## Example

Input:

```
Service:
> Example

Master Secret:
> your secret
```

Output:

```
TZUxxxxxxxxxxxxxxxxxxxx...
```

## Security Notice

TZEPak is an experimental project and has not been independently audited.

The security of generated passwords depends heavily on:

- the strength and secrecy of the master secret
- the correctness of the implementation
- the security of the underlying cryptographic primitives

Do not use TZEPak for important accounts unless you fully understand the risks and have independently verified the implementation.
