# kagipass

> This is still an experimental project. It is not intended for production use without proper security review, testing, and validation.

> kagi (鍵、かぎ) means "key" in japanese.

## Overview

kagipass is a deterministic password generator that creates unique, reproducible passwords using two primary inputs:

- A service identifier (such as a website or application name)
- A user-provided master secret

Given the same inputs and generator version, kagipass will always generate the same password. This allows passwords to be regenerated without storing each password individually.

## How It Works

kagipass generates passwords using a deterministic process:

1. The service identifier is normalized and incorporated into a unique salt.
2. The master secret and salt are processed using PBKDF2-HMAC-SHA256 to derive a 256-bit key.
3. The derived key is used to produce deterministic formatting information, including:
    - component ordering
    - character case randomization
    - fixed password fragments

4. A version identifier is prepended to the generated password.

Service identifiers and master secrets are processed as UTF-8, allowing kagipass to support arbitrary Unicode input.

## Reproducing Passwords

The output will remain identical as long as:

- the master secret remains unchanged
- the service identifier remains unchanged
- the kagipass version remains unchanged

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

kagipass is an experimental project and has not been independently audited.

The security of generated passwords depends heavily on:

- the strength and secrecy of the master secret
- the correctness of the implementation
- the security of the underlying cryptographic primitives

Do not use kagipass for important accounts unless you fully understand the risks and have independently verified the implementation.
