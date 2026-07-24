# TZEPak Password Algorithm

> This is an experimental project. It is not intended for production use without proper security review, testing, and validation.

> TZEPak (more specifically, `tžepak`) means "security" in one of my older conlangs.

## Overview

TZEPak is a deterministic password generation algorithm that creates unique, reproducible passwords using two primary inputs:

- A service identifier (such as a website or application name)
- A user-provided master secret

Given the same inputs and algorithm version, TZEPak will always generate the same password. This allows passwords to be regenerated without storing each password individually.

# _Make your own TZEPak variant!_

**We strongly recommend reviewing, modifying, and testing the algorithm before using it for any real-world passwords. Any changes to the algorithm should be assigned an unique identifier to prevent compatibility issues with previously generated passwords.**

## How It Works

TZEPak uses a multi-stage generation process:

1. The service identifier and master secret are processed through a key derivation function.
2. The derived output is used to generate a deterministic seed.
3. The seed controls additional transformations, including:
    - component shuffling
    - character case randomization
    - output formatting

4. The final result is generated as a versioned TZEPak password.

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
TZU0.1Bxxxxxxxxxxxxxxxx
```

The output will remain identical as long as:

- the master secret remains unchanged
- the service identifier remains unchanged
- the TZEPak version remains unchanged

## Security Notice

TZEPak is an experimental project and has not been independently audited.

The security of generated passwords depends heavily on:

- the strength and secrecy of the master secret
- the correctness of the implementation
- the security of the underlying cryptographic primitives

Do not use TZEPak for important accounts unless you fully understand the risks and have independently verified the implementation.
