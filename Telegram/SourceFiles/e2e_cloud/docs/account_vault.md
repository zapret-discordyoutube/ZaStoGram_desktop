# Account Vault

## Key hierarchy

The user password is not a message key and is not used as raw cryptographic key
material.

```text
user password
    |
Argon2id(password, salt, versioned parameters)
    |
key-encryption key
    |
authenticated unwrap
    |
random account vault master key
    |
encrypted account identity and vault records
```

The random account vault master key is generated locally with a cryptographic
random-number generator. Changing the password rewraps this master key and does
not re-encrypt the complete message and file archive.

## Vault contents

- account signing identity;
- account archive-decryption identity;
- authorized client-instance records;
- conversation identifiers, pinned Telegram peers, and immutable genesis-owner
  identities;
- latest locally observed vault generation and group checkpoints;
- password KDF algorithm, version, salt, and parameters;
- safety-code state and identity-change acknowledgements.

Large per-message keys do not belong directly in the account vault. They are
recovered through per-conversation archive epoch grants.

Each Telegram peer binding occurs at most once in the authenticated
conversation index. Two independent cryptographic conversations must never
consume the same carrier group; an index with duplicate peer bindings is
invalid and blocks unlock instead of selecting one mapping heuristically.

## Password derivation

Argon2id parameters are versioned and stored with the encrypted vault. Concrete
memory and time limits must be benchmarked on the oldest supported mobile and
desktop platforms. The client should target a bounded unlock delay while using
as much memory as safely available.

A KDF slows offline guessing but cannot repair a weak password. The UI must
encourage a long unique passphrase and must not silently truncate or normalize
it inconsistently across platforms. New vaults require at least 12 Unicode
characters; unlocking remains compatible with older nonempty passwords.

Version one wraps only the random 32-byte vault master key. Its authenticated
binary record contains the `TDE2EVLT` magic, format and KDF identifiers,
versioned Argon2id memory/time/parallelism parameters, a fresh 16-byte salt, a
fresh 12-byte AES-GCM nonce, the nonzero vault generation, the fixed ciphertext
length, 32 bytes of ciphertext, and a 16-byte tag. The complete header is
authenticated as additional data. Parsers bound KDF parameters before invoking
the KDF so a hostile cloud record cannot request unbounded memory or work.

The password is accepted as explicit UTF-8 bytes from the UI, is never silently
truncated or normalized by the cryptographic layer, and is cleansed after each
derivation attempt. Version one uses the official Argon2 reference
implementation at tag `20190702`, built from its portable sources rather than
depending on the project's older bundled OpenSSL. New vaults require at least
64 MiB and three iterations. Version one accepts at most 128 MiB, four
iterations, parallelism four, and 256 MiB-iterations of combined work. Vault
selection evaluates at most four distinct wrapped master keys and derives once
per wrapper regardless of the number of historical vault generations. These
limits are applied before Argon2 runs so an untrusted Telegram container cannot
turn unlock into an unbounded CPU or memory operation.

## Unlocked session

Version one does not store the password or vault master key in an operating-
system credential facility. The user enters the password after a process start
and whenever the protected identity is manually locked or the application
passcode locks Telegram. The unlocked vault master key remains only in process
memory and is cleansed when the protected identity locks.

Per-conversation 256-bit local record keys are derived from the unlocked vault
master key with HKDF-SHA-256 and are bound to the Telegram account and protected
conversation. Versioned AES-256-GCM envelopes then protect local snapshots with
purpose-bound authenticated data. Snapshot files are atomically replaced and
there is no plaintext fallback.

## Password change

1. Unlock the current vault.
2. Derive a new key-encryption key with a fresh salt and current parameters.
3. Increment the authenticated vault generation.
4. Rewrap the unchanged random vault master key.
5. Publish the new encrypted vault blob.

## Forgotten password

Telegram cannot recover the old vault. Password reset creates a new account E2E
identity. Protected groups treat it as an identity replacement requiring a
signed admission decision. Owners or E2E administrators may grant the new
identity historical epochs allowed by group policy.

## Rollback limitation

An active server may present an older encrypted vault to a brand-new installation
that has no recent local checkpoint. Vault generations, signed checkpoints, and
gossip can reveal rollback after group synchronization, but no independent
witness exists in the current no-backend design. This remains part of the stated
active-server limitation.

Even without a local checkpoint, every vault version returned by Telegram must
form one authenticated chain beginning at generation one. A missing generation,
missing genesis, or `previousBlobDigest` that crosses between concurrent branches
blocks unlock. This catches selective holes and visible branch substitution, but
it cannot detect a server that presents a complete, self-consistent stale prefix.

The selected availability policy permits a new installation to unlock the vault,
read available history, download ciphertext, and compose messages before it
receives a fresh signed checkpoint. Composed messages are protected at rest in a
local queue. They are not encrypted against group state or uploaded to Telegram
until freshness is confirmed.

Any authenticated installation of a protected participant may answer the random
freshness challenge. Security-critical E2E administration is also disabled
while the challenge is pending. If the response reports a newer checkpoint, the
client resynchronizes and then encrypts queued messages against that state.

An active server may keep the isolated installation on a stale read-only view,
block the challenge, or route it only to a participant that is also stale. The
random nonce prevents recorded-response replay but does not prove that no newer
branch exists. Avoiding stale-membership disclosure requires reaching an honest
witness that has observed the current branch.
