# Architecture

## Product model

A protected group consists of two related objects:

1. A normal private Telegram group used only for delivery, ordering hints, and
   encrypted blob storage.
2. An E2E conversation identified by a random conversation identifier and a
   cryptographically authenticated group state.

Telegram membership is an input to the user interface and admission workflow.
It is not sufficient proof of cryptographic membership. Access to plaintext is
granted only after a valid group-state transition.

## Components

### Application integration

Presents the group, messages, members, history policy, safety codes, and
security events. It maps a Telegram peer identifier to an E2E conversation but
does not perform cryptographic operations itself.

### Account vault

Stores the account identity, archive decryption identity, conversation index,
and recovery metadata. The vault is encrypted under a random key that is
wrapped by a password-derived key. A new installation downloads the encrypted
vault from Telegram and unlocks it locally.

### Account identity

Uses a stable account-level Ed25519 authorization key and X25519 archive HPKE
key. It signs independent per-installation, per-group client credentials rather
than sharing one MLS leaf signing key across devices or groups. TOFU pins the
credential to a Telegram user binding; pairwise and roster safety codes support
optional out-of-band comparison.

### Client instance

Devices are not paired or managed in the product interface. Internally, every
installation still needs an independent client instance and independent MLS
sender state. Sharing one mutable sender state between concurrently active
devices risks key or nonce reuse.

An unlocked account vault authorizes the installation to create a client
credential signed by the account identity. Enrollment in protected groups is
automatic after that proof is validated.

### MLS engine

Provides group creation, KeyPackage processing, proposals, commits, welcomes,
application-message protection, member removal, epoch changes, persistence,
and state validation. The application depends on a narrow engine interface and
not on one concrete MLS library.

The production engine must implement RFC 9420 semantics, pass published test
vectors, interoperate with another implementation, support fuzzing, and receive
independent security review.

### Protected group state

Maintains the authoritative account membership, independent client
credentials, E2E owner, capability-scoped administrators, history policy, and
monotonic protected generation. It validates authorization again after
cryptographic verification, so a Telegram role or malformed signed payload
cannot directly mutate product state.

### Archive service

Full cloud history is intentionally separate from live MLS forward secrecy.
It stores encrypted content-key envelopes grouped into archive epochs. Archive
epoch keys are granted to eligible account identities according to signed
history policy.

### File service

Encrypts arbitrary byte streams locally, creates authenticated manifests, and
uploads only ciphertext chunks through the Telegram transport.

### Telegram transport

Serializes protocol envelopes into ordinary Telegram messages or documents.
It may retry, reorder, duplicate, delay, or lose data. The protocol layer must
therefore validate every envelope independently and never rely on Telegram
delivery as proof of authenticity.

## Primary flows

### Create a protected group

1. The creator unlocks or creates the account vault.
2. The client creates a normal private Telegram carrier group.
3. The MLS engine creates a new cryptographic group and random conversation
   identifier.
4. The creator publishes signed initial group state and transport metadata.
5. The client pins the creator identity and records the initial safety-code
   material.

### Join a participant

1. Telegram membership produces an admission request, not immediate access.
2. A supported client publishes an account credential and client KeyPackage.
3. An E2E owner or administrator validates the request and current pinned
   identity.
4. The MLS engine produces the authenticated add transition and welcome.
5. History keys are granted according to the group default and any signed
   per-invitation override.
6. The participant becomes active only after applying the valid MLS state.

### Send a message

1. The client creates a random content key.
2. The body is encrypted once under that key.
3. The live MLS application message carries the content key and authenticated
   metadata to current group members.
4. An archive envelope wraps the same content key under the current archive
   epoch key.
5. Telegram stores the encrypted body, MLS envelope, and archive envelope.

### Add a new installation

1. The user signs in to Telegram and downloads the encrypted account vault.
2. The user enters the E2E password.
3. The installation creates independent client state authorized by the account
   identity.
4. It automatically enrolls in the account's protected groups.
5. It downloads archive grants, encrypted history, and encrypted files.
6. It requests fresh signed checkpoints from protected-group participants.

The installation may unlock the vault, read available history, download
ciphertext, and compose messages while checkpoint confirmation is pending.
Composed messages remain in a protected local queue. The client sends no new
content and performs no security-critical E2E administration until any current
installation of any participant answers a fresh challenge with a valid current
checkpoint. This confirms live agreement with that checkpoint; it proves global
freshness only when an honest up-to-date witness is reachable.

After confirmation, queued messages are encrypted against the confirmed current
group state and uploaded. If a witness reports a newer generation, the client
resynchronizes first and only then encrypts and sends the queue.

No existing desktop or phone needs to approve or connect to the new
installation.

### Change protected administration

1. The client confirms freshness before constructing a local operation.
2. The current protected state validates the actor client, role, capability,
   target credential, generation, and transition identifier.
3. The MLS engine authenticates and commits the transition.
4. Clients apply the verified transition and rotate live or archive epochs when
   the operation requires it.
5. Telegram administrator state remains only an untrusted UI signal.
