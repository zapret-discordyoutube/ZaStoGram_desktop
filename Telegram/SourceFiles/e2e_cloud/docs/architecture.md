# Architecture

## Product model

A protected group consists of two related objects:

1. A private Telegram supergroup used only for delivery, ordering hints, and
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

Telegram Desktop owns the orchestration service at `Main::Session` scope. The
service coordinates vault selection, protected-group discovery, group and
content backfill, exact-byte outboxes, freshness, and crash recovery. The UI
reads only authenticated local records and invokes the same transactional group
engines used by automatic admission; it has no direct mutation path around MLS
or protected authorization.

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
and state validation. Version one uses OpenMLS `0.8.1`, pinned to upstream
commit `0e99bc8814d136f0bc7bc9ce86dd288eb32273ed`, with its RustCrypto provider
and only cipher suite `0x0001`. A narrow versioned C ABI keeps Rust and OpenMLS
types out of the desktop and future mobile application layers.

The application-facing boundary remains replaceable so migrations and
independent interoperability tests do not depend on OpenMLS types. Selection of
the library does not waive the production gate: the integrated engine must pass
published RFC vectors, interoperate with another implementation, support
fuzzing, and receive independent security review.

Each protected conversation owns an independent provider state. A mutating
operation runs on an isolated copy and produces a candidate provider snapshot.
Admissions, removals, policy changes, and ownership or role changes each create
a real MLS commit and advance the MLS epoch. The same operation rotates the
archive epoch and signs commitments to the exact commit and encrypted archive
key distribution. The MLS snapshot, protected-group ledger, archive state, and
outbox become authoritative through one encrypted recoverable write-ahead
transaction. The application never sends ciphertext from an uncommitted state
and never advances a live sender ratchet before the corresponding exact retry
bytes are durable.

Inbound commit, transition, archive-distribution, Welcome, and
admission-KeyPackage objects may arrive in any order. A purpose-bound encrypted
inbox stages them by stable object identifier together with the Telegram sender
binding observed at receipt, detects competing next-generation transitions or
sender substitutions, and assembles a bundle only when all signed hashes match.
The immutable genesis owner anchors public discovery even after protected
ownership is transferred; the current owner remains authoritative in the
signed group state. Existing members process the commit and distribution on
isolated OpenMLS state. A joining client processes the Welcome and distribution
from its KeyPackage state. Both paths use the same cross-store transaction, but
inbound transactions never enqueue the received objects for upload.

If a processed commit removes the local client, it cannot decrypt the following
archive distribution. The transaction instead destroys active provider bytes,
stores a removal tombstone, advances the verified group chain, and leaves the
archive state unchanged. Re-admission uses a fresh KeyPackage and Welcome; the
archive store records the skipped generations as an access gap.

### Protected group state

Maintains the authoritative account membership, independent client
credentials, E2E owner, capability-scoped administrators, history policy, and
monotonic protected generation. It validates authorization again after
cryptographic verification, so a Telegram role or malformed signed payload
cannot directly mutate product state.

The persistent ledger starts with a signed genesis and stores every canonical
transition. Each checkpoint commits its predecessor, actor, authorization,
exact MLS object, next archive-key commitment, and encrypted archive
distribution. OpenMLS roster reconciliation requires the exact protected set
of account/client pairs after every change.

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

Control and content use distinct fixed generic filenames in the same private
carrier group. Control reconstruction is bounded to 65,536 objects and 512 MiB,
matching the version-one signed-ledger lifecycle bound. Content backfill keeps a
protected newest-observed boundary and processes bounded pages without treating
that Telegram message identifier as security state.

## Primary flows

### Create a protected group

1. The creator unlocks or creates the account vault.
2. The client creates a private Telegram carrier supergroup.
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
5. The target applies the Welcome and current archive-key distribution in one
   atomic local transaction. It starts with the current archive epoch only.
6. Older history keys are granted according to the group default and any signed
   per-invitation override.
7. The participant becomes active only after the signed transition, archive
   commitment, and resulting MLS roster all agree.

### Send a message

1. The client creates a random content key.
2. The body is encrypted once under that key.
3. The MLS engine seals the content key and authenticated metadata against an
   isolated copy of the current provider state.
4. The new provider snapshot and exact outgoing envelope are committed in one
   protected local transaction.
5. The live MLS application message carries the content key and authenticated
   metadata to current group members.
6. An archive envelope wraps the same content key under the current archive
   epoch key.
7. Telegram stores the encrypted body, MLS envelope, and archive envelope.

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
3. The MLS engine creates an add, remove, or self-update commit authenticated
   with the canonical transition prelude.
4. Every protected transition advances both MLS and archive epochs. Clients
   apply the MLS state, protected state, and archive key atomically.
5. Telegram administrator state remains only an untrusted UI signal.

The Desktop owner interface exposes promotion/demotion, member removal, the
default history mode, and per-member history mode. Expanding a member's history
also creates an account-scoped HPKE grant inside the same prepared transition;
the group mutation, MLS self-update, archive rotation, grant publication, and
vault checkpoint update either become recoverable together or do not publish.

### Confirm freshness and gossip identity

1. Before first send or protected administration, a client publishes a random
   challenge containing its exact known checkpoint.
2. Any account client active at that checkpoint may sign a response binding the
   challenge nonce, challenged checkpoint, its observed checkpoint, and its
   account/client identity.
3. An equal checkpoint opens sending; a newer checkpoint requires
   resynchronization; an equal-generation different hash permanently marks a
   fork until explicit recovery.
4. Signed gossip snapshots carry the reporter checkpoint plus the sorted
   Telegram-user/account/credential-hash observations. A valid differing local
   snapshot creates an identity security event instead of replacing a pin.
