# E2E Cloud Groups

This directory is the design and implementation home for encrypted cloud
groups transported through Telegram. The feature is under active development.
Nothing here should currently be treated as production cryptography.

The intended user experience is a new protected Telegram group that looks the
same on every authorized desktop or mobile installation. Devices are not
paired in the user interface. A user unlocks the account E2E vault with one
password on each new installation.

## Fixed decisions

- Telegram is the only delivery and blob-storage service. There is no custom
  backend.
- Telegram stores opaque encrypted containers and must not receive plaintext
  chat, file, archive, or private-key material.
- The system aims to resist active server attempts to replace established
  keys or inject participants.
- First contact uses trust on first use, signed key gossip, and a human-readable
  safety code. This cannot completely prevent first-contact substitution when
  Telegram is the only communication channel.
- Protected groups are created as a new group mode. A normal private Telegram
  group acts as the carrier, while the cryptographic membership is authoritative.
- Clients without E2E support do not receive keys.
- Group owners and explicitly appointed E2E administrators manage encryption
  policy.
- History access has a group default and may be overridden for an individual
  invitation.
- The account password unlocks a random account vault key. It never encrypts
  messages or files directly.
- A forgotten password creates a new E2E identity. Telegram cannot recover the
  previous identity or vault.
- An unlocked vault may be remembered using the operating system's protected
  credential storage.
- A new installation may unlock its vault, read available history, and compose
  messages before a freshness witness answers a new challenge. New messages
  remain in a protected local queue, and no content or security-critical
  administration is sent until confirmation. Telegram-only delivery cannot
  prove that the witness sees the globally latest branch.
- The MLS engine remains replaceable. Cisco MLS++, OpenMLS, another audited
  implementation, or a separately reviewed RFC 9420 implementation may be
  evaluated later.
- The first performance target is 500 group participants, without making 500 a
  protocol limit.

## Implementation status

The first core slice now contains:

- strongly typed account, client, conversation, object, and checkpoint IDs;
- a versioned logical transport envelope and strict structural validation;
- a deterministic version-one binary envelope codec with bounded fields;
- a freshness state machine that fails closed on conflicting checkpoints;
- a protected-outbox boundary that cannot seal or upload drafts before
  freshness confirmation and retries the exact persisted ciphertext;
- an encrypted atomic outbox snapshot and purpose-bound AES-256-GCM local
  record protector;
- an authoritative owner, capability-scoped administrator, membership, client,
  history-grant, and canonical-transition state machine;
- canonical account credentials, safety-code derivation, real Ed25519/X25519
  account key generation, and domain-separated account signatures;
- an authenticated password-vault wrapping format with a bounded Argon2id
  provider boundary;
- a two-stage opaque Telegram document carrier that acknowledges only after
  the final send operation succeeds;
- a two-phase authenticated inbound processor and protected replay journal that
  preserve uncertain crash state instead of replaying it blindly;
- resumable AES-256-GCM file chunks, a canonical private manifest, and an
  idempotent nonce ledger boundary that rejects changed source bytes;
- replaceable boundaries for MLS, the account vault, archive, files, envelope
  encoding, and Telegram transport;
- focused state-machine and negative tests in the standard desktop test area.

The test doubles do not implement encryption and are never part of the
production target. A production MLS engine remains deliberately unselected.

## Code layout

```text
e2e_cloud/
├── core/          types, envelopes, freshness, outbox, and service boundaries
├── protocol/      replaceable MLS engine and wire envelopes
├── vault/         password-unlocked account identity storage
├── archive/       history epochs and grants
├── files/         encrypted manifests and chunk streams
├── transport/     Telegram message and document carrier
├── tests/         vectors, state-machine tests, fuzz targets, interoperability
└── docs/          architecture and security decisions
```

Additional code directories are created only with their first reviewed
implementation file. Empty directories would not be preserved by Git.

## Documents

- [Architecture](docs/architecture.md)
- [Threat model](docs/threat_model.md)
- [Protocol model](docs/protocol.md)
- [Protected group state](docs/group_state.md)
- [Account identity and safety codes](docs/identity.md)
- [Protected local storage](docs/local_storage.md)
- [Account vault](docs/account_vault.md)
- [History access](docs/history_access.md)
- [Files](docs/file_storage.md)
- [Telegram transport](docs/transport.md)
- [Decision record](docs/decisions.md)
- [Architecture review](docs/review.md)
- [Open questions](docs/open_questions.md)
