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
- Protected groups are created as a new group mode. A private Telegram
  supergroup acts as the carrier, while cryptographic membership is authoritative.
- Clients without E2E support do not receive keys.
- Group owners and explicitly appointed E2E administrators manage encryption
  policy.
- History access has a group default and may be overridden for an individual
  invitation.
- The account password unlocks a random account vault key. It never encrypts
  messages or files directly.
- A forgotten password creates a new E2E identity. Telegram cannot recover the
  previous identity or vault.
- The user remembers the E2E password. Version one keeps the unlocked vault only
  for the current process session and clears it on manual or application lock.
- A new installation may unlock its vault, read available history, and compose
  messages before a freshness witness answers a new challenge. New messages
  remain in a protected local queue, and no content or security-critical
  administration is sent until confirmation. Telegram-only delivery cannot
  prove that the witness sees the globally latest branch.
- Version one pins OpenMLS `0.8.1` at upstream security-dependency commit
  `0e99bc8814d136f0bc7bc9ce86dd288eb32273ed`, uses its RustCrypto provider,
  and exposes it only through a replaceable versioned C ABI.
- The first performance target is 500 group participants, without making 500 a
  protocol limit.

## Implementation status

The first core slice now contains:

- strongly typed account, client, conversation, object, and checkpoint IDs;
- a versioned logical transport envelope and strict structural validation;
- a deterministic version-one binary envelope codec with bounded fields;
- a freshness state machine that fails closed on conflicting checkpoints;
- canonical signed freshness responses and identity-gossip snapshots bound to
  protected checkpoints and active account clients;
- a protected-outbox boundary that cannot seal or upload drafts before
  freshness confirmation and retries the exact persisted ciphertext;
- an encrypted atomic outbox snapshot and purpose-bound AES-256-GCM local
  record protector;
- an authoritative owner, capability-scoped administrator, membership, client,
  history-grant, and canonical-transition state machine;
- a persistent signed genesis/transition ledger whose chain commits the exact
  MLS commit, archive-key commitment, and encrypted key distribution;
- canonical account credentials, safety-code derivation, real Ed25519/X25519
  account key generation, and domain-separated account signatures;
- an authenticated password-vault wrapping format with the pinned Argon2id
  reference implementation and a separate minimum policy for new vaults;
- a two-stage opaque Telegram document carrier that acknowledges only after
  the final send operation succeeds;
- a desktop Telegram-session carrier adapter that uses the existing uploader,
  sends an empty-caption force-file document with `messages.sendMedia`, and
  downloads bounded `messages.search` pages through the existing file
  loader;
- separate fixed-name control and content carriers, Telegram update-driven
  incremental content synchronization with fingerprint-verified oldest-first
  page replay, and automatic protected-group discovery from the carrier groups
  already visible to the signed-in account;
- a two-phase authenticated inbound processor and protected replay journal that
  preserve uncertain crash state instead of replaying it blindly;
- resumable AES-256-GCM file chunks, a canonical private manifest, and a
  protected persistent nonce ledger that rejects changed source bytes;
- a protected per-conversation MLS state store that atomically commits a new
  provider snapshot with the exact outgoing retry envelope or accepted inbound
  plaintext;
- real OpenMLS creation, inspection, add, remove, self-update, Welcome, and
  application processing through ABI `0x00010006`, with roster reconciliation;
- account-signed, carrier-bound, generation-bound client KeyPackage
  publications whose signed object IDs commit to the observed Telegram author,
  with explicit 84-day MLS lifetimes;
- one encrypted write-ahead transaction spanning MLS state, protected group
  state, archive epochs, and outgoing publication for admissions, removals,
  role/policy changes, ordinary inbound changes, and first-time Welcome joins;
- a protected group-change inbox that accepts Telegram objects in arbitrary
  order, detects competing transitions, survives restart, and never republishes
  inbound objects;
- a protected own-removal tombstone that destroys active MLS state, preserves
  the verified removal checkpoint, and permits re-admission only through a new
  account-authorized KeyPackage and Welcome;
- RFC 9180 Base-mode history grants, signed by the granting account and sealed
  to the recipient account archive key;
- signed checkpoint gossip with automatic per-account witness reporting,
  pairwise/account/group safety codes, and fail-closed fork or identity-conflict
  handling;
- an encrypted archive-epoch state store with fail-closed key-conflict and safe
  `Full`, `FromJoin`, and epoch-boundary `Since` selection;
- replaceable boundaries for MLS, the account vault, archive, files, envelope
  encoding, and Telegram transport;
- a Desktop interface for vault creation/unlock, protected-group creation,
  encrypted text and arbitrary-file transfer, file restoration with final hash
  verification, participant safety details, E2E roles, removal, and history
  administration;
- fail-closed Desktop carrier presentation that hides service containers from
  the ordinary timeline/shared media, removes ordinary export actions, and
  replaces plaintext composition with the protected-conversation entry point;
- focused state-machine and negative tests in the standard desktop test area.

Test doubles remain outside the production target. Live carrier integration
still needs end-to-end server transformation, multi-account update-stream, and
large-group testing. Mobile integration, full interoperability/fuzz/load
coverage, and independent
cryptographic review are still required; the module is not ready for user data.

## Code layout

```text
e2e_cloud/
├── core/          types, envelopes, signed freshness, and outbox boundaries
├── group/         protected state and the signed persistent transition ledger
├── identity/      account credentials, safety codes, and signed gossip
├── mls/           OpenMLS ABI, roster validation, and group-change engines
├── protocol/      inbound staging and cross-store transactions
├── storage/       purpose-bound encrypted persistent records
├── vault/         password-unlocked account identity storage
├── archive/       history epochs and grants
├── files/         encrypted manifests and chunk streams
├── transport/     Telegram message and document carrier
├── desktop/       Telegram Desktop service and protected-group interface
└── docs/          architecture and security decisions
```

Tests live with the existing Telegram Desktop tests in `SourceFiles/tests`.

## Documents

- [Architecture](docs/architecture.md)
- [Threat model](docs/threat_model.md)
- [Protocol model](docs/protocol.md)
- [MLS engine and transaction boundary](docs/mls_engine.md)
- [Protected group state](docs/group_state.md)
- [Account identity and safety codes](docs/identity.md)
- [Protected local storage](docs/local_storage.md)
- [Account vault](docs/account_vault.md)
- [History access](docs/history_access.md)
- [Files](docs/file_storage.md)
- [Telegram transport](docs/transport.md)
- [Desktop integration](docs/desktop_integration.md)
- [Decision record](docs/decisions.md)
- [Architecture review](docs/review.md)
- [Open questions](docs/open_questions.md)
