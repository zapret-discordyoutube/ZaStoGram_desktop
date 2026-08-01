# Protected Local Storage

## Key boundary

Local drafts, sealed retry envelopes, MLS state, and vault cache records are
protected under per-conversation local record keys derived only after the
account vault is unlocked. User password bytes never enter the local record
protector.

Version one derives each key from the vault master key with HKDF-SHA-256 and
binds it to the Telegram account and protected conversation. Neither the
password nor the vault master key is retained by an operating-system credential
facility. Locked protected records remain inaccessible and there is no
plaintext file fallback.

## Record protection

Version one local records use AES-256-GCM with a fresh random 96-bit nonce for
every write and a 128-bit authentication tag. The fixed header, format version,
plaintext length, and a caller-supplied purpose string are authenticated as
additional data. Keys are consumed from the caller, rejected when all-zero, and
cleansed from owned memory on destruction.

The record format is:

```text
byte[8]  magic = "TDE2ELCL"
uint16   version = 1
byte[12] random_nonce
uint32   plaintext_length
byte[]   ciphertext
byte[16] authentication_tag
```

## Protected outbox

The outbox serializes its complete ordered snapshot with a monotonic local
revision. Draft items contain plaintext only inside the protected record. Once a
message is sealed, the snapshot removes its plaintext and retains the exact
encoded ciphertext for idempotent upload retry.

Every mutation builds and protects a new snapshot before atomically replacing
the old file through `QSaveFile`. A failed encryption or write leaves the
previous in-memory and on-disk state unchanged. Authentication failure,
malformed lengths, duplicate object identifiers, invalid stages, or mismatched
sealed identifiers fail closed.

Content records deduplicate by the authenticated E2E object and plaintext, not
by Telegram message id. Reposting identical carrier bytes under another
Telegram id is harmless, while changing any protected content under the same
event id remains a conflict. Reload failure clears previously decrypted
in-memory records and returns the store to a not-loaded state.

The encrypted snapshot is bounded to 128 MiB and 4096 items. Attachments are not
copied into it; they use the encrypted file pipeline.

## Transactional MLS state

Every protected conversation has its own encrypted MLS provider snapshot and
monotonic local storage revision. The record identifies the exact engine and
storage format, contains the complete opaque provider state, and retains exact
outgoing-operation receipts while Telegram delivery is pending. Conversation
identity is authenticated both in the record and in its protection purpose, so
a valid state file cannot be swapped into another conversation.

Mutating crypto runs on an isolated candidate state. The candidate state,
request digest, operation identifier, and outgoing envelope are written as one
atomic protected record before the live engine adopts the state. Failed writes
leave both the old in-memory and on-disk ratchet authoritative. Committed
operation identifiers are idempotent and return their exact recorded envelope;
the same identifier with different content is rejected.

The current full-snapshot transaction is deliberately simple and bounded to
64 MiB of engine state and 128 MiB total. Performance and secure-deletion tests
at 500 participants decide whether a future encrypted write-ahead log is
needed. Such a change may optimize storage but may not weaken the single-commit
state-and-ciphertext invariant.

The inbound replay journal uses the same protected-record and atomic snapshot
boundary. It stores a bounded recent set of conversation/object identifiers,
payload hashes, and `pending` or `accepted` states. `Pending` survives a crash
between object application and journal commit and forces explicit recovery
instead of blind replay. MLS replay state remains authoritative for application
messages; the bounded transport journal is not an unbounded message archive.

Content delivery and control-response replay use separate journal domains. A
freshness response is placed in the protected outbox before its challenge is
accepted by the control journal, so either write can be retried after a crash.
An exact accepted challenge is never answered twice, including after restart.
Persisted outgoing MLS receipts are likewise reconciled with the exact inbound
journal entry before the receipt is removed.

## Cross-store group-change transaction

Group changes span records that cannot be replaced in one filesystem rename:
the OpenMLS provider, archive epochs, signed group ledger, and outgoing queue.
Before touching any of them, the client writes a purpose-bound encrypted
transaction containing their exact base revisions, signed transition, raw MLS
commit, archive distribution, candidate provider state, archive key, and—only
for locally created changes—exact outgoing envelopes.

Recovery replays each mutation idempotently and checks already-written values
byte-for-byte before continuing. The transaction is cleared only after every
required store commits. Incoming and first-Welcome transactions contain no
outbox envelopes, so recovery cannot republish remote objects. A first-Welcome
transaction is also allowed to initialize the archive store directly at the
current generation; older keys arrive only through authorized history grants.

An inbound own-removal transaction is the deliberate exception to archive
mutation. It atomically replaces provider state with a removal tombstone and
advances the signed group ledger without storing the archive key that was sent
only to the remaining roster. A later rejoin uses a fresh KeyPackage and keeps
the missing archive generation as a real access gap rather than fabricating or
copying a key.

## Out-of-order group-change inbox

The encrypted group-change inbox durably stages signed transitions, MLS
commits, and encrypted archive-key distributions by application object ID.
Telegram order is not trusted. The inbox assembles only the single next
generation whose referenced IDs and hashes match the signed transition;
multiple candidates at that generation are reported as a fork. Successfully
applied bundles are removed after the cross-store transaction clears. If a
crash occurs between inbox storage and replay-journal acceptance, recovery
recognizes the already staged payload hash and does not process the MLS object
twice.

## Rollback

The snapshot revision detects inconsistent in-memory updates but is not a
hardware monotonic counter. An attacker capable of restoring both local files
and operating-system secrets can roll back local state. Stable object identifiers,
idempotent ciphertext upload, protocol deduplication, and the remote freshness
gate limit consequences, but endpoint compromise remains outside E2E protection.
