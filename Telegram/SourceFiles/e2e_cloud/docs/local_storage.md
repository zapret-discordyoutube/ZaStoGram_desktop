# Protected Local Storage

## Key boundary

Local drafts, sealed retry envelopes, MLS state, and vault cache records are
protected under random local record keys derived or unwrapped only after the
account vault is unlocked. User password bytes never enter the local record
protector.

The operating-system credential adapter stores or wraps the local record key.
Failure to access that adapter leaves protected records locked. There is no
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

The encrypted snapshot is bounded to 128 MiB and 4096 items. Attachments are not
copied into it; they use the encrypted file pipeline.

The inbound replay journal uses the same protected-record and atomic snapshot
boundary. It stores a bounded recent set of conversation/object identifiers,
payload hashes, and `pending` or `accepted` states. `Pending` survives a crash
between object application and journal commit and forces explicit recovery
instead of blind replay. MLS replay state remains authoritative for application
messages; the bounded transport journal is not an unbounded message archive.

## Rollback

The snapshot revision detects inconsistent in-memory updates but is not a
hardware monotonic counter. An attacker capable of restoring both local files
and operating-system secrets can roll back local state. Stable object identifiers,
idempotent ciphertext upload, protocol deduplication, and the remote freshness
gate limit consequences, but endpoint compromise remains outside E2E protection.
