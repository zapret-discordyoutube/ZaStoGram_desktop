# File Storage

## Data model

Every file is an arbitrary byte stream. Encryption does not depend on the file
extension or MIME type.

A file object contains:

- a random file identifier;
- a random file content key;
- an encrypted and authenticated manifest;
- ordered ciphertext chunks;
- authenticated chunk sizes and hashes;
- an authenticated total size and chunk count that detect truncation.

The encrypted manifest contains the original file name, declared MIME type,
plaintext size, chunk layout, and any future preview metadata. Telegram-visible
names and MIME types must be generic and must not reveal the original metadata.

The version-one private manifest plaintext is a canonical `TDE2EFMF` record. It
contains the conversation and file identifiers, file key, total size, chunk
layout, nonce prefix, full plaintext SHA-256 digest, bounded UTF-8 basename, and
bounded declared MIME value. This record is never a Telegram document by
itself: it must first be encrypted as authenticated group/archive content. The
decoder rejects path separators, dot path components, NUL, CR/LF MIME injection,
unknown versions, inconsistent layouts, and trailing bytes.

## Encryption

Version one assigns every file a random 256-bit AES key, random 256-bit file
identifier, and random 64-bit nonce prefix. Each chunk uses AES-256-GCM with the
prefix followed by its 32-bit unsigned index. The authenticated fixed header
binds the conversation and file identifiers, total plaintext size, chunk size
and count, nonce prefix, index, and exact plaintext length. Chunks are limited
to 4 MiB and the layout is validated before encryption or allocation.

Recomputing the same chunk with unchanged material is deterministic, which
supports exact resume, but the upload pipeline must not rely on that alone. A
protected persistent nonce ledger records the first plaintext digest or exact
ciphertext allocated to each `(file key, chunk index)`. Retry re-uploads that
persisted ciphertext. If the source file changes, the pipeline starts a new
file identifier and key instead of reusing any nonce. Desktop keeps the failed
transfer until the user selects a replacement; replacement is one authenticated
local transaction, so persistence failure cannot erase the previous cursor.

## Telegram storage

Ciphertext chunks are uploaded as ordinary Telegram documents or another
supported opaque carrier. The transport adapter owns Telegram size limits,
retry, resume, and reference expiry. Cryptographic file identity must not depend
on a mutable Telegram file reference.

Each new file uses a distinct carrier name derived from its random 256-bit file
identifier. Ordinary message synchronization therefore fetches manifests but
not bulk ciphertext. Chunks are fetched only after an explicit Save request;
the client verifies every signed envelope and authorization before placing it
in the bounded encrypted cache. A missing or malicious stream cannot make the
client scan before the manifest, retain more than 16 MiB in one page, or exceed
the manifest-derived total download budget.

The current Desktop pipeline uses 1 MiB chunks. Each stored chunk is wrapped in
an account-signed content envelope that binds the carrier group, conversation,
protected generation, sender account/client, file identifier, chunk index and
count, ciphertext hash, and exact ciphertext. This provides sender binding even
though the chunk is independently encrypted rather than an MLS application
message. When the sender later observes its own carrier, local deduplication
compares the exact ciphertext bytes. It deliberately does not compare the
ledger's plaintext digest with the envelope's ciphertext digest because those
fields have different meanings.

The authenticated manifest is published and acknowledged before the first
chunk. A receiver persists a protected local authorization record derived from
that manifest and accepts a chunk only when its file identifier, layout,
sender, client, generation, and authenticated ciphertext agree with the
manifest. Unknown or malformed chunks are discarded without creating files.
Exact manifest duplicates retain their earliest positive Telegram message
identifier in the protected content index. Chunk download uses that identifier
as its exclusive lower search boundary, so a later duplicate cannot hide
chunks published after the original manifest.
During history synchronization, manifests are previewed while Telegram pages
are scanned and ordinary content is still replayed oldest-first. This preserves
files written by the earlier chunk-first sender without reopening orphan-chunk
storage.

Version one limits a protected file to 4 GiB. The Desktop ciphertext cache is
also bounded to 8 GiB and refuses a write that would leave less than 1 GiB free
on its filesystem. Reaching either storage boundary drops additional remote
chunks rather than allowing an authenticated participant to exhaust the local
disk. The limits apply to bytes and not extensions; arbitrary file types remain
supported.

Global plaintext deduplication is excluded because it leaks equality across
conversations. Any future conversation-local deduplication requires an explicit
privacy review.

## Opening files

Successful decryption proves integrity, not safety. A legitimate participant
can send malware. Clients must sanitize file names, prevent path traversal,
respect operating-system quarantine facilities, and avoid automatically opening
active content.

Desktop restoration writes through `QSaveFile`, decrypts chunks in order, and
commits the destination only after the manifest's total size and full plaintext
SHA-256 digest match. The encrypted manifest list exposes every locally
authorized file rather than relying on Telegram-visible filenames. Local chunk
ledger reads validate the protected file length before allocation, so a damaged
or oversized ledger file fails closed without consuming memory proportional to
its claimed filesystem size.

Save is asynchronous when chunks are not cached. Only one file download per
protected conversation runs at a time, and the UI reports success only after
the atomic destination commit. Retryable transport failure, missing chunks,
pagination manipulation, quota exhaustion, or digest failure leaves no partial
destination file.

Previews must be generated locally from authenticated plaintext. The client must
not upload plaintext thumbnails or media metadata to Telegram.
