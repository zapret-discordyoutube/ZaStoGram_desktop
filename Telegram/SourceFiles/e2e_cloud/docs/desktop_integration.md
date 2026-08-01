# Desktop Integration

## Entry points

Telegram Desktop owns one `DesktopService` per signed-in `Main::Session`.
The main menu opens the protected-group surface. The service never shares
cryptographic state between Telegram accounts, and every local record path is
bound to the Telegram account identifier and random E2E conversation ID.

The first Desktop surface supports:

- creation and password unlock of the encrypted account vault in Saved
  Messages;
- creation of a new private Telegram carrier group as a protected group;
- automatic discovery and enrollment when the account sees an existing
  protected carrier group;
- encrypted text messages and arbitrary files;
- resumable file upload and authenticated file restoration;
- safety codes, automatic checkpoint witnesses, participants, roles, and
  history policy;
- owner/administrator role, removal, default-history, and per-member-history
  changes.

Stock Telegram message widgets are not reused for plaintext protected content.
ZaStoGram hides exact reserved carrier documents from the ordinary timeline and
shared-media index, replaces their preview with a generic encrypted-activity
label, and disables forwarding and clipboard export. A carrier peer shows one
full-width action that opens the protected conversation instead of Telegram's
text, attachment, voice, bot, edit, and forwarding controls. The protected
window is fed only from locally authenticated and decrypted records.

## Session state

Opening Protected Groups first performs one passwordless Saved Messages
document search for the reserved vault filename and verifies the exact MIME
type and size locally. It neither downloads carrier bytes nor walks the full
message history. Until the search finishes, neither the unlock form nor
new-identity creation is available. No matching carrier exposes the
create-and-confirm-password flow; a matching opaque carrier exposes the unlock
flow. Discovery never derives a password key or interprets carrier bytes. As
elsewhere, an active server can hide or fabricate first-contact metadata, so
the new-identity warning and the documented first-contact limitation still
apply.

Unlocking selects the newest valid cloud vault that is consistent with the
local rollback anchor. The password derives only a wrapping key; it never
becomes a message, archive, file, or local-record key. Locking destroys the
unlocked vault value, pending password bytes, group pipelines, and observable
per-conversation state. Version one remembers neither the password nor the
unlocked key across sessions. Manual E2E lock and Telegram's application
passcode lock both invoke the same cleanup path.

Each protected conversation owns independent instances of:

- OpenMLS provider state and application engine;
- signed group ledger and group-change write-ahead journal;
- archive epochs and history grants;
- exact-byte control and content outboxes;
- replay and inbound transaction journals;
- content index and newest observed Telegram message boundary;
- resumable file-transfer state and encrypted chunk store;
- freshness trust and current safety-gossip witnesses;
- Telegram control and content carrier adapters.

Content status is stored per conversation. Activity or a transport failure in
one protected group cannot make another group appear synchronized, stale, or
failed. The shared reactive signal is only an invalidation notification; every
window rereads its own conversation state.

Presentation recognition is deliberately separate from protocol acceptance.
Exact filename/MIME metadata is sufficient to suppress or block the plaintext
Desktop surface, because confidentiality takes priority over availability. It
is never sufficient to decrypt, index, admit a participant, or advance state.
An active server can fabricate the metadata and deny ordinary composition, but
the authenticated protocol pipeline will reject fabricated bytes.

## Cloud synchronization

Saved Messages contains versioned opaque vault containers. A vault update is
prepared locally, uploaded byte-for-byte, selected again from Telegram, and
committed to the local rollback anchor before it becomes authoritative.
Conversation-index updates therefore precede publication of newly prepared
group objects.

The private carrier group uses two generic document names:

- `protected-control.tde2e` for bootstrap, credentials, KeyPackages, MLS
  changes, archive distributions, history grants, freshness, and safety gossip;
- `protected-content.tde2e` for MLS application descriptors, encrypted bodies,
  manifests, and encrypted file chunks.

Control backfill accepts at most 65,536 matching objects and 512 MiB in one
bounded reconstruction. This accommodates the 500-participant target including
admission artifacts and safety traffic. The signed ledger itself has the same
65,536-generation version-one lifecycle bound. A later protocol version needs
signed state snapshots before raising either bound.

Content synchronization is paged and records a monotonically advancing newest
observed Telegram message boundary. Every page remains untrusted. Telegram
message IDs determine only where to resume scanning and never authorize,
identify, or order protected content.

## Sending and freshness

A new installation may unlock, read locally authorized archive history, and
compose immediately. The first outgoing message or administrative operation
requires a fresh signed checkpoint response from any active client of any
current participant.

If confirmation is pending, outgoing plaintext is transformed only inside the
protected local transaction and exact retry bytes remain queued. Telegram sees
no new protected content. A newer witness checkpoint triggers group
resynchronization; an equal-generation different hash blocks the vault as a
fork. Administrative controls are shown only when both E2E permission and the
freshness gate allow the operation.

## Files

The Desktop sender hashes the source before allocating file encryption
material, records a canonical encrypted manifest, and encrypts independent
1 MiB chunks. The persistent transfer record contains the next chunk index and
source identity, so a restart resumes without nonce reuse. Every chunk is also
account-signed and bound to its Telegram sender, conversation, group generation,
file ID, and index.

Saving a file reads only authenticated local chunks, decrypts them in order to
a `QSaveFile`, verifies total length and the full plaintext SHA-256 digest, and
atomically commits the destination only after all checks pass.

## Mobile reuse boundary

Mobile clients reuse the wire formats, Rust OpenMLS bridge, account vault,
group/transaction engines, archive, files, and negative vectors. They replace
only the Telegram transport adapter, protected local-storage adapter,
unlock-session integration, background scheduling, and product interface.
No Desktop device pairing or simultaneous Desktop connection is required.
