# Desktop Integration

## Entry points

Telegram Desktop owns one `DesktopService` per signed-in `Main::Session`.
The main menu opens the protected-group surface. The service never shares
cryptographic state between Telegram accounts, and every local record path is
bound to the Telegram account identifier and random E2E conversation ID.

The first Desktop surface supports:

- creation and password unlock of the encrypted account vault in Saved
  Messages;
- creation of a new private Telegram supergroup as a protected group, avoiding
  the basic-group participant ceiling and later automatic migration;
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
Reserved vault metadata is recognized only in Saved Messages, and reserved
group metadata only in basic groups or supergroups. A same-named ordinary file
in a direct chat or broadcast channel therefore remains an ordinary file.
Once a group is authenticated or restored as protected, an account-local
durable peer marker permanently keeps Telegram's ordinary composer disabled for
that peer, including before vault unlock and after carrier messages are unloaded
or deleted. A basic-group marker is inherited and durably recorded by its
migrated supergroup peer before Telegram's current peer classification is
trusted. An authenticated marker also takes precedence if the server later
classifies that peer as a broadcast channel. Markers are monotonic and are
never removed by server-visible history changes. A malformed local marker
record conservatively disables ordinary composition for all group peers until
the protected state can be repaired. Reserved metadata alone blocks the
currently observed peer but does not create a durable marker before
cryptographic verification.

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
apply. A search that receives no Telegram result within 15 seconds is cancelled
and exposed as a retryable discovery error instead of leaving the modal in an
unbounded checking state.
Opening a surface that previously observed no vault repeats discovery, because
another device may have created the identity meanwhile. Create also performs a
fresh passwordless preflight before generating identity keys; a newly observed
vault switches the form to password unlock without publishing a competing
identity.

Unlocking selects the newest valid cloud vault that is consistent with the
local rollback anchor. The password derives only a wrapping key; it never
becomes a message, archive, file, or local-record key. Locking destroys the
unlocked vault value, pending password bytes, group pipelines, and observable
per-conversation state. Version one remembers neither the password nor the
unlocked key across sessions. Manual E2E lock and Telegram's application
passcode lock both invoke the same cleanup path.

Each protected conversation owns independent instances of:

- OpenMLS provider state and application engine;
- signed group ledger, group-change write-ahead journal, and durable
  out-of-order inbox;
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
After vault unlock and local-group recovery, Desktop also checks already loaded
group histories for protected carrier metadata and queues their normal
authenticated discovery. A carrier received while the vault was locked is
therefore not forgotten merely because Telegram does not emit it as a new item
again. This is a local loaded-state check, not an unbounded server-history scan.

## Cloud synchronization

Saved Messages contains versioned opaque vault containers. A vault update is
prepared locally, uploaded byte-for-byte, selected again from Telegram, and
committed to the local rollback anchor before it becomes authoritative.
Newly prepared group objects are published before a conversation-index update
can reference them. A crash after carrier publication but before the vault
update resumes the exact local outbox or the pending locally-ahead checkpoint.

The private carrier group uses two generic document names:

- `protected-control.tde2e` for bootstrap, credentials, KeyPackages, MLS
  changes, archive distributions, history grants, freshness, and safety gossip;
- `protected-content.tde2e` for MLS application descriptors, encrypted bodies,
  manifests, and encrypted file chunks.

Bootstrap discovery retains only the immutable genesis, owner credential, and
initial MLS public object. Join catch-up retains only transition, KeyPackage,
Welcome, archive, and grant material. The accepted join material is copied into
a bounded encrypted inbox together with its observed Telegram sender before the
Telegram scan boundary advances. A restart therefore resumes from the saved
boundary without replaying unrelated freshness and safety traffic. Existing
active groups use the same durable inbox for incomplete next-generation
transitions.

One reconstruction accepts at most 65,536 relevant objects and 512 MiB; the
durable inbox is additionally bounded for the 500-participant target. The
signed ledger itself has the same 65,536-generation version-one lifecycle
bound. A later protocol version needs signed state snapshots before raising
either bound.

Content synchronization is paged and records a monotonically advancing newest
observed Telegram message boundary. Every page remains untrusted. Telegram
message IDs determine only where to resume scanning and never authorize,
identify, or order protected content.

The Desktop conversation initially decrypts and renders only the newest 200
authenticated local records. An in-place older-history action expands that
window in 200-record pages without discarding or redownloading the earlier
synchronized archive. The separate files view uses the same bounded paging;
opening either view no longer copies and sorts the complete decrypted history.

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

The sender never races a running control reconstruction. A control carrier
noticed during an upload marks the group dirty; the already sealed item may
finish, then file chunks, new messages, and administrative changes pause until
the control chain is synchronized. A freshness challenge starts one control
observation after publication. If no witness has answered yet, the client waits
for a live control item or an explicit synchronization request instead of
polling the complete history in a tight loop.

## Files

The Desktop sender hashes the source before allocating file encryption
material, records a canonical encrypted manifest, and encrypts independent
1 MiB chunks. The persistent transfer record contains the next chunk index and
source identity, so a restart resumes without nonce reuse. Every chunk is also
account-signed and bound to its Telegram sender, conversation, group generation,
file ID, and index.

If the source disappears or changes, the pending transfer remains available for
retry. Selecting a replacement file atomically commits a new transfer with a
new file identifier and key; a failed replacement write leaves the prior
transfer intact.

Saving a file reads only authenticated local chunks, decrypts them in order to
a `QSaveFile`, verifies total length and the full plaintext SHA-256 digest, and
atomically commits the destination only after all checks pass.
Its deferred completion remains bound to the lock epoch and manifest event that
started the request, so a result queued before lock cannot affect a new Save
operation after the same conversation is restored.

## Mobile reuse boundary

Mobile clients reuse the wire formats, Rust OpenMLS bridge, account vault,
group/transaction engines, archive, files, and negative vectors. They replace
only the Telegram transport adapter, protected local-storage adapter,
unlock-session integration, background scheduling, and product interface.
No Desktop device pairing or simultaneous Desktop connection is required.
