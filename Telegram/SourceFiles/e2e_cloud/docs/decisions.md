# Decision Record

## 2026-07-31

### D001: New protected group

Create a new protected-group mode backed by a private Telegram carrier
supergroup. Do not initially convert existing groups or create protected
subrooms.

### D002: Telegram-only remote infrastructure

Use Telegram for all remote delivery and encrypted blob storage. Operate no
custom backend.

### D003: Active-server threat target

Protect established keys, membership, and state transitions against active
server manipulation. State the unavoidable first-contact and availability
limitations of a Telegram-only design.

### D004: TOFU identity bootstrap

Use trust on first use, signed key gossip, and a human-readable safety code.
Warn prominently on unexpected key changes. Out-of-band comparison is optional.

### D005: No stock-client plaintext

Accounts using stock clients receive no cryptographic keys. There is no
plaintext compatibility mode.

### D006: Password-unlocked account vault

Use one user-memorized E2E password per account to unlock a random account vault
master key. Version one does not remember the password or unlocked vault key in
an operating-system credential store. Keep them only for the unlocked process
session, cleanse owned password buffers on every failure or lock, and lock the
vault automatically when the application passcode locks. New vaults require at
least 12 Unicode characters; old vaults remain unlockable without changing
their password bytes.

### D007: No server password recovery

Password loss creates a new E2E identity. Group owners or E2E administrators may
admit that identity and regrant history allowed by policy.

### D008: Configurable history admission

Provide a signed group default plus a per-invitation override. Support no
history, history from join, history from a boundary, and full history.

### D009: E2E administration

The group owner and explicitly appointed E2E administrators may manage E2E
admission and history policy. Telegram administrator status alone is not enough.

### D010: Replaceable MLS implementation (superseded by D024)

Define an implementation-independent engine boundary and require RFC 9420
vectors, interoperability, fuzzing, and security review before production use.
The original deferral of the concrete implementation is superseded by D024;
the boundary remains.

### D011: Initial scale target

Validate groups containing 500 participant accounts and multiple concurrent
client instances without encoding 500 as a protocol maximum.

### D012: Freshness gate before first send

Allow a new installation to unlock its vault, read available history, download
ciphertext, and compose messages before another participant confirms freshness.
Keep composed messages in a protected local queue. Send no new content and allow
no security-critical E2E administration until any current installation of any
participant returns a valid response to a fresh challenge. Encrypt and upload
the queue only against confirmed current group state.

### D013: Fixed-order version-one envelope

Encode the application transport envelope as a bounded fixed-order binary
structure with unsigned big-endian integers. Reject unknown versions, malformed
lengths, identifier mismatches, and trailing bytes. Keep MLS wire messages
opaque inside the payload and authenticate carrier binding through the
object-specific MLS authenticated data or signature.

### D014: Authenticated history boundary

Represent a `Since` history grant with the stable object identifier of an
authenticated archive event. Dates remain a user-interface selection aid and
are never the signed authorization boundary.

### D015: Capability-scoped E2E administrators

Only the E2E owner appoints administrators and assigns their explicit
capabilities. Default administrators may admit and remove ordinary members,
grant bounded history, and change bounded defaults. Granting full history is a
separate opt-in capability. Telegram roles never assign these capabilities.

### D016: E2E owner remains authoritative

If Telegram carrier ownership diverges from protected ownership, retain the E2E
owner as cryptographic authority and show a security warning. The carrier owner
may still delete or censor transport objects and cause denial of service but
does not gain keys, roles, or history access.

### D017: Unsupported carrier members remain pending

Show Telegram members without a verified protected credential as pending or
unsupported. They are not protected members, do not receive keys, and never
trigger plaintext fallback.

### D018: Canonical protected-group transitions

Encode each version-one group transition as a fixed 185-byte payload. Require a
single canonical value for unused fields, exact generation increments, unique
transition identifiers, an active actor client, and state-level authorization
after cryptographic verification.

### D019: Mandatory MLS 1.0 suite first

Start version one with cipher suite `0x0001`,
`MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`, which every MLS 1.0 client must
implement. Keep suite and credential versions explicit so a reviewed hybrid
post-quantum migration can replace it later without transport negotiation.

### D020: Stable account authorization, distinct MLS keys

Use a stable Ed25519 account key to authorize client credentials and a stable
X25519 archive HPKE key for granted history. Derive the account identifier with
domain-separated SHA-256 over the canonical public credential. Never reuse the
account signing key as a per-group MLS leaf key.

Pairwise safety codes hash the sorted account identifiers. Group safety codes
hash the conversation identifier, E2E owner, and sorted active account roster.
Display 240 bits as grouped Crockford Base32 and retain the full digest for QR
comparison.

### D021: Purpose-bound encrypted local records

Protect local outbox and state snapshots with AES-256-GCM under a random local
record key obtained after vault unlock. Generate a new 96-bit nonce per write,
authenticate the versioned header and record purpose, cleanse owned key material,
and atomically replace only ciphertext files. Never derive this record key
directly from the password and never fall back to plaintext storage.

### D022: Opaque document carrier with two-stage acknowledgement

Carry every version-one protocol envelope as an ordinary Telegram document
whose bytes are the exact encoded envelope. Use the fixed control/content
filenames defined by D035, MIME type `application/octet-stream`, an empty
caption, no preview, and no original application-file metadata. Treat both
upload and `messages.sendMedia` as one transport operation. Remove an outbox
item only after the final send RPC succeeds; an uploaded file token alone is
not delivery.

Downloaded documents remain untrusted byte strings until the protocol codec,
carrier binding, signature or MLS authentication, generation rules, and replay
state accept them. Telegram message identifiers and document identities never
become protocol object identifiers.

### D023: Independently authenticated resumable file chunks

Encrypt file content with a new random 256-bit key per file. Use AES-256-GCM
independently for each chunk. Construct its 96-bit nonce from a random 64-bit
per-file prefix followed by the unsigned 32-bit chunk index. Authenticate the
conversation identifier, random file identifier, total plaintext size, chunk
size and count, nonce prefix, index, and exact chunk plaintext length.

The encrypted private manifest carries the key, nonce prefix, full plaintext
digest, layout, original filename, and original MIME value. None of those
private metadata values are copied into Telegram document metadata. A
persistent nonce ledger must retain the exact ciphertext or plaintext digest
for every allocated `(file key, chunk index)` before upload; changed source
bytes may never be encrypted under an already allocated nonce.

### D024: OpenMLS production engine

Use the MIT-licensed OpenMLS `0.8.1` code line at upstream commit
`0e99bc8814d136f0bc7bc9ce86dd288eb32273ed` behind a narrow versioned C ABI.
That commit carries the upstream July 2026 HPKE and cryptographic dependency
updates. Enable only RFC 9420 cipher suite `0x0001` and the RustCrypto provider
for version one. Do not expose draft protocol extensions. Rust ownership, panics,
allocations, and library types never cross the ABI; callers exchange bounded
byte strings and numeric status codes.

OpenMLS is selected because its `StorageProvider` is designed to persist the
complete long-lived group state after successful operations and the upstream
project builds the required desktop targets plus future Android and iOS
targets. The evaluated unmodified Cisco MLS++ interface does not expose a
supported complete persistence format for all private TreeKEM, key-schedule,
and sender/receiver ratchet state. Maintaining a private serialization fork of
cryptographic internals is a larger and less reviewable risk.

The pin is a dependency baseline, not a claim that the application is ready for
production. Updating it requires review of security advisories, storage-format
changes, RFC vectors, differential interoperability against an independent MLS
implementation, fuzzing, and migration tests. The bridge build pins Rust 1.91
and a checked Cargo lockfile so the toolchain and transitive graph do not drift.

The earlier release-tag dependency graph was rejected after RustSec reported
six vulnerabilities in the selected cryptographic transitive graph. The
replacement lockfile has no reported vulnerability as of 2026-07-31. Its sole
maintenance warning is an unmaintained build-time proc-macro reached through
the verified SHA3 implementation; it is tracked but is not runtime crypto code.

### D025: Transactional MLS state and outgoing bytes

Run every mutating MLS operation against an isolated copy of the current
per-conversation provider state. The engine returns a candidate state snapshot
and any exact outgoing wire message without publishing either. Commit the new
snapshot, request digest, operation identifier, and complete outgoing envelope
as one purpose-bound encrypted atomic local record. Only then may the in-memory
state advance or Telegram upload begin.

A failed local commit leaves the previous provider state authoritative and
exposes no candidate ciphertext. A retry with an already committed operation
identifier returns the recorded exact envelope. Reusing that identifier with a
different request digest or ciphertext fails closed. Receipts remain until the
outbox acknowledges Telegram delivery; stale receipts may be compacted only
after the outbox no longer references them.

### D026: Transactional inbound MLS plaintext

Process every incoming MLS message against an isolated provider copy. Commit
the resulting provider snapshot and the authenticated decrypted application
record in one encrypted atomic local write before releasing plaintext. A
separate replay journal may remain pending across that write: restart recovery
checks the committed application record and either delivers it without replay,
retries an operation known not to have committed, or fails closed when neither
state can be proven. Never process uncertain ciphertext twice against a mutable
receiver ratchet.

### D027: Strict archive boundaries

Every retained archive epoch records its own monotonically increasing archive
generation, the protected-group generation at which it became active, and the
authenticated event identifier that activated it. Rotate the archive epoch on
each admission, removal, and history-policy boundary. `FromJoin` grants begin
only at an epoch whose activation generation exactly equals the member's join
generation. `Since` accepts only an archive-activation event, never an arbitrary
Telegram timestamp or an event in the middle of an epoch. The interface may
resolve a requested date to the nearest later safe boundary, but may not grant
an earlier epoch and silently reveal extra history.

Persist archive keys in a purpose-bound encrypted atomic snapshot. Importing a
history grant is idempotent only when every repeated generation has identical
activation metadata and key bytes; any conflict blocks the conversation for
recovery rather than replacing a key.

### D028: Signed group chain binds MLS and archive state

Every transition signs its predecessor checkpoint, canonical protected
mutation, actor account/client, exact MLS object ID and hash, next archive-key
commitment, encrypted archive-distribution object ID and hash, and any target
client authorization. A transition is accepted only after the account
signature, MLS sender/AAD, archive key, and resulting OpenMLS roster all agree.
Telegram cannot substitute a participant, commit, or archive key independently.

### D029: One recoverable transaction across group stores

Persist each group change through an encrypted write-ahead transaction spanning
the OpenMLS provider, archive epoch store, signed group ledger, and—only for a
local change—outbox. Recovery checks base revisions and exact already-written
values and replays only missing steps. Inbound and first-Welcome transactions
never contain outgoing envelopes. A new member initializes its local archive at
the current epoch and obtains any older authorized epochs through history
grants.

### D030: Telegram delivery order is untrusted

Stage signed transitions, commits, and archive distributions in a bounded
encrypted inbox keyed by stable application object identifiers. Assemble only
the unique next-generation bundle whose signed IDs and hashes match. Preserve
the bundle over restart, accept exact duplicates, treat object-ID reuse as a
conflict, and report multiple next-generation transitions as a fork. Never use
Telegram message order as protocol order.

### D031: Every protected transition advances MLS and archive epochs

Admissions use an MLS add commit, removals use one batch remove commit, and
role, ownership, and history-policy changes use an MLS self-update commit.
Every protected generation also creates a new archive epoch whose key is sent
inside an MLS application message after the commit. Keeping these three
generations aligned removes ambiguous unsigned policy boundaries and ensures a
removed client cannot decrypt the next archive key.

### D032: Account-signed freshness and identity gossip

A freshness response signs the random nonce, exact challenged checkpoint,
witness checkpoint, and witness account/client under the stable account key.
Only a client active at the challenged generation is a valid witness. Equal
checkpoints open sending, newer checkpoints force resynchronization, and an
equal-generation different hash signals a fork.

Identity gossip signs a checkpoint plus the sorted Telegram-user, account-ID,
and credential-hash observations for the full protected roster. Valid gossip
is compared with the reconstructed local state at that generation. A mismatch
creates a security event and never replaces a TOFU pin automatically. Telegram
can still censor all witnesses and preserve permanent isolation.

### D033: Own removal destroys active MLS state

After a valid removal commit excludes the local client, atomically replace its
active OpenMLS provider state with a protected tombstone bound to the signed
transition, resulting checkpoint, commit hash, account, and client. Advance the
signed group ledger but do not decrypt or append the new archive epoch. A later
admission requires a fresh account-authorized KeyPackage and Welcome. Preserve
the absent archive generations as an explicit access gap, and authenticate
stored content against the exact protected generation that activated its epoch.

### D034: KeyPackages are bounded, one-time admission tickets

Each client publishes account-signed, conversation-scoped KeyPackages for one
exact protected-group generation. Their MLS lifetime is 84 days and renewal
starts seven days before expiry or immediately after a generation change.
Still-valid replaced private packages remain in a bounded encrypted local pool
until a Welcome consumes one or they expire. Telegram stores only the signed
public publication and may suppress it, but cannot substitute a package,
move it to another protected conversation, or make a stale-generation package
authorize admission.

### D035: Separate control and content carrier streams

Use `protected-control.tde2e` for group authority, credentials, KeyPackages,
freshness, and safety gossip, and `protected-content.tde2e` for encrypted
messages, MLS content descriptors, and file manifests. File chunks use the
per-file carrier selected in D041. Keep every stream in the same private
Telegram carrier group with the same generic MIME type and empty caption. This
lets content use a protected incremental observation boundary without allowing
Telegram message order to become group authority.

### D036: Signed deterministic checkpoint gossip

After observing a current group checkpoint, each active account/client publishes
at most one deterministic account-signed gossip object for that checkpoint.
Count distinct reporter accounts as automatic witnesses. A valid future
checkpoint, equal-generation fork, or credential/Telegram binding conflict
blocks security-sensitive operation; malformed or unauthenticated gossip is
ignored. Human group, account, and pairwise safety codes remain available for
out-of-band comparison.

### D037: Desktop administration uses canonical transitions

Expose member removal, owner-controlled role changes, signed default-history
changes, and per-member history changes in the Desktop protected-group surface.
Do not mutate UI or Telegram membership as authority. Every action first passes
the freshness gate and protected capability checks, then uses the existing
OpenMLS removal or policy-change engine, archive rotation, write-ahead
transaction, exact-byte outbox, and vault-checkpoint update. A per-member
history change includes its HPKE history grant in that prepared transition.

### D038: Bound version-one large-group reconstruction

Permit at most 65,536 matching control objects and 512 MiB in one public
bootstrap/discovery/group-change reconstruction. Keep the signed local ledger
at the same 65,536-generation limit and retain the 4,096-member protocol ceiling
while testing for 500 participants. These are denial-of-service and lifecycle
bounds, not target group sizes. A protocol version that needs longer-lived
groups must add reviewed signed state snapshots and compaction instead of
silently increasing untrusted memory.

### D039: Fail-closed Desktop carrier interface

Recognize carrier presentation only by the reserved legacy/control/content or
vault filename together with the exact generic MIME type. Hide recognized
carrier objects from protected-client history elements and shared media, expose
only a generic encrypted-activity preview, and disallow forwarding or clipboard
export through ordinary message actions.

When a Telegram peer is mapped to an authenticated protected conversation, or
its loaded history contains reserved group-carrier metadata, replace the entire
ordinary compose surface with one action that opens the protected interface.
This blocks text, attachments, voice messages, bot commands, forwarding, and
editing through the plaintext Telegram sender. A matching unverified carrier
can therefore cause a local availability failure, but it cannot make the client
downgrade to plaintext. Cryptographic processing never trusts this UI marker;
the envelope, peer binding, signature, MLS state, and replay checks remain
authoritative.

### D040: Discover before asking for a vault password

Do not assume that a protected identity exists when the Desktop service is
constructed. On first opening the protected surface, issue one bounded Saved
Messages document search for the reserved vault filename without a password,
then verify the exact MIME type and size locally. Do not download carrier bytes
or walk the complete history during discovery. Show identity creation only
after an empty result and show password unlock only after a carrier is present.
Discovery never parses or accepts the encrypted bytes and cannot bypass normal
vault selection after password entry. Retryable discovery failure exposes only
a retry action, not an unsafe create-or-unlock guess.

### D041: Fetch file ciphertext only on explicit Save

Publish each new encrypted chunk under an exact carrier filename derived from
the manifest's random file identifier. Do not route this carrier into ordinary
content observation. An explicit Save performs a bounded, manifest-authorized
search after the manifest message, verifies and caches only matching chunks,
and atomically reconstructs the plaintext after all chunks arrive. Keep a
bounded `protected-content.tde2e` fallback for chunks uploaded by older clients.
This prevents a large file or hostile member from turning every chat refresh
into gigabytes of automatic downloads without changing Telegram's role as the
only opaque remote store.

### D042: Ambiguous Telegram searches fail closed

Treat `messages.messagesNotModified` as an unexpected retryable transport
failure for protected-carrier searches because every such request uses a zero
hash. Never interpret it as an empty result or a completed history page. During
passwordless vault discovery, accept absence only from a complete
`messages.messages` response or from a slice whose declared total equals the
returned first page. A malformed count or a partial first page without a valid
vault carrier exposes Retry only, never identity creation. The same malformed or
not-modified responses interrupt protected history synchronization instead of
silently truncating it.

Every MTP search response must also contain no more messages than the requested
page limit. Enforce the same limit again in every pagination controller before
parsing, retaining, or authenticating an object so future transport adapters
cannot accidentally weaken the boundary.

### D043: KeyPackage tickets commit to the Telegram author

Derive every client KeyPackage publication object ID from its conversation,
account, client, generation, account credential, KeyPackage bytes, and the
publishing Telegram user ID. The account authorization signs that object ID.
Before automatic admission, recompute the ID using the Telegram sender observed
for the carrier message and reject any mismatch. This prevents an active server
from transplanting a valid Alice publication into a message attributed to Bob.

This binding does not remove the first-contact limitation: Telegram can still
present a consistently false account view before any identity is pinned. It
does prevent independent relabeling of already signed package bytes. Legacy
pending joins with an unbound ticket generate and publish a new bound ticket on
local recovery; old unbound publications are never admitted.

### D044: New installations require a complete visible vault chain

When no local vault anchor exists, accept the Telegram history only if the
decrypted candidates start at generation one and every subsequent generation
increments by one and names the exact previous blob digest. Reject a missing
genesis, an internal gap, a duplicate generation, or a transition between
parallel branches. An existing local anchor continues to permit older history
before the anchor while requiring an exact contiguous suffix from it.

This does not solve absolute rollback on a new installation. Telegram may still
show a complete stale prefix ending before the real latest generation. The rule
does ensure that suppression cannot be hidden inside the visible history and
that the selector never assembles a newest vault from incompatible branches.

### D045: Deferred MLS content cannot advance synchronization

Stop content replay when an authenticated MLS application reports a deferred
result. Return a retry-required completion and keep the previous persisted
Telegram boundary unchanged. On a later run, replay the complete suffix and
rely on object IDs and the inbound journal to skip applications that were
already committed before the deferred object.

Never classify a deferred application as ignored. The overlap retains only a
bounded recent suffix, so advancing the boundary after a deferred object could
make older ciphertext permanently unreachable even though its failure was
explicitly retryable.

### D046: Exact manifest duplicates retain the earliest carrier position

Keep the minimum positive Telegram message identifier observed for identical
authenticated content in the protected content index. A newer duplicate must
not replace the original manifest position: file chunks are published after
the original manifest, so using the duplicate as the exclusive search boundary
could permanently exclude valid chunks between the two copies.

The identifier remains an untrusted transport hint and is not included in file
identity, signatures, or encryption context. Updating it rewrites only the
authenticated index, leaving the immutable content record and its hash
unchanged. Legacy file-manifest indexes migrate to the conservative boundary
one so already stored files remain recoverable even when an older client kept
only a later duplicate position.

### D047: Manifest authorization failure stops content synchronization

Advance content synchronization past a file manifest only after both its
immutable content record and protected chunk authorization are durable. Treat
authorization quota exhaustion like any other local persistence failure rather
than silently reporting the manifest as processed. A later retry may reuse the
already stored content record and finish authorization without losing the
manifest behind the saved Telegram boundary.

Chunk-cache quota exhaustion during an explicit Save remains a bounded download
failure: it cannot advance ordinary content synchronization and the user may
retry after recovering local capacity.

### D048: Publish-state durability precedes manifest outbox removal

After Telegram accepts the final MLS manifest envelope, persist the file
transfer's `manifestPublished` state before removing that exact envelope from
the protected outbox. If this pre-acknowledgement persistence step fails, keep
the exact bytes queued and retry them with the same Telegram random identifier.
Unrelated queued messages do not prevent this transition.

Never regenerate a manifest pair merely because its final local state write
failed. The archived content preparation uses fresh randomized encryption, so
regeneration under the same event and content object identifiers would create
competing authenticated hashes and security-block recipients. Chunks start only
after the durable publish state proves the final manifest envelope was accepted.
The same pre-acknowledgement rule applies when a restarted active group drains
its persisted outbox through startup recovery, and successful group observation
must resume a pending chunk transfer even when that outbox is already empty.

### D049: Release durable file-chunk cache entries after use

Keep an outgoing chunk's exact ciphertext until Telegram accepts it and the
next chunk cursor is durably committed. Then remove that cache entry. After a
downloaded file is fully authenticated, atomically saved, and hash-verified,
remove its cached chunks while retaining the small manifest authorization.

Removal is idempotent and best-effort after the durability boundary. A failed
cleanup cannot invalidate a completed upload or saved output, while successful
cleanup returns the protected bytes to the bounded cache quota. Retaining the
manifest authorization allows a later Save to authenticate freshly downloaded
chunks without reprocessing chat history.

### D050: A new file cannot replace an unfinished transfer

Reject a new protected-file send while the conversation has a durable pending
file transfer. Perform this check before hashing the selected source so a busy
conversation does not synchronously scan an unrelated file.

Never replace the persisted transfer implicitly. Its manifest or some of its
chunks may already be present in Telegram, and replacing its local cursor would
make that authenticated file permanently incomplete while leaving no state from
which upload recovery could resume.

### D051: Full-file hashing never blocks the interface thread

Hash a newly selected source on a worker before creating its durable transfer.
Keep the prepared path and digest attached to the conversation while control
synchronization finishes, then construct the manifest from the latest accepted
group state. Reject another file selection until that preparation is consumed.

Do not synchronously hash the same source again before queuing its manifest; a
size and readability check is sufficient because chunk encryption reads the
source afterward and recipients verify the manifest's full plaintext hash. Once
all chunks are accepted, verify the source hash again on a worker before clearing
the durable transfer. Operation epochs and transfer identity prevent late worker
results from mutating a relocked or different conversation state.

### D052: Saved files are assembled cooperatively

After all encrypted chunks are available, decrypt, hash, and append one chunk
per interface-loop turn instead of assembling the complete file in one call.
Keep the manifest, digest context, and atomic output owned by the pending Save
operation, and bind every continuation to its event object and operation epoch.
Discover cached chunks with bounded filesystem metadata probes; authenticate
their full local records only when the cooperative writer consumes each chunk.

Commit the destination only after the reconstructed plaintext size and SHA-256
match the authenticated manifest. Release cached chunks afterward in bounded
batches, then report success. Cancelling, locking, or destroying the group drops
the pending atomic output without exposing a partial destination file.

### D053: File-transfer cancellation is durable and explicit

Allow the user to cancel an unfinished outgoing file after confirmation. First
persist `cancelRequested` in the protected transfer snapshot. A cancelled
transfer cannot publish its manifest, advance its chunk cursor, or be replaced
by another transfer.

Remove the manifest event/content pair from the persistent outbox in one atomic
rewrite, release the current retry chunk, and only then clear the transfer. If
the app stops between these steps, startup observes the cancellation marker and
finishes cleanup before any outbox recovery upload. Failed cleanup remains
retryable and never silently resumes the cancelled file.

### D054: Administration waits for the outgoing pipeline

Reject a local administrative transition while file preparation, a durable file
transfer, the direct transport, the protected outbox, or its upload controller
has work. An administrative transition moves the group into the vault-update
state machine, so an older upload callback would otherwise target a group that
is no longer in the active-group map and fail to acknowledge accepted bytes.

The user may retry the role, removal, or history-policy action after the active
operation reaches its durability or callback boundary.

### D055: Transient file work serializes control transitions

Do not start control observation while a source hash, final source verification,
or on-demand file Save is active. A verified control transition temporarily
moves the conversation through the vault-update state machine, while those
continuations deliberately resolve their conversation in the active-group map.
Letting both proceed could drop a worker or cooperative-write continuation and
leave the file operation permanently busy.

Reject a new Save while control observation is active or already queued, and
reject local administration while a Save is active. A control notification that
arrives during transient file work remains dirty and automatically starts after
the file operation finishes. Durable outgoing file transfers may still cross a
remote transition because their manifest, cursor, and source path survive the
state-machine move and resume from persistent state.

### D056: Control observation precedes content observation

Run at most one control or content observation for a conversation at a time.
Control has priority because it may replace the MLS roster and archive epoch,
then temporarily move the conversation through the vault-update state machine.
A content callback that completed during that move would otherwise miss the
active-group map and leave its finished controller permanently installed.

Coalesce content notifications while control is active. If a control
notification arrives during content observation, keep it dirty and start it as
soon as the content controller finishes, including after a retryable content
failure. The normal outgoing pump restarts deferred content after control is
settled. Local administration waits for an active content observation for the
same callback-lifetime reason.

### D057: Cancellation survives an in-flight carrier upload

Persist a file-transfer cancellation request even while the manifest outbox or
one direct chunk upload is active. Do not report a false rejection merely
because Telegram has not completed its current callback. Keep the transfer in a
synchronizing state until that callback reaches its durability boundary, then
remove the manifest pair and current retry chunk before clearing the transfer.

If Telegram accepted a chunk after cancellation was requested, do not advance
the durable chunk cursor. The accepted ciphertext becomes an unusable opaque
orphan and local cleanup removes its retry copy. Manifest acknowledgement still
finishes normally before cancellation cleanup, so an accepted Telegram object
is never confused with an unacknowledged local outbox entry. Retryable and
permanent callback results also resume the durable cleanup instead of leaving
the cancellation marker stuck until restart.

### D058: Permanent transport failures remain manually retryable

Treat `PermanentTransportError` as a prohibition on automatic retry, not as a
requirement to restart the client. A peer can regain write access, an account
can rejoin a group, and transport-side validation conditions can change while
the process remains open. Expose an explicit Retry action for vault discovery,
password-backed vault loading, and pending group publication or join.

Retry the same durable group operation and identifiers when one exists. If a
failed vault creation already discarded its pending identity, retry performs a
fresh password-backed cloud selection; a still-missing vault then returns to
the normal confirmed creation form. Security-blocked and local-persistence
failures never use this path, and no transport state retries automatically.

### D059: Lock closes protected plaintext surfaces

Close every protected conversation, file, group-list, and security dialog as
soon as the vault leaves `Ready`. These surfaces may already contain decrypted
messages, filenames, member safety codes, or an unsent draft, so leaving their
widgets alive after a manual or passcode lock would expose stale plaintext even
though the service has discarded its keys. Clear both password fields when the
main protected-groups dialog returns to `Locked` as well.

Keep content, file-transfer, and security revision streams monotonic across a
lock and explicitly publish a revision after clearing the protected state.
Resetting a revision to zero can repeat its initial value and suppress the
reactive notification. Publish security revisions for verified roster and
history-policy changes too, so an open security view cannot retain an older
membership state before the lock boundary.

### D060: Security failures destroy the unlocked runtime

Treat `SecurityBlocked` as a fail-closed boundary, not only as a status shown by
the interface. Once a rollback, fork, identity conflict, invalid pagination, or
authenticated-content conflict selects that state, defer one lock operation
until the current callback returns. The lock cancels controllers, destroys the
unlocked vault and group objects, cleanses remembered passwords, and invalidates
worker continuations without deleting the persistent encrypted recovery state.

While that deferred cleanup is pending, require `Ready` and an unlocked vault
at every public plaintext, send, file, administration, synchronization, and
active pipeline entry point. In-flight observation or upload callbacks must not
write, acknowledge, or publish after a separate callback has already detected a
security failure. A manual lock that wins the race makes the deferred cleanup a
no-op, and assigning `SecurityBlocked` with no unlocked runtime does not create
a lock loop.

### D061: Admission and discovery failures remain retryable

An incoming client waiting for admission has no protected conversation surface
from which to request synchronization. If its control observation ends with a
retryable or permanent transport error, publish the corresponding group state
so the main protected-groups dialog exposes Retry instead of remaining forever
in `AwaitingAdmission`.

Retry restarts every stalled admission observation already restored in the
active-group map. Collect conversation identifiers before starting controllers,
because a synchronous completion may move a group into the vault-update state
machine and invalidate map iterators. If an admission completes synchronously,
preserve the state selected by that completion instead of writing the waiting
state over it.

Keep a peer in the discovery queue after both retryable and permanent transport
failures. Neither state retries automatically; the existing explicit Retry
action returns the group state to Ready and resumes the queued discovery. A
missing or non-protected bootstrap is still a completed negative discovery and
is not retried.

Failure to start an admission observation or discovery request is retryable as
well. Do not leave admission in a waiting state without a live controller, and
do not discard a discovery peer before a request actually starts. In both
cases, preserve the durable in-memory operation and restore the Retry action.

Existing protected conversations remain accessible from the main dialog while
another group is publishing, awaiting admission, retryable, or locally failed.
The global creation state controls creation and retry actions, but it must not
hide unrelated active groups or force a lock-and-unlock cycle merely to read
them.

### D062: Open protected views never keep stale authority data

Close security and member-management dialogs when the verified security
revision changes. Their action buttons and safety codes describe one atomic
membership snapshot; updating only their text could leave a revoked action or
an obsolete verification code visible. Reopening the dialog constructs every
control from the new verified snapshot, while the service still rechecks
authorization before accepting an action.

Rebuild an open protected-file list whenever the content revision changes.
The list remains bounded by the existing visible-page limit and therefore can
show newly synchronized manifests without retaining an unbounded plaintext
snapshot or requiring the user to close the conversation.

Refresh an open conversation's status and input availability on the same
security revision. Removal or re-admission changes the active phase without
necessarily adding content, so waiting for a content notification would leave
the field looking writable even though the service correctly rejects the send.

### D063: A control observer must exist before showing synchronization

If a control observation cannot start, retain its dirty marker but expose a
retryable content error instead of `Synchronizing`. For a client awaiting
admission, expose the same retryable failure through the group state so restart
recovery cannot leave the main dialog waiting without a live controller.

Starting a controller may synchronously invoke its completion callback. Any
caller that wants to inspect the group afterward must find it again by
conversation identifier, because processing a verified control page may move
the group into the durable vault-update state machine. Never dereference the
pre-start map entry or group reference across that callback boundary.

### D064: File-download security failures lock the vault

Treat an authenticated file-chunk conflict, invalid pagination, or exceeded
download bound as the same fail-closed boundary as a protected message or
control conflict. A file-save callback returning `SecurityBlocked` is not
sufficient while the unlocked service can still send or administer the group.

Set both the vault and conversation states to `SecurityBlocked` before
finishing the transient file operation. This prevents its cleanup from
starting another observation, still delivers the failure to the UI callback,
and lets the existing deferred security lock destroy all unlocked runtime
state immediately afterward.

### D065: Vault-changing group operations are globally serialized

Starting a protected group or an administrative transition is allowed only
while the global group operation is `Idle` or `Ready`. Administration also
requires that no creation, indexed join, or discovery controller owns the
global slot. Reading and ordinary protected sends in unrelated groups remain
available because they do not rewrite the account vault index.

Without this gate, a discovery callback could finish while administration of a
different group had moved that group into the pending vault-update state. The
join would then fail only because the slot was occupied and could overwrite the
real operation state with `LocalFailure`, leaving both operations without a
correct recovery action.

### D066: Discovery owns the global group-operation slot

Start queued group discovery only while the global group operation is `Idle`
or `Ready`, and publish `Preparing` before invoking its controller. The start
can complete synchronously, so assigning the state afterward would overwrite
the completion result. Existing chats remain accessible under D061, but the UI
does not offer another vault-changing action while discovery is live.

Keep discovery requests queued while admission or freshness is unresolved.
After a successful verified control observation, try the queue again; this is
the boundary that can turn `AwaitingFreshness` back into `Ready`. Pending
creation or join still takes precedence and naturally keeps discovery queued.

### D067: Global vault work defers every control boundary

Do not start a group control observation while creation, indexed join, or
discovery owns the global operation slot. If an already-running observation
finishes after another group takes that slot, first honor an unambiguous
security failure, otherwise discard its transient page, retain
`observationDirty`, and do not advance the persistent Telegram boundary. The
page will be fetched and authenticated again from the old boundary.

When the slot is released, collect dirty conversation identifiers and restart
their observers one by one. Stop if a synchronous completion claims the slot
again. Discovery also waits until no control observer is running or dirty, so a
new control notification received during discovery is deferred rather than
raced. Resume this work after publication and after retryable, permanent,
start, or local join/discovery failures.

### D068: Accepted outgoing file chunks are cleaned before state is forgotten

After advancing the durable outgoing-file cursor, remove every cached chunk
strictly before that cursor before preparing more work. A stop between the
cursor commit and the original best-effort removal can therefore leave at most
a recoverable cache entry, and restart removes it without discarding the
current chunk whose exact ciphertext is required for a safe retry.

Cancellation removes the complete file chunk range before clearing the durable
transfer. Successful finalization repeats the same check immediately before
clearing, after the final source hash has completed. A cleanup failure retains
the transfer and becomes a local failure instead of forgetting the only index
from which the encrypted cache can be reclaimed.

### D069: Chunk-store lock contention never blocks the interface thread

Acquire per-record file locks without waiting. Chunk preparation, manifest
authorization, and cache cleanup run from interface-driven callbacks, so a
five-second lock wait can freeze the entire client and a prefix cleanup can
multiply that pause by the number of cached records. Contention now fails the
current operation immediately while preserving its durable state for recovery.

### D070: Removal durably discards every pending outgoing object

When a verified control transition removes the local client, persist
cancellation of any outgoing file, reclaim its cached chunks, and atomically
clear the remaining protected outbox before publishing the updated vault index.
Freshness challenges and other objects queued before removal must never be sent
after the client has lost membership.

Run the same cleanup from restored vault-update work. A transient cleanup or
outbox persistence failure remains a local recoverable operation with its
durable state intact; it no longer masquerades as authenticated vault damage
and no longer forces a global security lock during unlock.

### D071: Cancellation waits for final source verification

Keep a cancelled transfer durable while its final source-hash worker is still
running. The worker already owns the single `fileFinalHashInProgress` slot and
will resume the outgoing pump after observing the cancellation marker. Clearing
the transfer early would let a second file reach finalization while that slot
still belonged to the first file, leaving the second transfer synchronized
forever with no continuation able to restart it.

### D072: Equal content states still notify every conversation

Keep the per-conversation content-state map authoritative, but force the shared
reactive notifier to emit for every map update. Protected conversation views use
that producer as an invalidation signal and then read their own conversation's
state. A normal equality-filtered assignment loses the second notification when
two different groups consecutively enter the same enum state, leaving one view
with stale status and controls even though the service state is correct.

### D073: File cancellation covers hashing as well as upload

Expose file preparation as a pending transfer immediately, prevent text from
being queued behind it, and let the existing cancel action stop both the initial
and final source-hash workers. Each worker owns a distinct atomic cancellation
token; its callback must still match that token before changing group state, so
a late completion can never finish a newer file operation. Destroying a group
also signals both tokens, preventing lock or shutdown from continuing to read a
large plaintext file in the background.

### D074: Protected peers never downgrade after local recognition

Persist a monotonic account-local set of Telegram peer bindings as soon as a
protected group is created, restored, indexed by the authenticated unlocked
vault, or accepted from a verified protected bootstrap. The ordinary Telegram
composer must consult this set even while the E2E vault is locked. Removing,
unloading, or hiding the carrier object therefore cannot turn a previously
known protected group back into a plaintext chat.

The marker contains no secret beyond a Telegram peer binding already known to
the local account and lives in Telegram Desktop's encrypted account-local
preferences. Flush the preference synchronously at the recognition boundary;
the normal delayed settings write leaves a crash window in which an active
server could remove the carrier before restart and regain a plaintext composer.
The marker is deliberately never pruned from server history. Invalid or
oversized marker state fails toward confidentiality by treating every group
peer as protected instead of silently re-enabling plaintext composition.
Unauthenticated reserved metadata continues to block composition while present,
but cannot write a permanent marker and give an ordinary group member a lasting
local denial-of-service primitive.

### D075: One Telegram carrier peer maps to one protected conversation

Require the authenticated account-vault conversation index to contain unique
Telegram peer bindings as well as unique sorted conversation identifiers. Two
independent MLS and archive states must never observe the same Telegram carrier
group as their authoritative transport. Reject an ambiguous index during both
encoding and authenticated decoding, so the client blocks rather than choosing
one conversation based on iteration or UI state.

### D076: Authenticated markers survive Telegram peer migration

Check the durable protected-peer marker before trusting the current Telegram
peer classification. When Telegram Desktop links a migrated supergroup to an
older basic group whose marker is authenticated, immediately persist the new
peer as another monotonic protected presentation alias. The migrated chat then
keeps its plaintext composer disabled even after the old carrier is unloaded or
the server later hides that migration edge. Opening the protected surface also
falls back through the migrated history binding to the original conversation.

### D077: Identity creation repeats passwordless discovery

Treat a previous `Missing` result as a snapshot, not as durable proof that the
Telegram account still has no protected identity. Opening the protected surface
again repeats the bounded Saved Messages discovery. More importantly, pressing
Create starts another passwordless discovery before generating any identity or
uploading a vault. If another device has created an identity since the form was
shown, switch to the unlock flow and discard the proposed password instead of
publishing a competing account identity.

This preflight narrows honest multi-device races but does not claim an atomic
compare-and-swap from Telegram storage. A server that hides first-contact
metadata remains covered by the documented first-contact limitation.

### D078: Deferred file completions stay inside one lock epoch

Bind every Desktop file-download completion to both the service operation epoch
and the manifest event that started the Save request. The transport controller
can finish on a non-interface thread and defer its completion to the next main
turn. A lock destroys the old group runtime, but the service object survives and
can later restore the same conversation identifier. Without both bindings, a
late old completion could mistake a new Save request in that conversation for
its own operation, reset its controller, or begin writing the wrong manifest.

An epoch mismatch or event mismatch now drops the stale callback without
touching the restored group or its user callback.

### D079: Loaded carriers survive a locked-vault interval

After the vault becomes authenticated and ready through either unlock or first
identity creation, run local-group recovery, enumerate only the Telegram group
histories already loaded in the session, and queue ordinary protected-group
discovery for histories that retain carrier metadata. A carrier received while
the vault was unavailable would otherwise be forgotten because the new-item
notification is not replayed merely by making the vault ready.

The loaded metadata remains only a discovery trigger. It cannot decrypt,
enroll, index, or advance protected state; the existing authenticated bootstrap
pipeline still verifies every accepted byte. Do not turn this recovery into a
full Telegram history scan.

### D080: Admission retry preserves synchronous outcomes

An admission observation may complete synchronously while Retry is starting
it. Stop the retry loop immediately if that completion claims the global group
operation slot; the remaining dirty admissions will resume when the slot is
released. Likewise, retain a synchronous permanent, local, or security result
instead of replacing it with a generic retryable failure merely because no live
observer remains after `beginGroupObservation` returns.

This is required for multiple waiting groups as well as test transports. A
synchronous completion of the first group can move it into the vault-update
state while later admission groups are still present in the active map.

### D081: Unanchored discovery cannot block the account vault

Object conflicts, ambiguous bootstraps, capacity excess, and invalid pagination
while discovering an unindexed Telegram carrier group reject that discovery
attempt and release the global operation slot. They do not security-block the
authenticated account vault or destroy established protected-group runtimes.
Before a verified bootstrap is accepted there is no cryptographic trust anchor
linking that group to the account, so an ordinary group member or active server
can construct these inputs at will.

This rule narrows only first-contact availability scope. No conflicting bytes
are accepted, no peer is added to the vault, and another carrier notification
may trigger a fresh bounded discovery later. The same conflict in an indexed or
already authenticated group remains a fail-closed security block.

### D082: Password KDF work never blocks the interface thread

Run cloud-vault selection and first-vault creation on a background worker. The
64 MiB Argon2id derivation is intentionally expensive and must not freeze the
Protected Groups box, window painting, or its Close action while a password is
being checked. A controller-owned completion guard discards selection results
after cancellation or destruction; first creation additionally binds its result
to the service operation epoch so locking or restarting cannot adopt stale key
material.

The worker owns independent crypto providers and all input copies. It returns
only the completed move-only vault result to the main thread, where persistent
anchors, uploads, UI state, and service-owned secrets continue to change.

### D083: Pagination work shares the version-one lifecycle bound

Limit every generic long-running carrier scan to 65,536 pages and 64 MiB of
retained encoded cursors. The earlier million-page allowance was finite in a
type-theoretic sense but still let an active server impose effectively
unbounded network work and excessive duplicate-tracking memory. The new bound
still exceeds the minimum pages needed for the existing 65,536-object control
lifecycle and million-record content-store ceiling at the 100-object transport
page size.

Exhaustion remains an explicit invalid-pagination failure. No partial scan is
committed as complete and no unauthenticated object becomes authoritative.

### D084: Every asynchronous transport attempt has a generation token

Bind each page request, vault discovery, vault selection, outbox attempt, and
two-stage carrier upload to a monotonically advancing in-memory token. Object
identifiers and a generic `requestActive` flag are insufficient because a
cancelled controller may restart with the same object or while a newer page is
already active. A duplicated or delayed callback from the older operation must
be ignored without consuming the new operation's active slot.

Lifetime guards still prevent callbacks after destruction. Generation tokens
cover the distinct case where the owner remains alive and deliberately retries
the exact same authenticated ciphertext or reuses the controller.

### D085: Carrier downloads do not own unrelated document loads

Reuse a Telegram document that is already loaded or loading instead of changing
its destination or cancelling it. Start at most one module-owned download for a
shared `DocumentData`, even when Telegram returns duplicate messages for the
same document. Only a download started by the protected transport may be
cancelled and have its temporary location cleared when the page completes or
the backend is destroyed.

Clearing a module-owned temporary location removes both the live document
location and its account-local location record, including filename-pair and
alias bookkeeping. This prevents deleted temporary paths from accumulating in
Telegram Desktop's persistent media-location map.

### D086: Protected groups use the native history and composer

Supersede the presentation part of D039 while retaining its carrier-hiding and
fail-closed requirements. Materialize only authenticated records from the local
protected content store as silent client-side items in the bound Telegram group
history. Mark every item visibly as encrypted and prohibit Telegram reply,
forward, pin, and reaction actions. Keep materialization bounded
to the newest 200 records and extend it in 200-record pages when the native
history approaches its top.

For an unlocked active protected group, retain the ordinary Telegram text
field, send button, and local-file attachment picker. Intercept text before rich
message or ordinary send processing and route it to `sendProtectedText`; route
local file paths to `sendProtectedFile`. Disable Telegram cloud drafts and link
preview resolution for the protected composer. Hide or reject voice, bots,
stickers, GIFs, inline results, contacts, send-as, scheduling, forwarding,
in-memory media without a local path, and any stale stock send dialog.
If no authenticated conversation runtime is available, retain D039's single
unlock or recovery action and never fall back to plaintext Telegram sending.

### D087: File previews are authenticated protected content

Generate a bounded JPEG thumbnail locally while the original file is hashed.
Store that thumbnail, its original dimensions, and media duration inside the
encrypted file manifest. Telegram receives only the opaque manifest carrier
and ciphertext chunks; it never receives a plaintext thumbnail, filename,
MIME value, dimensions, or duration from the protected presentation.

Materialize a protected file as a native local document item with the decrypted
thumbnail and a lock caption. Clicking an uncached item runs the authenticated
protected-file restoration flow and opens only the hash-verified result. Keep
manifest revision 2 readable without a preview and emit revision 3 for new
files. Previously sent revision-2 files remain generic because no thumbnail
exists in their authenticated ciphertext.

### D088: Clipboard images use the protected file pipeline

Supersede D086's rejection of in-memory media for non-animated images. Encode a
pasted image as an owner-only staged PNG, then pass it through the ordinary
protected-file hash, encrypted manifest, chunk encryption, freshness, and
authenticated upload flow. Never upload the staged PNG through Telegram's
ordinary photo API and never expose its path as a durable local history cache.

Remove the staged plaintext after successful final hash verification, durable
cancellation, or any preparation failure. A staged source that belongs to a
persisted transfer remains available across a restart until that exact transfer
finishes or is cancelled.

### D089: Message changes are immutable authenticated events

Represent edits and deletions as encrypted version-two message-body events that
reference the immutable original event identifier. Telegram retains the opaque
original and mutation carriers; clients fold the authenticated events into the
native timeline. A deletion is a permanent tombstone, while the newest valid
edit supplies the visible text and native edited badge.

Accept a mutation only when its authenticated account identifier equals the
original message or file author's account identifier. Any authorized device of
that account may therefore change its own content, while Telegram and other
participants cannot forge the operation. Editing is limited to text; deletion
also applies to protected files. The ordinary Telegram edit field and delete
confirmation route to these events and never call Telegram's edit or delete
message APIs for decrypted protected items.

### D090: Selected files use durable staging and automatic retries

Copy every selected local file into an owner-only conversation staging path
while computing the manifest hash, and persist that staging path as the source
of the outgoing transfer. Temporary picker paths and later removal of the
original file must not truncate a multi-chunk upload. Remove the staged source
only after full source-hash verification or durable cancellation.

Retry transient manifest and chunk uploads automatically with bounded
exponential delay. A Save operation also retries transient downloads and
temporarily missing chunks while an authenticated sender may still be
publishing them. Keep retries bounded, retain already authenticated chunks, and
commit the destination only after its exact size and full hash match.

### D091: Retry the control observation that gates file recovery

An interrupted account authorization or transient Telegram failure may leave a
restored group control observation marked dirty before a persisted file transfer
can resume. Retry that observation automatically with bounded exponential
delay. A successful request invalidates older retry callbacks; permanent
transport failures remain explicit and require user retry.

The retry belongs to the protected-group control plane. It does not admit,
delay, pace, or own MTProto media/upload sessions. Once observation succeeds,
the existing durable transfer continues from its saved chunk cursor and exact
manifest instead of replacing the transfer or regenerating ciphertext.

### D092: Windows chunk locks cannot leave restart-blocking files

Use a non-waiting per-record Windows kernel mutex for protected chunk cache
authorization, storage, and cleanup. The kernel releases mutex ownership when
the client exits or crashes, so a forced restart cannot strand `QLockFile`
artifacts that recursively grow `.rmlock` suffixes and permanently block a
durable transfer. Retain the existing non-waiting `QLockFile` on other systems.

While holding the mutex, remove only exact legacy lock paths left by earlier
Windows builds. Windows refuses that removal while another process still owns
the old file handle, preserving contention safety. Retry each existing exact
legacy file for at most 500 milliseconds because antivirus or indexing readers
can make a single Windows deletion attempt fail even after the owner exited.
Do not route this migration back through `QLockFile`, whose one-shot explicit
stale removal recreated the permanent failure for the original base lock. The
migration changes only the local encrypted chunk cache; Telegram upload sessions
and their MTProto connection lifecycle remain untouched.

### D093: A durable file transfer does not block protected messages

Allow protected text, edit, and delete events to enter the persistent outbox
while an already-durable file transfer is publishing chunks. Materialize those
events locally at once and keep the existing file-transfer pump ahead of the
ordinary outbox, so the file resumes from its committed cursor and queued chat
events follow without replacing or regenerating any encrypted file object.

Initial file staging and hashing remain exclusive because their durable transfer
does not exist yet, and a second file remains rejected until the first transfer
finishes or is cancelled. A busy-file rejection is an expected user-visible
state, not a local cryptographic or persistence failure. This policy changes
only protected-content queueing; it does not alter MTProto upload-session
ownership, pacing, endpoints, or connection selection.
