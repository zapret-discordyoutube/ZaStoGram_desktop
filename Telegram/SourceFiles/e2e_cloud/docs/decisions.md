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
