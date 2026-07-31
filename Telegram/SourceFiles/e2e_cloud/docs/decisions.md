# Decision Record

## 2026-07-31

### D001: New protected group

Create a new protected-group mode backed by a normal private Telegram carrier
group. Do not initially convert existing groups or create protected subrooms.

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
master key. Remember the unlocked key locally only through protected operating
system storage.

### D007: No server password recovery

Password loss creates a new E2E identity. Group owners or E2E administrators may
admit that identity and regrant history allowed by policy.

### D008: Configurable history admission

Provide a signed group default plus a per-invitation override. Support no
history, history from join, history from a boundary, and full history.

### D009: E2E administration

The group owner and explicitly appointed E2E administrators may manage E2E
admission and history policy. Telegram administrator status alone is not enough.

### D010: Replaceable MLS implementation

Do not select Cisco MLS++, OpenMLS, or a custom engine yet. Define an
implementation-independent engine boundary and require RFC 9420 vectors,
interoperability, fuzzing, and security review before production use.

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
whose bytes are the exact encoded envelope. Use the fixed filename
`protected.tde2e`, MIME type `application/octet-stream`, an empty caption, no
preview, and no original application-file metadata. Treat both upload and
`messages.sendMedia` as one transport operation. Remove an outbox item only
after the final send RPC succeeds; an uploaded file token alone is not delivery.

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
