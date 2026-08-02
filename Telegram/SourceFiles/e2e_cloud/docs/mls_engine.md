# MLS Engine and Transaction Boundary

## Selected implementation

Version one uses the MIT-licensed OpenMLS `0.8.1` code line, pinned to upstream
commit `0e99bc8814d136f0bc7bc9ce86dd288eb32273ed`, which contains the July 2026
security dependency update. Only the mandatory RFC 9420
cipher suite `MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519` (`0x0001`) is
accepted. The RustCrypto provider supplies the OpenMLS primitives. Draft
OpenMLS extensions and post-quantum cipher suites are disabled at the
application boundary.

The dependency is compiled as a Rust static library with Rust 1.91 and a
checked lockfile. The checked dependency graph was scanned with RustSec after
the provider migration and contains no reported vulnerabilities. RustSec does
report one maintenance warning for `proc-macro-error2`, reached only on some
targets through `hpke-rs` → `libcrux-sha3` → `hax-lib`; it is not runtime
cryptographic code but remains an upgrade item. Versioned C ABI `0x00010006`
exposes group creation and inspection, KeyPackages, add/remove/self-update
commits, Welcome joins, application sealing and processing, HPKE, bounded byte
buffers, and
numeric results. The ABI also distinguishes a valid private
KeyPackage snapshot from active group state before admission replacement. Rust
structs, allocator ownership, unwinding, and OpenMLS
types do not cross that boundary. Every exported entry point catches panics,
validates pointer/length pairs, and returns buffers that only the matching
bridge release function may destroy.

Desktop and future mobile clients share the same bridge crate and protocol
vectors. Platform code supplies only protected local storage, time, and the
Telegram carrier.

## Why OpenMLS

OpenMLS implements RFC 9420, supports the mandatory suite, exercises Windows,
Linux, and macOS in upstream CI, and builds Android and iOS targets. Its
`StorageProvider` covers long-lived group state and is used by the group load
path. That persistence model is essential because a sender or receiver ratchet
cannot safely be reconstructed from only public group messages.

The evaluated Cisco MLS++ revision remains useful as an independent
interoperability implementation, but its public state API does not provide a
supported complete serialization format for every private ratchet and TreeKEM
component. A private serialization fork would couple the product to internal
cryptographic layout and enlarge every future upgrade review.

This comparison chooses an integration boundary; it is not a general claim
that one implementation is universally safer than the other.

## Per-conversation provider

Every client installation and protected conversation has one independently
serialized provider. It includes only that client's credential material,
conversation-scoped KeyPackages, and the OpenMLS group state. A provider is
never copied to another installation and is never used concurrently by two
actors.

KeyPackages have an explicit 84-day lifetime (the OpenMLS maximum accepted
range, including its one-hour clock-skew margin). A client starts replacement
seven days before expiry and after every protected-group generation change.
Publications are account-signed and valid only for the exact generation they
name. Their signed object identifier is derived from the conversation,
account, client, generation, credential, KeyPackage, and publishing Telegram
user ID. A receiver recomputes it from the Telegram author observed at receipt,
so the server cannot relabel another user's valid publication. Replacement does
not delete an older private package immediately: a
small encrypted local pool retains every still-valid publication until one is
consumed by a Welcome or expires. This lets an administrator use any package
that Telegram delivered without creating an unrecoverable ghost client.

The bridge canonicalizes its provider snapshot as a sorted bounded key/value
map with an explicit snapshot version. C++ treats it as opaque sensitive bytes.
The outer local record binds the conversation identifier, engine identifier,
storage revision, and protected operation receipts.

## Outgoing transaction

For every application message, proposal, or commit:

1. Lock the per-conversation actor and find an existing receipt for the random
   operation identifier.
2. If the receipt exists and its request digest matches, return its exact
   envelope. A mismatch is a permanent local integrity error.
3. Clone the current provider into an isolated candidate and run OpenMLS only
   on that candidate.
4. Validate and encode the outgoing MLS object and its application envelope.
5. Atomically protect and replace one local record containing the candidate
   provider snapshot, request digest, operation identifier, and exact envelope.
6. Only after that commit succeeds, replace the live provider and allow the
   outbox to upload the recorded envelope.
7. Retain the receipt across retries and restarts. Remove it only after the
   outbox has durably recorded successful Telegram delivery.

No candidate outgoing bytes are returned when step 5 fails. This prevents a
caller from publishing a ciphertext whose corresponding sender-ratchet state
was never persisted.

## Incoming transaction

Incoming MLS bytes remain untrusted until carrier binding and strict envelope
decoding succeed. Message processing runs against an isolated provider copy.
Application plaintext, a candidate provider snapshot, authenticated sender and
epoch metadata, and replay-journal changes form one logical result.

The provider mutation and decrypted application record are committed in the
same encrypted atomic snapshot before plaintext is exposed to the model. The
two-phase inbound journal then records acceptance. On restart, a pending journal
entry is matched against the committed application record: committed plaintext
is delivered without ratchet replay, an uncommitted attempt is retried, and an
ambiguous state fails closed for explicit recovery.

Group-control traffic adds another level above an individual MLS message.
Telegram may deliver a signed transition, MLS commit, Welcome, and archive-key
distribution in any order. Existing members process the commit followed by the
distribution on isolated provider copies. A new member joins from its local
KeyPackage state with the Welcome and then processes the distribution. The
resulting roster must exactly equal the protected account/client set.

The candidate provider, signed protected transition, and rotated archive key
are persisted through an encrypted cross-store write-ahead transaction. An
outbound transaction additionally records exact publish envelopes; inbound and
Welcome transactions contain no publish set. A crash at any store boundary is
replayed idempotently from the transaction record.

When the verified commit removes the local client, processing stops before the
new archive distribution: the client is not entitled to decrypt it. The same
transaction replaces active provider bytes with a protected tombstone bound to
the removal transition, generation, resulting checkpoint, commit hash, account,
and client. Group-ledger recovery continues normally while the archive store
remains at its last authorized epoch. Re-admission first installs a newly
account-authorized KeyPackage, then consumes a new Welcome and appends the new
archive epoch across an explicit gap.

## Upgrade and release gate

An OpenMLS update requires all of the following:

- review of the exact upstream diff, release notes, and security advisories;
- deterministic migration tests from every shipped provider snapshot version;
- RFC 9420 known-answer and negative-validation vectors;
- wire interoperability with Cisco MLS++ or another independent implementation;
- parser, C ABI, state-transition, and storage fuzzing;
- crash injection before and after every transaction boundary;
- 500-participant desktop performance and memory tests;
- Android and iOS cross-platform vectors before mobile release;
- independent review of the bridge and application-level authorization rules.

If migration cannot be proven, the client must keep the prior engine available
for read/migration or block the affected conversation with an explicit recovery
state. It must never silently create a replacement group or downgrade to
plaintext.
