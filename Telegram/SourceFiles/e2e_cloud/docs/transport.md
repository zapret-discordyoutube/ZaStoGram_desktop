# Telegram Transport

## Constraint

There is no custom delivery, key-directory, archive, or blob server. Telegram is
the sole remote storage and delivery system.

The carrier is a newly created private Telegram supergroup. Protected clients
interpret specially encoded messages and documents as E2E protocol objects.
Stock clients do not receive keys and may display only opaque carrier objects.
ZaStoGram recognizes the reserved filename/MIME pairs as presentation metadata,
hides them from its ordinary timeline and shared media, and routes the carrier
peer to the protected interface. That recognition is fail-closed UI policy, not
cryptographic acceptance.

## Transport responsibilities

- upload and download opaque envelopes;
- upload, resume, and download ciphertext file chunks;
- map a Telegram peer identifier to a random E2E conversation identifier;
- expose ordinary Telegram membership and administrator events as untrusted
  admission signals;
- retry delivery without changing signed bytes;
- preserve enough ordering information for MLS processing while tolerating
  duplicates and gaps;
- avoid plaintext notifications, previews, captions, and file names.

## Protocol responsibilities

The protocol layer, not the transport, validates:

- account and client credentials;
- owners and E2E administrators;
- MLS epochs and transitions;
- history grants;
- message and file integrity;
- carrier-group binding;
- replay, fork, and rollback evidence.

Telegram message authorship, membership, order, and administrator status are not
cryptographic proof by themselves.

## Carrier encoding

Version one uses an ordinary Telegram document for every protocol envelope.
The document body is the exact version-one envelope. Control objects use the
fixed filename `protected-control.tde2e`; messages, manifests, and MLS content
descriptors use `protected-content.tde2e`. A file chunk uses
`protected-file-<random-file-id>.tde2e`. The random identifier is already
present in the chunk's signed authentication data and reveals neither the
original filename nor its MIME type. The MIME type is always
`application/octet-stream`, and the caption is empty. The protected client does
not upload previews or original application-file metadata.

The carrier representation supports:

- small control envelopes;
- large encrypted message bodies;
- resumable encrypted files;
- stable object identifiers independent of Telegram message identifiers;
- protocol version discovery by protected clients;
- bounded impact on stock clients and carrier-group history.

Upload completion is not delivery. The transport first uploads the bytes and
then sends the resulting document with `messages.sendMedia`. The protected
outbox acknowledges an object only after that second RPC succeeds. Retries use
the exact persisted envelope bytes.

Downloaded documents are delivered upward as untrusted byte strings. The
transport does not infer a conversation identifier, object identifier, sender,
or ordering guarantee from Telegram metadata.

History download is paged. The adapter uses Telegram document search, narrowed
to the exact carrier filename when the transport has one, instead of walking
ordinary chat messages. A page returns at most 100 search results and retains
at most 64 MiB of matching carrier documents. The cursor is an
opaque availability hint derived from the oldest scanned Telegram message; it
is neither signed nor trusted as evidence of completeness. Invalid cursor
bytes fail locally. Every returned document still passes the envelope,
carrier-binding, signature, replay, MLS, and group-chain checks above the
transport. Initial backfill continues until `complete`; live updates feed the
same untrusted-object pipeline.

File chunks are excluded from ordinary content backfill. Selecting Save creates
an exact-filename search for that file only, starts after the authenticated
manifest's Telegram message identifier, and stops as soon as every authorized
chunk is available. It caps each retained page at 16 MiB and independently caps
pages, objects, and total bytes from the authenticated manifest layout. Older
clients that used `protected-content.tde2e` remain readable through the same
bounded search as a one-time fallback after the per-file search is empty.

Telegram may duplicate the same authenticated manifest under several message
identifiers. The protected content index retains the minimum positive observed
identifier for exact duplicates, so a later copy cannot move the exclusive
chunk-search boundary past chunks uploaded after the original. This value is
only a local availability hint; all returned chunks still require the manifest
authorization, signed sender binding, and ciphertext verification. A legacy
index conservatively starts per-file recovery after identifier one because it
cannot prove whether its stored identifier belonged to the first copy.

Every long-running pagination controller tracks cursor uniqueness with an
ordered set, accepts at most 65,536 pages in one run, and caps the encoded
cursor bytes retained by that run at 64 MiB. This keeps duplicate detection
sublinear per page and prevents an active server from turning syntactically
valid unique cursors into unbounded client memory or effectively unbounded
network work.

Content backfill first scans the bounded Telegram pages from newest to oldest
without applying them. It records only opaque cursors, per-page SHA-256
fingerprints, and the newest page, whose retained bytes share the transport's
64 MiB cap. Stable older-page cursors are then fetched in reverse page order,
fingerprint-checked, and handed to the protocol from oldest to newest. The
newest page is applied from the bounded scan copy because an empty Telegram
cursor moves whenever a new carrier arrives. Any mutation of an older page
between the scan and replay fails closed, and the saved overlap boundary
advances only after the entire replay is persisted. A crash before that point
restarts from the previous boundary, while object IDs and the inbound journal
make the replay idempotent.

An MLS application that returns a deferred result interrupts the replay without
advancing the saved boundary. A later synchronization retries the complete
suffix; already persisted applications are duplicates. Deferred objects are
never counted as ignored because an object outside the retained overlap would
otherwise become permanently unreachable after a successful boundary advance.
The generic envelope pager follows the same rule and returns its current cursor
rather than the uncommitted next-page cursor.

A control reconstruction retains at most 65,536 matching objects and 512 MiB.
This bound includes untrusted and ultimately ignored objects because an active
server must not obtain unbounded client memory. It is sized for the initial
500-participant target, whose admissions also produce KeyPackages, commits,
Welcomes, archive distributions, grants, freshness traffic, and safety gossip.
Version one deliberately stops at the matching 65,536-generation ledger bound;
longer-lived groups require a future signed snapshot/compaction protocol.

The desktop adapter reuses Telegram Desktop's uploader, but does not create a
visible local plaintext message. Upload readiness yields an in-memory
`InputFile`; only a successful empty-caption, force-file `messages.sendMedia`
acknowledges the protected outbox. Downloads use `messages.search` with the
document filter, accept only the matching exact filename and MIME type, and
stage document bytes in an auto-removed temporary directory before handing
them upward.

The passwordless Saved Messages metadata search has a 15-second client timeout.
On expiry the in-flight RPC is cancelled and discovery reports a retryable
transport error; a later explicit retry starts a fresh request.

Uploader, `sendMedia`, document-search, and document-download phases each have
a 120-second client timeout. Exact carrier bytes and the Telegram peer derive a
stable nonzero `random_id`, so retry after an ambiguous `sendMedia` timeout is
idempotent at Telegram as well as in the protected outbox.

This encoding must still be tested against server-side content transformations,
document deduplication, forwarding, copying, deletion, and retention behavior.

Forwarding or copying an intact carrier document cannot move protected content
to another conversation: every accepted object is authenticated to its random
conversation identifier and Telegram peer binding. The Desktop UI also removes
ordinary forwarding actions for recognized carriers. A stock client can still
copy opaque bytes, and an active server can fabricate matching metadata; both
remain untrusted and cannot advance protected state.

## Availability

An active Telegram server can censor the group, withhold a commit, present stale
objects, or partition participants. E2E can detect many integrity failures but
cannot force delivery. The client must represent stalled or inconsistent state
instead of silently falling back to plaintext.
