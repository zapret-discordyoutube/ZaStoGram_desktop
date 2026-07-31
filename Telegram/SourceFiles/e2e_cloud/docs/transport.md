# Telegram Transport

## Constraint

There is no custom delivery, key-directory, archive, or blob server. Telegram is
the sole remote storage and delivery system.

The carrier is a newly created normal private Telegram group. Protected clients
interpret specially encoded messages and documents as E2E protocol objects.
Stock clients do not receive keys and may display only opaque carrier objects.

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
The document body is the exact version-one envelope, the filename is always
`protected.tde2e`, the MIME type is always `application/octet-stream`, and the
caption is empty. The protected client does not upload previews or original
application-file metadata.

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

This encoding must still be tested against server-side content transformations,
document deduplication, forwarding, copying, deletion, and retention behavior.

## Availability

An active Telegram server can censor the group, withhold a commit, present stale
objects, or partition participants. E2E can detect many integrity failures but
cannot force delivery. The client must represent stalled or inconsistent state
instead of silently falling back to plaintext.
