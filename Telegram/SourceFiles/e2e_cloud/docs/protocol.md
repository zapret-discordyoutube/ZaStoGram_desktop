# Protocol Model

## Versioning

Every object carries an application protocol version independent of the MLS
version and cipher suite. Version one uses a fixed-order binary structure in the
style of the TLS presentation language used by MLS. Multi-byte integers are
unsigned and big-endian. There are no optional or unknown fields in version one.
Readers reject every unsupported version and every trailing byte.

This avoids signing reconstructed JSON or a generic object model. Object-level
signatures and MLS authenticated data cover the exact version-one bytes defined
for that object. The outer carrier representation is never signed in place of
the decoded protected object.

## Transport envelope

A logical transport envelope contains at least:

```text
magic
application_protocol_version
conversation_id
object_kind
sender_account_id
sender_client_id
telegram_peer_id_binding
epoch_or_generation
payload_hash
payload
authentication_data
```

The version-one envelope is encoded in this exact order:

```text
byte[8]  magic = "TDE2ECLD"
uint32   application_protocol_version = 1
byte[32] conversation_id
uint16   object_kind
byte[32] sender_account_id
byte[16] sender_client_id
uint64   telegram_peer_id_binding
uint64   epoch_or_generation
byte[32] object_id
byte[32] payload_hash
uint32   payload_length
byte[]   payload
uint32   authentication_data_length
byte[]   authentication_data
```

The payload is limited to 16 MiB and authentication data to 1 MiB. Larger
objects use encrypted file chunks rather than oversized envelopes. Decoders
check lengths before allocation, reject zero identifiers and empty protected
fields, and require transport indexing identifiers to match the identifiers in
the encoded envelope.

Structural validation does not authenticate an envelope and does not prove that
`payload_hash` is correct. Those checks belong to the selected cryptographic
engine and object-specific verifier.

The exact fields included in MLS wire messages are delegated to the MLS engine.
Application fields that bind the MLS group to the Telegram carrier belong in
authenticated application data.

## Protected group transition payload

Version one protected-group transitions use a fixed 185-byte payload:

```text
byte[8]  magic = "TDE2EGST"
uint16   payload_version = 1
byte[32] conversation_id
byte[32] transition_id
uint64   previous_generation
uint64   generation
uint8    transition_kind
byte[32] target_account_id
byte[16] target_client_id
uint64   target_telegram_user_id_binding
uint8    target_role
uint32   target_admin_permissions
uint8    history_access_mode
byte[32] history_boundary_event_id
```

The generation must advance by exactly one. Fields unused by a transition kind
must contain their defined zero or default value; this prevents multiple byte
representations of the same operation. The state machine independently repeats
structural, actor, role, capability, credential, and replay validation after the
cryptographic layer authenticates the payload.

## Account credential payload

Version one account credentials use a fixed 76-byte representation containing
the `TDE2EACT` magic, credential version, initial MLS cipher suite, Ed25519
account authorization public key, and X25519 archive HPKE public key. The
account identifier and safety-code inputs are domain-separated SHA-256 hashes of
this canonical credential and protected context.

## Object kinds

- initial group state;
- account credential announcement;
- client KeyPackage;
- join request;
- MLS proposal, commit, welcome, and application message;
- encrypted message body reference;
- encrypted file manifest and chunk;
- archive epoch declaration;
- history policy update;
- history grant;
- owner or administrator role update;
- safety-code gossip;
- freshness challenge and response;
- recovery and resynchronization request.

Encrypted message-body plaintext revision one contains an original timestamp
and UTF-8 message text. Revision two is an edit or delete event containing its
action, timestamp, target original event identifier, and edit text when
applicable. The encrypted descriptor authenticates the mutation sender. A
client applies it only when that sender account is the original content author;
a delete is a terminal tombstone and an edit is valid only for original text.

## Membership authority

Telegram membership starts the workflow, but the protected group state is
authoritative. A user has plaintext access only when a valid cryptographic group
transition includes an authorized client credential for that account.

Owners and E2E administrators are represented inside signed protected state.
Telegram administrator changes do not silently grant E2E authority. They must
be confirmed by an already authorized E2E owner or administrator transition.

## Unsupported clients

A stock Telegram client may appear in the carrier group's ordinary membership,
but it has no KeyPackage and receives no history grant or content key. Supported
clients show that account as pending until valid E2E enrollment succeeds.

There is no plaintext fallback.

## Replay and fork handling

Clients reject duplicate object identifiers, invalid epochs, invalid transcript
hashes, invalid signatures, and unauthorized policy changes. Conflicting valid
branches must enter an explicit recovery flow; clients must not silently choose
the branch most recently delivered by Telegram.

Exact fork recovery depends on the selected MLS engine and delivery encoding and
remains an open design item.

## Scale target

The initial validation target is 500 participant accounts with multiple active
client instances per account. Tests must cover mass joins, removals, offline
clients, concurrent senders, delayed commits, and large skipped-message windows.
