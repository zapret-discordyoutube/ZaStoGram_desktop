# Account Identity and Safety Codes

## Version-one credential

The stable account identity is separate from per-group MLS sender keys. Its
version-one public credential is the fixed binary tuple:

```text
byte[8]  magic = "TDE2EACT"
uint16   credential_version = 1
uint16   initial_mls_cipher_suite = 0x0001
byte[32] Ed25519 account_signing_public_key
byte[32] X25519 archive_HPKE_public_key
```

The account identifier is:

```text
SHA-256("TDE2E/account-id/v1" || 0x00 || encoded_public_credential)
```

The account signing key authorizes independent client credentials and identity
gossip. It is not reused as the MLS leaf signature key. Every installation and
protected group receives independent MLS signing and sender state authorized by
the account credential.

Version one starts with the mandatory MLS 1.0 cipher suite `0x0001`,
`MLS_128_DHKEMX25519_AES128GCM_SHA256_Ed25519`. A later post-quantum or hybrid
suite requires a new credential version, interoperability review, and an
authenticated group migration; it is not silently negotiated by Telegram.

## Pinning

The first accepted credential pins a Telegram user identifier to an account
identifier inside the local account vault and protected group state. A different
credential for the same Telegram user is an identity-change event, not an
automatic update. The old account must be removed and the new account admitted
through an authorized protected transition before it receives keys or history.

This is TOFU. It cannot authenticate a perfectly isolated first delivery from
an active Telegram server.

## Pairwise safety code

The pairwise digest sorts the two account identifiers lexicographically and
hashes:

```text
SHA-256("TDE2E/pair-safety/v1" || 0x00 || lower_id || higher_id)
```

Both users therefore see the same result. Comparing it out of band detects a
first-contact substitution affecting either credential.

## Group safety code

The group digest hashes the random conversation identifier, E2E owner, and
sorted unique active account roster:

```text
SHA-256(
  "TDE2E/group-safety/v1" || 0x00 ||
  conversation_id || owner_account_id || uint32(member_count) ||
  sorted_member_account_ids)
```

It changes when the protected owner or account roster changes, but not when an
account adds another installation. The interface displays the first 240 bits as
48 Crockford Base32 characters in twelve four-character groups. QR comparison
uses the full 256-bit digest and versioned context.

## Gossip

One signed gossip snapshot carries:

```text
conversation_id
gossip_object_id
protected_generation + checkpoint_hash
reporter_account_id + reporter_client_id
sorted repeated (
  telegram_user_id,
  account_id,
  SHA-256(encoded_account_credential)
)
Ed25519 account signature over every preceding field
```

The reporter must have been an active client at the observed generation. A
receiver reconstructs its own historical protected state and exact credential
hashes at that generation. A checkpoint mismatch is a fork; a roster or
credential mismatch is an identity conflict; a valid newer checkpoint requests
resynchronization. None of these outcomes automatically replaces a pin.

Gossip can reveal a split view after partitions reconnect, but Telegram can
censor every crossing message and maintain permanent isolation. Out-of-band
safety-code comparison remains the only way to detect a perfectly isolated
first-contact substitution.
