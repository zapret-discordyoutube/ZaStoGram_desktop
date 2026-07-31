# History Access

## Policy modes

Each protected group has a signed default policy:

- `None`: no history before the admission transition;
- `FromJoin`: history beginning with the admission transition;
- `Since`: history beginning with a specified authenticated archive event;
- `Full`: every retained archive epoch.

An owner or E2E administrator may attach a signed per-invitation override. The
effective grant is recorded as a protected system event visible to current
members.

The `Since` boundary is a stable cryptographic object identifier, not a Telegram
message date, server order, or local wall clock. The interface may let an
administrator choose a human-readable date, but it resolves that choice to an
authenticated archive event before signing the invitation policy.

## Archive epochs

Message bodies and files use independent random content keys. For cloud history,
those content keys are additionally wrapped under a conversation archive epoch
key.

Archive epochs change on security-relevant boundaries, including membership
policy changes and participant removal. Time- or volume-based rotation may be
added after performance testing.

## History grants

A history grant contains the archive epoch keys allowed by policy, sealed to the
recipient account's archive public key and signed by an authorized owner or E2E
administrator.

The grant is account-scoped rather than device-scoped. Any installation that
unlocks the same account vault can use the account archive identity to recover
the granted history.

Granting full history transfers epoch keys, not re-encrypted copies of every
message and file. This keeps admission work proportional to the number of
archive epochs rather than total archive size.

## Removal and revocation

Removing a participant rotates future live and archive epochs. The removed
participant cannot receive future keys but retains every old key or plaintext
already obtained.

Reducing a participant's history policy affects future grants and installations
that do not already possess the removed epoch keys. It cannot erase keys from a
previously authorized or malicious client.

## Forward-secrecy tradeoff

Automatic full-history synchronization deliberately preserves archive keys.
Compromise of an unlocked account archive identity can expose all history
granted to that account. Live MLS forward secrecy does not undo this archive
access. Product documentation must distinguish live-message ratcheting from
cloud-history confidentiality.
