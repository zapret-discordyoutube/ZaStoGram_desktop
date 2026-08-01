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

The Desktop interface also permits an authorized actor to change the signed
default or an existing member's policy after admission. That operation advances
the protected and MLS generations, rotates the archive epoch, and—when a member
policy is changed—publishes a new account-scoped HPKE grant from the same
prepared transaction. Granting `Full` requires the separate full-history
capability; the E2E owner always has it.

The `Since` boundary is the stable identifier of an authenticated archive-epoch
activation event, not a Telegram message date, server order, or local wall
clock. An epoch key exposes every content key wrapped in that epoch, so accepting
an event from the middle of an epoch would also expose earlier content. The
interface may let an administrator choose a human-readable date, but resolves
that choice to the nearest later archive boundary before signing the policy.

## Archive epochs

Message bodies and files use independent random content keys. For cloud history,
those content keys are additionally wrapped under a conversation archive epoch
key.

Archive epochs change on every protected-group transition: admission, client
addition, removal, role or ownership change, and history-policy change. This
keeps archive generation equal to the signed protected generation and avoids a
second partially ordered control stream. Each epoch records the protected-group
generation and authenticated event that activated it. Time- or volume-based
rotation may later add transitions after performance testing; it may not create
an unsigned key boundary.

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

Every granted epoch is checked against the commitment stored in the exact
historical signed transition. `FromJoin` and `Since` are resolved against a
reconstructed historical protected state, not the current member list. A new
installation initially stores only its current epoch; eligible older epochs are
merged later from bounded HPKE grants without replacing conflicting keys.

## Removal and revocation

Removing a participant rotates future live and archive epochs. The removed
participant cannot receive future keys but retains every old key or plaintext
already obtained.

If the account is admitted again, its archive store appends the new admission
epoch after a deliberate generation gap. Content is accepted only when its
archive epoch was activated at that exact protected generation, so a retained
old key cannot be presented as active during the removed interval. A separate
history grant may later add older epochs that policy explicitly permits, but it
never fills the removed interval with an invented key.

Reducing a participant's history policy affects future grants and installations
that do not already possess the removed epoch keys. It cannot erase keys from a
previously authorized or malicious client.

## Forward-secrecy tradeoff

Automatic full-history synchronization deliberately preserves archive keys.
Compromise of an unlocked account archive identity can expose all history
granted to that account. Live MLS forward secrecy does not undo this archive
access. Product documentation must distinguish live-message ratcheting from
cloud-history confidentiality.
