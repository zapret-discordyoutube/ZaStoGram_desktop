# Protected Group State

## Authority

The protected group state, not Telegram membership, defines active accounts,
client credentials, roles, history access, and the current state generation.
Every accepted transition advances the generation by exactly one and carries a
stable object identifier. Duplicate identifiers, skipped generations, unknown
actors, and invalid actor clients are rejected.

Telegram user identifiers are stored only as authenticated bindings inside the
protected member records. A Telegram membership event may start an admission
flow but cannot create such a record.

## Roles and capabilities

Exactly one account is the E2E owner. Ownership transfer is atomic: the new
owner is installed in the same transition in which the previous owner becomes
an administrator. The owner cannot be removed by an ordinary removal event.

Administrators receive an explicit capability mask:

- manage admissions;
- remove ordinary members;
- grant bounded history;
- grant full history;
- change the default history policy.

The default administrator capabilities exclude full-history grants. The owner
must explicitly add that capability. Only the owner appoints administrators,
changes their capabilities, demotes them, or transfers ownership. An
administrator cannot remove another administrator.

## Account and client membership

Membership is account-scoped, while MLS sender state is client-scoped. An
account member contains one or more independent client credentials. A client
identifier is unique across the protected group.

Adding an account requires both protected admission authority and a verified
client authorization signed by the target account identity. Adding another
installation to an existing account requires a verified authorization for that
exact account and client identifier. Any current participant can automatically
carry that verified request into a protected transition; no device pairing or
manual approval is required.

The final client credential of an active account is not removed as a client-only
operation. Removing the account itself is a separate membership transition.

## Local and remote application

Verified remote transitions may be applied while resynchronizing. A locally
initiated administrative transition is additionally checked by the freshness
gate. Until freshness is confirmed, the client may inspect state but cannot
admit members, change roles, grant history, or modify policy.

The state machine performs authorization and invariant checks. Cryptographic
signature, KeyPackage, MLS transcript, and account-credential verification are
performed before it receives a verified transition.

Version one transitions have one fixed binary representation. Unused fields are
required to contain their defined defaults, generations advance by exactly one,
and duplicate transition identifiers remain rejected even if an attacker places
them in a later carrier message.
