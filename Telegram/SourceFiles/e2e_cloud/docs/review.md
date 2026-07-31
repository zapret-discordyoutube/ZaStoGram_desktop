# Architecture Review

This review records known tensions so later implementation work does not
silently weaken the agreed model.

## Mandatory invariants

- No plaintext fallback is allowed for unsupported clients or failed protocol
  state.
- A Telegram membership or administrator event is never sufficient by itself
  to grant a content key.
- Password bytes never directly encrypt a message, file, MLS state, or archive
  epoch.
- An MLS sender state is never cloned for concurrent use by two installations.
- Every history grant and E2E role change is authenticated by current protected
  group authority.
- Original file names, MIME types, previews, and captions are never uploaded as
  plaintext carrier metadata.
- Invalid, stale, forked, or unverifiable state fails closed and becomes visible
  to the user. It never triggers a downgrade to ordinary Telegram messaging.
- Telegram object identifiers and ordering are transport hints, not
  cryptographic identity or authenticity.
- No MLS implementation is described as production-ready before the production
  readiness gate at the end of this document is satisfied.

## Active server and Telegram-only transport

Status: partially resolved, with a documented limitation.

Signatures, pinned identities, and authenticated group transitions protect an
established conversation from silent participant injection. TOFU cannot fully
authenticate the first key when the adversary controls the only delivery
channel. Safety codes and gossip improve detection but do not create an
independent trust anchor.

Required follow-up: define the safety-code input, gossip object, identity-change
UI, and exact security claim before implementation.

## Full history and forward secrecy

Status: resolved as an explicit product tradeoff.

MLS may protect live epochs, but full-history synchronization requires retained
archive epoch keys. Compromise of an authorized archive identity can reveal its
granted history. Documentation and UI must not claim that ratcheting makes the
cloud archive forward-secret.

## No visible device binding and concurrent clients

Status: resolved internally.

The product does not ask users to pair devices. Each installation still has an
independent client credential and MLS sender state, authorized by the unlocked
account identity. Mutable sender state must never be copied and used concurrently.

## Telegram administrators and active-server lies

Status: resolved by separating trigger from authority.

Telegram roles trigger proposed changes. Existing signed E2E owners and
administrators authorize the protected transition. A server-provided Telegram
role alone cannot grant plaintext access.

## Password-derived access and offline attack

Status: accepted with mitigation.

The encrypted vault and KDF parameters are stored by the adversarial server, so
password guesses can be tested offline. Argon2id raises cost but password quality
remains essential. The UI needs a strong-passphrase policy and platform-calibrated
parameters.

## Password reset and old history

Status: resolved.

Reset never decrypts the old vault. It creates a new identity. History becomes
available only through a new signed grant from an authorized group owner or E2E
administrator, and only within the group's policy.

## Unsupported clients

Status: resolved without fallback.

Stock clients remain unable to decrypt and are not cryptographic members. The
carrier may look noisy or unusable in stock clients. Carrier encoding and product
messaging must be tested before release.

## Server rollback and partition

Status: product policy decided; protocol details remain open.

Signed generations and gossip can expose some stale or conflicting views, but a
new installation has no independent latest checkpoint. The selected policy
permits history reading and protected local message composition, but gates all
new content delivery and security-critical administration on a valid response
to a fresh random challenge. The nonce prevents the server from replaying a
response recorded before the challenge.

This does not create a global latest-state oracle. Because Telegram remains the
only route, an active server can isolate the installation with an authenticated
participant that is itself stale, or with a malicious former participant still
able to sign for an older branch. The gate proves live authenticated agreement
with the reported checkpoint, not that no newer checkpoint exists.

The protection against stale-membership disclosure therefore depends on
reaching at least one honest witness that has observed the current branch. A
server can also block the challenge and cause denial of service. An absolute
latest-state guarantee would require an independent transparency service,
out-of-band checkpoint, or another trust anchor excluded by the chosen product
constraints.

Exact signed challenge payloads, witness selection strategy, rollback recovery,
and fork recovery must still be completed with the selected MLS engine.

## Production readiness gate

No implementation is production-ready until all of the following exist:

- a complete wire specification and deterministic encoding;
- an RFC 9420-compatible engine selected through a recorded review;
- external interoperability against an independent implementation;
- official test vectors and negative validation tests;
- state-machine and parser fuzzing;
- desktop and mobile secure-storage adapters;
- cross-platform account-vault test vectors;
- Telegram carrier transformation and retry tests;
- performance tests at the target group size;
- an independent cryptographic and application-security audit;
- accurate user-facing documentation of metadata and first-contact limits.
