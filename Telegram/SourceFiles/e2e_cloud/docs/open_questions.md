# Open Questions

## Protocol and identity

- Which RFC 9420 implementation will provide the production MLS engine?
- Which reviewed hybrid post-quantum MLS suite and migration path will follow
  the mandatory version-one suite when implementations mature?
- Which deterministic encodings will be used inside each application payload?
- What signed gossip protocol detects Telegram split views without a custom
  witness service?
- How are valid concurrent commits and forks recovered?
- How long are KeyPackages valid, and how are depleted packages replenished
  through Telegram-only storage?

## Telegram carrier

- How are opaque carrier objects hidden or grouped in the protected client UI?
- What server transformations affect bytes, metadata, ordering, forwarding, or
  document identity?
- How are missing, deleted, copied, and migrated carrier groups handled?
- Can a stock client accidentally forward a useful encrypted object into another
  context, and how does carrier binding reject it?

## Vault and platform integration

- What Argon2id parameters satisfy the oldest supported desktop and mobile
  devices?
- Which exact Windows, macOS, all-other desktop, Android, and iOS credential
  stores wrap the locally remembered vault key?
- What password strength and normalization policy is consistent across every
  platform?
- How are stale encrypted vault generations detected on a brand-new installation?

## History and files

- How often do archive epochs rotate?
- How are large history grants compressed, paged, and authenticated?
- Which streaming AEAD construction and chunk size are used for files?
- What padding policy is worth its bandwidth cost?
- What deletion guarantees can be stated accurately for Telegram-held
  ciphertext and participant-held keys?

## Product policy

- Should a visible multi-party quorum be added for selected operations after
  the initial owner-only authorization model ships?
- What is the migration plan when mobile support is introduced after desktop?
