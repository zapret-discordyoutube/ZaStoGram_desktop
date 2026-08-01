# Open Questions

## Protocol and identity

- Which reviewed hybrid post-quantum MLS suite and migration path will follow
  the mandatory version-one suite when implementations mature?
- Which independent MLS implementation will be the long-term differential
  interoperability oracle?
- What reviewed signed snapshot format will compact groups that approach the
  65,536-control-object and generation lifecycle bound?

## Telegram carrier

- What server transformations affect bytes, metadata, ordering, forwarding, or
  document identity?
- How are missing, deleted, copied, and migrated carrier groups handled?
- Can a stock client accidentally forward a useful encrypted object into another
  context, and how does carrier binding reject it?

## Vault and platform integration

- What Argon2id parameters satisfy the oldest supported desktop and mobile
  devices?
- Should a future independent transparency service be optional for users who
  want stronger brand-new-installation rollback detection than the chosen
  Telegram-only automatic freshness witness can provide?

## History and files

- How are large history grants compressed, paged, and authenticated?
- What default chunk size best balances resumability, storage overhead, and
  mobile memory use within the authenticated version-one chunk layout?
- What padding policy is worth its bandwidth cost?
- What deletion guarantees can be stated accurately for Telegram-held
  ciphertext and participant-held keys?

## Product policy

- Should a visible multi-party quorum be added for selected operations after
  the initial owner-only authorization model ships?
- Which desktop/mobile release sequence can reuse the same protocol core while
  keeping platform local-storage and background-sync behavior testable?
- What battery, background execution, and push-wakeup policy lets a phone answer
  freshness challenges without requiring a connected Desktop client?
