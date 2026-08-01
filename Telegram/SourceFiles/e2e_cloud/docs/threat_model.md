# Threat Model

## Security goals

The design aims to provide:

- confidentiality of message bodies, file contents, file names, and protected
  metadata from Telegram and storage attackers;
- integrity and sender authentication for protocol events;
- authenticated membership changes after identities have been pinned;
- detection of replayed, corrupted, conflicting, or invalid state transitions;
- removal of a participant from access to future epochs;
- consistent account access from independently installed desktop and mobile
  clients after password unlock;
- explicit, signed grants for access to historical epochs.

## Adversaries

### Passive Telegram server

The server observes and stores all transport envelopes but does not know E2E
private keys. It learns carrier-group membership, timing, sizes, IP addresses,
and approximate activity.

### Active Telegram server

The server may drop, delay, replay, reorder, duplicate, fork, or replace
transport objects. It may lie about ordinary Telegram membership or attempt to
substitute identity material.

Valid established identities and group transitions are protected by signatures,
transcript validation, and pinned state. The server can still deny service.

### Compromised Telegram storage

An attacker may obtain all encrypted messages, files, vault blobs, salts, and
password-derivation parameters. Password strength and the memory-hard KDF are
therefore part of the security boundary.

### Malicious group member

A legitimate member can retain every plaintext and key already granted to that
member. No protocol can revoke copied history. A member may also export or
retransmit plaintext outside the protected group.

### Compromised endpoint

Malware or an attacker controlling an unlocked client can read locally available
plaintext and keys. E2E does not protect an endpoint from itself.

## First-contact limitation

Telegram is the only communication service, and there is no independent key
directory or transparency witness. A server that controls the first delivery
of every identity can present a consistent substituted view before any key has
been pinned.

The chosen practical mitigation is:

- trust on first use;
- stable account safety codes;
- signed key gossip among protected conversations;
- prominent warnings for unexpected identity changes;
- optional out-of-band safety-code comparison.

This detects later substitution and can reveal inconsistent views, but it does
not mathematically prevent a perfectly isolated first-contact attack. Product
claims must state this limitation accurately.

## Latest-state limitation

A random signed freshness challenge proves that a participant is live and
agrees with the checkpoint in its response. With Telegram as the only route, it
does not prove that the participant has observed every newer branch. An active
server can censor up-to-date witnesses and maintain a stale partition. Absolute
rollback prevention on a brand-new installation is therefore outside the
no-backend, no-out-of-band design.

The selected product behavior accepts that residual availability/freshness
risk for usability. A brand-new installation may unlock and read archive keys
already present in its authenticated vault, and may prepare local outgoing
work. Before the first actual send or security-critical administration it
publishes a random challenge and waits for any currently active participant
client to sign a checkpoint response. An equal checkpoint opens the queue, a
newer checkpoint forces resynchronization, and an equal-generation different
hash blocks as a fork. An active server can delay this gate or keep an isolated
witness stale, but cannot make the gated client sign a transition for a
different checkpoint without detection.

Current-checkpoint safety gossip is deterministic and account-signed. A valid
future checkpoint, conflicting state hash, or credential/Telegram binding
conflict blocks the conversation instead of silently changing a TOFU pin.

## Explicit non-goals

- hiding who belongs to the carrier group from Telegram;
- hiding traffic timing or exact availability without a future padding policy;
- recovering plaintext after all authorized users lose their E2E passwords and
  identities;
- deleting plaintext or keys already copied by a participant;
- providing plaintext compatibility to stock Telegram clients;
- continuing to trust a weak password merely because a memory-hard KDF is used.
