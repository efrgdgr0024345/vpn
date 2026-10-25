# Proposed VPN system: threat model and design

Status: design proposal, not an implemented or deployed VPN server. This document
captures the critical review and a recommended starting architecture. The current
desktop prototype and its installer remain separate from this proposed system.
Custom bootloader work is deferred.
New feature development is paused while the existing Access Server VPN is
recovered. See PROJECT_STATUS.md for the reconciled implementation/deployment state.

## The goal

Permit one approved device to hold one authorized VPN session. A stolen account
password alone must not authorize that session. Initial access reaches only a
small authorization service. Broader access requires proof from the enrolled
device and an exclusive, expiring grant enforced on the server.

The security benefit is controlled authorization and containment of initial
access. Changing usernames and making session passwords invisible to a human
does not establish who is connecting.

## Critical review

1. A password-only credential service is another way to obtain the same access.
   An attacker with the original password can complete the same exchange unless
   the service checks an independent, previously enrolled device key or MFA.
2. Single-session lockout is an availability policy and an investigative signal.
   It is not proof of intrusion. Stale sessions and connection failures can cause
   the same symptom; a successful attacker can also occupy the slot first.
3. A second tunnel adds routing, DNS, firewall and crash-recovery transitions.
   Every overlapping or half-completed state needs defined authorization. Merely
   allowing two connections for a moment does not identify the intended pair.
4. A sandbox must constrain actual packets and reachable services. An ordinary
   VPN user account or a restricted shell does not provide network containment.
5. The client key is the real credential. Malware controlling an authorized
   running device can use its session/key even if no human sees its password.
   Hardware-backed keys reduce extraction; they do not prevent every misuse.
6. A VPS administrator can change routing, authorization and logging. Namespace
   isolation does not survive compromise of the host's root account. HTTPS and
   other end-to-end encryption remain necessary for application confidentiality.
7. New protocol code is security-critical work. Use maintained VPN/TLS mechanisms
   and established certificate authentication rather than inventing cryptography.

## Recommended first architecture

Use a maintained OpenVPN server initially, consistent with the existing client.
Separate its restricted initial network from the authorization service, ordinary
VPN forwarding and management access. A Linux network namespace supplies a
network boundary; a hardened service account and service sandbox limit process
privileges. The packet policy must still be verified independently.

The initial session can reach only the authorization service's fixed internal
address and TLS port. It cannot forward to the internet, use arbitrary DNS, reach
the host's management services, reach other clients, or escape over IPv6.
Rate-limit initial sessions and authentication attempts separately from active
VPN session ownership.

The authorization service requires possession of a previously registered device
key, using a standard client certificate/mutual TLS exchange with fresh protocol
challenges. Device enrollment and replacement require independent administrator
authorization; knowledge of the bootstrap password must not enroll a new key.
Optional MFA supplies another check for interactive authorization.

Prefer one authenticated tunnel whose forwarding permissions are promoted after
authorization. The server must bind the grant to its verified connection identity
and enforce anti-spoofing; a client-supplied address, common-name header or claimed
device ID is insufficient. Confirm that the chosen server integration supports
this mapping before selecting its deployment configuration.

If separate bootstrap/main VPN instances are required, issue a short-lived,
single-use grant bound to the enrolled device key and the intended transition.
Only the intended new session can redeem it. Keep the bootstrap network restricted
throughout; revoke its authorization after the main session is confirmed. Test
dual-tunnel routing/DNS/firewall behavior explicitly. Rotating operating-system
accounts is unnecessary for either variant.

## Server authorization rules

| State | Allowed behavior |
| --- | --- |
| Restricted | Talk to the authorization service only; no full-access slot owned |
| Pending | A proved device has a bounded transition grant; broad forwarding still denied |
| Active | Exactly one verified session owns a bounded grant; only configured traffic is forwarded |
| Revoked/expired | Broad forwarding denied; old credentials and session generations rejected |

- Allocate or redeem an active grant through a transactional server operation.
  Two simultaneous requests must never create two active owners.
- Define “one connection” as one authorized VPN session. Rejected initial
  requests and independent administrative recovery are separate policies.
- Reject additional session claims while a healthy active grant exists. A later
  password login must not replace or disconnect its owner.
- A grant contains the verified principal, device key binding, session binding,
  expiry and revocation generation. Possession of a bearer string alone is
  insufficient. Keep credentials out of URLs, shell arguments and logs.
- Enforce expiry/revocation in the forwarding path. A dead broker, lost client or
  failed cleanup handler must not leave broad access authorized indefinitely.
- On restart, begin with broad forwarding denied and require fresh authorization.
  Specify clock-change behavior before relying on persistent expiration times.
- Administrator reset denies forwarding, invalidates old grant generations,
  disconnects owned sessions and clears pending transitions. Rotate compromised
  bootstrap credentials and revoke compromised device keys as separate actions.
- Record authentication results, state transitions and resets without recording
  passwords, private keys or usable tokens. Unexpected contention is investigable
  evidence, not an automatic conclusion about compromise.

## Independent recovery and client behavior

Retain the VPS provider console or SSH with a separate administrative key and
appropriate access restrictions. Recovery must work when the VPN is unavailable.
The VPN-only forwarding policy must not accidentally remove this recovery path.

On the client, the kill switch exists before connection and remains active across
authentication, promotion, failure, reconnect and shutdown. Provide no all-app
Wi-Fi bypass. Integrate DNS through a supported, reviewed resolver mechanism and
make the IPv6 policy explicit. Never treat an interface or a PID as connection
health or authorization evidence.

The current desktop prototype rejects a second tunnel/OpenVPN process. It cannot
perform the proposed two-tunnel handoff without a separately implemented client
state machine. Its strict homegrown profile and nftables parsers also need
broader compatibility review. The certificate-name spacing bug identified in
the audit was subsequently fixed locally with regression tests; real server
profiles still need integration validation. Its networking tests are mocked. The prototype is not evidence that the new server design works.

## Required validation before deployment

1. Stolen bootstrap password plus an unregistered device never obtains broad
   access or reserves the active grant indefinitely.
2. Replayed/expired grants, old device proofs, substituted device keys and
   simultaneous redemption attempts are rejected.
3. Real packet tests show that restricted sessions cannot reach internet, DNS,
   IPv6 destinations, host management, other clients or unintended local services.
4. Real packet tests show that active permissions disappear on expiry/revocation,
   broker/VPN failure and restart, including interrupted firewall updates.
5. The client leaks no direct IPv4/IPv6/DNS traffic during connection loss,
   promotion, reconnect, suspend/resume or failed startup.
6. Administrator recovery revokes outstanding access, and stale credentials
   cannot restore it after reset. Recovery remains available with the VPN down.
7. Logs support diagnosis of real contention versus stale state without exposing
   credentials. Repeated rejected initial requests are rate-limited.

No production claim follows from unit tests alone. Implement a local isolated
integration environment and these acceptance checks before any live VPS migration.
