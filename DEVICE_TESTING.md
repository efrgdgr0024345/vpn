# Controlled device acceptance

Start this phase after the server/container checks and live boot verification
are recorded in deployments/vpn-lab.json. The owner requested a testing request
when actual device behavior becomes the remaining source of useful evidence.
The existing Access Server is separate and must not be reconfigured.

## First step: private profile transfer

Use a dedicated ED25519 download key generated on Kali. If it already exists,
reuse its public key; do not overwrite an existing private key. To display it:

```sh
cat "$HOME/.ssh/vpn-lab-download.pub"
```

Only the one line beginning `ssh-ed25519` may be supplied for enrollment. Never
share the private key, passphrase, login file or VPN profile. If the key does not
exist, generate a new dedicated key with a passphrase before continuing:

```sh
mkdir -p "$HOME/.ssh"
ssh-keygen -t ed25519 -f "$HOME/.ssh/vpn-lab-download" -C vpn-lab-download
```

Run `prepare-download` for the selected identity, using only that public key.
The owner downloads its `client.ovpn` and `login.txt` through the read-only SFTP
sandbox. Check the SSH host fingerprint against the provider-console value;
never disable host-key verification. Close the download grant after retrieval.
The files stay private; no Actions artifact or chat transfer is used.

## Platform setup

- Kali: import the desktop identity through protected installation and validate
  the matching firewall/resolver policy. Do not launch root OpenVPN against an
  editable home-directory profile or blindly overlay the working VPN's routes.
  A Linux CLI does not automatically apply pushed DNS options. Agree a test
  window or use an isolated client network before changing the owner's routes.
- iPhone/Android: use a current OpenVPN Connect app and the corresponding
  separately issued identity. Record OS/app versions. The Linux desktop
  installer is not a phone app. Transfer profiles privately; remove temporary
  export copies after import. Do not reuse the Kali key on either phone.
- Platform-specific VPN lockdown settings need review and testing. Importing a
  profile alone does not establish always-on protection or prevent every leak.

## Acceptance checks

1. Connect using the initial username/password and that device's own profile.
   Confirm full tunnel traffic and the expected VPN exit, not only a green icon.
2. Let the session span TLS/token renewal. No second password should be typed.
3. Attempt a login from another enrolled device while the first owns the slot.
   It must fail without interrupting the first device's working connection.
4. Disconnect the first normally, then connect the second. Repeat for the third
   identity. There must never be two sessions forwarding traffic together.
5. Check Wi-Fi/mobile-data changes, screen lock, sleep/resume, app termination,
   internet loss and reconnect. Record whether fresh initial authentication is
   required after a new connection; old-token-only reconnect is not admission.
6. Verify DNS, IPv4 and IPv6 containment during startup, connection loss,
   reconnection and shutdown. Server-side tests cannot establish client leaks.
7. Revoke a test device through the workflow. Its session must lose forwarding
   and fresh logins must fail. Reenable only a known uncompromised test key.

Report pass/fail, platform/app versions and sanitized error text. Do not paste
profiles, passwords, token messages or complete management logs. Server recovery
is through the provider console or fixed session-reset workflow, never by
weakening authentication or evicting an owner on an ordinary competing login.
