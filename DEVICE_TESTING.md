# Controlled device acceptance

Start this phase after the server/container checks and live boot verification
are recorded in deployments/vpn-lab.json. The owner requested a testing request
when actual device behavior becomes the remaining source of useful evidence.
The existing Access Server is separate and must not be reconfigured.

## First Kali acceptance step

The corrected lab server has passed post-reboot live acceptance. The owner
already has the private Kali profile and login file; start here without opening
a new download grant.

On the Kali desktop, as the ordinary desktop user, open a terminal in the
reviewed source bundle's `source/vpn-dashboard` directory and run:

```sh
bash install.sh --check
```

This only checks prerequisites; it changes no firewall, DNS or routes. Report
that output before moving on to the guided installation and first connection.
The current build is for controlled acceptance, with the client boot/mobile
limits described below.

## Private profile transfer when needed

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

## Owned Kali app setup

The owner has already downloaded the Kali profile and login file privately,
verified the server host key and confirmed mode 0600. Download access is closed;
do not reopen it merely to install a new public-source application version.

Install the exact reviewed source following `vpn-dashboard/INSTALL.md`, as the
ordinary desktop user. The wizard imports the protected profile; installation
itself changes no networking. Record the installed version/source commit.
Start the owned app from its menu entry and retain access to the local terminal
for recovery. There is no NetworkManager VPN plugin or external VPN frontend.

The first Connect applies a runtime firewall and private VPN DNS. Direct Wi-Fi
Internet remains blocked after disconnect until explicit **Restore normal
networking**. Keep the documented protected recovery commands available offline.
This version requires a regular root-owned resolver file and an empty firewall
or its own previously saved state; it refuses unrelated firewall migration.

Native iPhone/Android apps are not implemented. The separately enrolled identities
have been exercised by Linux test clients, which does not establish phone support.
Do not treat the earlier stock-client proposal as the current rollout plan.
Boot-time client enforcement is also not implemented: this is a controlled
acceptance build, not an always-on or daily-use certification.

## Acceptance checks

1. Connect using the initial username/password and that device's own profile.
   Confirm full tunnel traffic and the expected VPN exit, not only a green icon.
2. Let the session span TLS/token renewal. No second password should be typed.
3. Attempt a login from another enrolled device while the first owns the slot.
   It must fail without interrupting the first device's working connection.
4. Disconnect the first normally, then connect the second. Additional enrolled
   devices require a separate controlled test client until owned phone apps exist.
   There must never be two sessions forwarding traffic together.
5. Check Wi-Fi/mobile-data changes, screen lock, sleep/resume, app termination,
   internet loss and reconnect. Record whether fresh initial authentication is
   required after a new connection; old-token-only reconnect is not admission.
6. Verify DNS, IPv4 and IPv6 containment during startup, connection loss,
   reconnection and shutdown. Server-side tests cannot establish client leaks.
7. Revoke a test device through the workflow. Its session must lose forwarding
   and fresh logins must fail. Reenable only a known uncompromised test key.

For the first physical test, report installation, Connect, local session events,
Disconnect and explicit restoration first. Continue with packet/transition tests
only after those steps work. Report pass/fail, platform/app versions and sanitized
error text. Do not paste
profiles, passwords, token messages or complete management logs. Server recovery
is through the provider console or fixed session-reset workflow, never by
weakening authentication or evicting an owner on an ordinary competing login.
