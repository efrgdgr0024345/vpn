# Third-party acknowledgements and license sources

The VPN lab builds on maintained projects rather than implementing cryptography.
Their authors and maintainers retain their copyrights. This repository invokes
distribution-provided tools; it does not vendor their source or binaries.

| Component | Credit and license information |
| --- | --- |
| OpenVPN Community | The OpenVPN project and contributors. GPLv2 terms with applicable upstream exceptions; [upstream](https://github.com/OpenVPN/openvpn). Installed notice: `/usr/share/doc/openvpn/copyright`. |
| Easy-RSA | The OpenVPN/Easy-RSA contributors. GPLv2; [upstream](https://github.com/OpenVPN/easy-rsa). Installed notice: `/usr/share/doc/easy-rsa/copyright`. |
| OpenSSL 3 | The OpenSSL project and contributors. Apache License 2.0; [license](https://openssl-library.org/source/license/). Installed notice: `/usr/share/doc/openssl/copyright`. |
| Unbound | NLnet Labs and contributors. BSD-style upstream terms; [upstream](https://github.com/NLnetLabs/unbound). Installed notice: `/usr/share/doc/unbound/copyright`. |
| DNS root data | DNS root-zone and trust-anchor maintainers, IANA/ICANN and Debian maintainers. Data/components retain their applicable terms; installed notice: `/usr/share/doc/dns-root-data/copyright`. |
| Tcl/Tk | Tcl/Tk authors and contributors. Upstream BSD-style/component terms; [Tk source](https://github.com/tcltk/tk). Distribution Tcl/Tk copyright notices remain installed. |
| nftables / Netfilter | The Netfilter project and contributors. See the upstream GPL notices and distribution copyright file; [upstream](https://netfilter.org/projects/nftables/). Installed notice: `/usr/share/doc/nftables/copyright`. |
| Linux kernel | Linux kernel contributors. GPLv2 with applicable upstream notes/exceptions; [upstream](https://www.kernel.org/). The installed kernel package retains its own copyright notices. |
| iproute2 / procps | The respective networking and process-tools contributors; individual components retain their upstream terms. Installed notices: `/usr/share/doc/iproute2/copyright` and `/usr/share/doc/procps/copyright`. |
| NetworkManager / nmcli (optional) | The NetworkManager project and contributors. Used only for read-only OS diagnostics and current DHCP lease discovery, without a VPN plugin. Individual components retain their upstream terms; [upstream](https://networkmanager.dev/). Installed notice: `/usr/share/doc/network-manager/copyright`. |
| systemd | The systemd project and contributors; individual components retain their upstream licenses. [Upstream](https://github.com/systemd/systemd). Installed notice: `/usr/share/doc/systemd/copyright`. |
| Linux-PAM | Linux-PAM contributors; individual components have their own license notices. [Upstream](https://github.com/linux-pam/linux-pam). Installed notice: `/usr/share/doc/libpam-modules/copyright`. |
| OpenSSH | The OpenSSH/OpenBSD authors and contributors. BSD/ISC-style component licenses; [upstream licensing](https://github.com/openssh/openssh-portable/blob/master/LICENCE). Installed notice: `/usr/share/doc/openssh-client/copyright`. |
| slirp4netns | Akihiro Suda, Giuseppe Scrivano and contributors. GPLv2/GPLv2-or-later and bundled component terms; [upstream](https://github.com/rootless-containers/slirp4netns). Installed notice: `/usr/share/doc/slirp4netns/copyright`. Used for the isolated external test client. |
| libslirp | Danny Gasparovski, the Regents of the University of California, Fabrice Bellard and other contributors. BSD-3-clause/MIT-style component terms; [upstream](https://gitlab.freedesktop.org/slirp/libslirp). Installed notice: `/usr/share/doc/libslirp0/copyright`. |
| Python 3 | The Python Software Foundation and contributors. PSF License Version 2 and bundled notices; [license](https://docs.python.org/3/license.html). |
| Debian GNU/Linux | Debian developers, package maintainers and upstream authors. Packages retain their individual licenses and `/usr/share/doc/*/copyright` files; [Debian](https://www.debian.org/). |
| GitHub Actions checkout | GitHub and contributors. MIT; [license at the pinned action revision](https://github.com/actions/checkout/blob/11bd71901bbe5b1630ceea73d27597364c9af683/LICENSE). |
| GitHub CodeQL, dependency review and Dependabot | GitHub and contributors. The actions, query libraries and CodeQL tooling retain their respective upstream licenses/usage terms; [CodeQL action](https://github.com/github/codeql-action), [queries](https://github.com/github/codeql), [dependency review](https://github.com/actions/dependency-review-action), [Dependabot](https://github.com/dependabot/dependabot-core). Used for eligible public-repository CI, not embedded in the client. |

The original desktop dashboard came from the user-supplied `vpn-dashboard.zip`.
Its original author and repository-wide license were not identified in the
supplied files. Existing notices are preserved; no third-party authorship or
blanket relicensing is claimed here. A repository-wide license for the original
project has not been selected. These acknowledgements do not replace the
upstream license terms or the installed distribution notices.

## Private administration browser tools

The optional isolated browser launcher uses the installed Mozilla Firefox/Firefox
ESR browser and Mozilla NSS `certutil` (provided by the distribution's
`libnss3-tools` package). These tools are not vendored in this repository. Mozilla
provides their upstream code and license notices:
[Firefox](https://www.mozilla.org/firefox/),
[NSS](https://firefox-source-docs.mozilla.org/security/nss/), and the
[Mozilla Public License 2.0](https://www.mozilla.org/MPL/2.0/).
The panel's Python, HTML, JavaScript and CSS implementation is project source;
it includes no external analytics or CDN assets.
