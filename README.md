This guide is a collection of techniques for improving the security and privacy of [Apple silicon](https://support.apple.com/116943) Mac computers running a [currently supported](https://support.apple.com/HT201222) version of macOS. **Using Macs with Intel CPUs leaves you open to [security vulnerabilities](https://github.com/axi0mX/ipwndfu?tab%253Dreadme-ov-file#checkm8) on the hardware level that Apple can't patch**. [Apple silicon](https://en.wikipedia.org/wiki/Apple_silicon) Macs are considered the minimum recommendation but as a general rule, newer chips are always more secure.

This guide targets power users who wish to adopt enterprise-standard security, but is also suitable for novice users with an interest in improving privacy and security.

For securing computers in an organization, use the [official NIST guidelines for macOS](https://github.com/usnistgov/macos_security).

A system's security ultimately depends on its administrator's capabilities. No single technology, piece of software, or technique can guarantee perfect security.

This guide is provided "as is" - without warranties of any kind. You are solely responsible for any consequences of following it.

To suggest a change, submit a [pull request](https://github.com/drduh/macOS-Security-and-Privacy-Guide/pulls) or open an [issue](https://github.com/drduh/macOS-Security-and-Privacy-Guide/issues).

- [Basics](#basics)
- [Threat modeling](#threat-modeling)
   * [Assets](#assets)
   * [Adversaries](#adversaries)
   * [Capabilities](#capabilities)
   * [Mitigations](#mitigations)
- [Hardware](#hardware)
- [Installing macOS](#installing-macos)
   * [System activation](#system-activation)
   * [Apple Account](#apple-account)
   * [App Store](#app-store)
   * [Virtualization](#virtualization)
- [First boot](#first-boot)
- [Admin and user accounts](#admin-and-user-accounts)
   * [Caveats](#caveats)
   * [Setup](#setup)
- [Firmware](#firmware)
- [FileVault](#filevault)
- [Lockdown Mode](#lockdown-mode)
- [Firewall](#firewall)
   * [Application layer firewall](#application-layer-firewall)
   * [Third-party firewalls](#third-party-firewalls)
   * [Packet filter](#packet-filter)
- [Services](#services)
- [Siri Suggestions and Spotlight](#siri-suggestions-and-spotlight)
- [Homebrew](#homebrew)
- [DNS](#dns)
   * [DNS profiles](#dns-profiles)
   * [Hosts file](#hosts-file)
   * [DNSCrypt](#dnscrypt)
   * [Dnsmasq](#dnsmasq)
- [Certificate authorities](#certificate-authorities)
- [Privoxy](#privoxy)
- [Browser](#browser)
   * [Firefox](#firefox)
   * [Chrome](#chrome)
   * [Safari](#safari)
   * [Web browser privacy](#web-browser-privacy)
- [Tor](#tor)
- [VPN](#vpn)
- [PGP/GPG](#pgpgpg)
- [Messengers](#messengers)
   * [XMPP](#xmpp)
   * [Signal](#signal)
   * [iMessage](#imessage)
- [Viruses and malware](#viruses-and-malware)
   * [Downloading Software](#downloading-software)
   * [App Sandbox](#app-sandbox)
   * [Hardened Runtime](#hardened-runtime)
   * [Antivirus](#antivirus)
   * [Gatekeeper](#gatekeeper)
- [System Integrity Protection](#system-integrity-protection)
- [Metadata and artifacts](#metadata-and-artifacts)
- [Passwords](#passwords)
- [Backup](#backup)
- [Wi-Fi](#wi-fi)
- [SSH](#ssh)
- [Physical access](#physical-access)
- [System monitoring](#system-monitoring)
   * [Logs](#logs)
   * [OpenBSM audit](#openbsm-audit)
   * [DTrace](#dtrace)
   * [Processes](#processes)
   * [Network](#network)
- [Miscellaneous](#miscellaneous)
- [Related software](#related-software)
- [Additional resources](#additional-resources)

# Basics

Apply general security best practices:

- Create a [threat model](#threat-modeling)
  * What are you trying to protect and from whom? Is the adversary a three-letter agency, a nosy eavesdropper on the network, or a determined [APT](https://en.wikipedia.org/wiki/Advanced_persistent_threat) orchestrating a campaign against you?
  * Recognize threats and how to reduce attack surface against them.

- Keep the system and software up to date
  * Patch the operating system and all installed software regularly.
  * System updates can be completed in the [settings](https://support.apple.com/guide/mac-help/keep-your-mac-up-to-date-mchlpx1065) or installed with the `softwareupdate` command-line utility - neither requires an Apple account.
  * Subscribe to announcement mailing lists like [Apple security-announce](https://lists.apple.com/mailman3/lists/security-announce.lists.apple.com/).

- Encrypt sensitive data
  * In addition to [FileVault](https://support.apple.com/guide/mac-help/protect-data-on-your-mac-with-filevault-mh11785) volume encryption, consider using the [built-in password manager](https://support.apple.com/105115) to protect passwords and other sensitive data.

- Assure data availability
  * Create [regular backups](https://support.apple.com/104984) of critical data and be ready to [restore from a backup](https://support.apple.com/102551) in case of compromise.
  * [Encrypt locally](https://support.apple.com/guide/mac-help/keep-your-time-machine-backup-disk-secure-mh21241) before copying backups to unencrypted external media or the "cloud"; alternatively, enable [end-to-end encryption](https://support.apple.com/guide/security/advanced-data-protection-for-icloud-sec973254c5f).
  * Verify backups by accessing them regularly.

- Click carefully
  * Ultimately, the security of a system depends on the capabilities of its administrator.
  * Take care when installing new software: install it only from sources the developer identifies as official, such as their website or GitHub repository.

# Threat modeling

The first and most important step for security and privacy is to create a [threat model](https://owasp.org/www-community/Threat_Modeling). You need to understand your adversaries in order to defend against them. Each person will have their own needs so everyone's threat model will be different. Threat models tend to evolve over time as our situation changes, so be sure to periodically reassess your threat model.

## Assets

Assets may include your phone, laptop, passwords stored on various devices, and browsing history. List them, starting with the assets that matter most to protect.

## Adversaries

Define whom you are defending against. Start by defining the motivation they might have to attack assets. [Financial gain](https://www.verizon.com/business/resources/reports/dbir/) is a big motivator for many attackers, for example.

## Capabilities

To counter adversaries, understand both their capabilities and limitations. Rank them from unsophisticated to highly advanced. For example, a common thief is not very sophisticated; they will likely be stopped by basic things like simply having a password and drive encryption on devices. An advanced adversary might require fully turning off devices when not in use to clear the keys from RAM and a long diceware password.

## Mitigations

Choose the best mitigation for each threat. For example, avoid writing passwords on paper if a roommate might find them, or encrypt storage to protect its data if it is stolen.

Balance security and usability: every mitigation should counter some capability of your adversaries, otherwise you might be making your life inconvenient without reason. If you can't think of any more capabilities your adversaries might have and you've implemented mitigations for them all, your work is done.

The following is an example of assets to protect:

Adversary | Motivation | Capabilities | Mitigation
:-: | :-: | :-: | :-:
Roommate | See private chats or browsing history | Close proximity; can see screen or watch type in password | Use biometrics, use privacy screen, keep phone locked when not using it
Thief | Unlock phone and steal personal info and drain bank accounts, sell phone for money | Shoulder surf to see password, steal device when not looking while it's logged in | Keep phone in sight or on person at all times, keep locked when not in use, use biometrics to avoid typing password in public, use Find My or similar service to track/remotely disable stolen device
Criminal | Financial gain | Social engineering, readily-available malware, password reuse, exploiting vulnerabilities | Use sandboxing, enable security features in OS, keep OS and all software updated and turn on automatic updates
Corporation | Marketing based on user data | Telemetry and behavioral data collection | Block network connections, reset unique identifiers, avoid adding payment data
Nation State/APT | Targeted surveillance | Passive surveillance of internet infrastructure, advanced computers for cracking encryption/analysis of packets | Use open source e2ee, use strong diceware passwords for devices, use hardware with secure element for secure encryption, shut down devices when not using them, software tripwire/honeypot/[canary tokens](https://canarytokens.org/)

Read more about threat modeling [here](https://www.netmeister.org/blog/threat-model-101.html).

# Hardware

macOS is most secure running on [Apple hardware](https://support.apple.com/guide/security/hardware-security-overview-secf020d1074/1/web/1) with Apple silicon. The newer the Mac, the better. Avoid hackintoshes and Macs that don't support the latest macOS, as Apple does not [patch all vulnerabilities](https://support.apple.com/guide/deployment/about-software-updates-depc4c80847a) in versions that aren't the most recent one.

When purchasing a Mac, consider paying in cash rather than ordering online or purchasing with a credit/debit card, to limit identifying information linked to the purchase.

When using a wireless keyboard, mouse, headphones, or other accessory, Apple accessories are generally the most secure option because macOS updates them automatically. They also support the latest [Bluetooth features](https://support.apple.com/guide/security/bluetooth-security-sec82597d97e/web) like BLE Privacy which randomizes the Bluetooth hardware address to prevent tracking, which is not guaranteed with third-party accessories.

# Installing macOS

There are several ways to [install macOS](https://support.apple.com/102662)

Install the latest version of macOS the hardware supports: newer versions include security patches and other improvements unavailable in older releases.

## System activation

As part of Apple's [theft prevention system](https://support.apple.com/102541), Apple silicon Macs will need to activate with Apple's servers every time macOS is installed to check against the database of stolen or activation-locked Macs.

Read about how this process works [here](https://support.apple.com/guide/security/localpolicy-signing-key-creation-management-sec1f90fbad1).

## Apple Account

An Apple Account is not required to use macOS, but creating one requires a phone number and, by default, syncs a substantial amount of [data](https://www.apple.com/legal/privacy/data/en/apple-id/).

You can [disable](https://support.apple.com/102651) the syncing later or enable [end-to-end encryption](https://support.apple.com/guide/security/advanced-data-protection-for-icloud-sec973254c5f/web) for data stored in iCloud.  You can [control the data](https://support.apple.com/102283) associated with Apple Account or completely delete it.

An Apple Account is required in order to access the App Store and use most Apple services like iCloud, Apple Music, etc.

## App Store

The Mac App Store is a [curated](https://developer.apple.com/app-store/review/guidelines) software repository.
Apps distributed through it are required to use [App Sandbox](https://developer.apple.com/documentation/security/app_sandbox/protecting_user_data_with_app_sandbox) and [Hardened Runtime](https://developer.apple.com/documentation/security/hardened_runtime), as well as offering automatic updates.

App Store distribution provides additional platform review and sandboxing requirements, but also requires an Apple Account, which can create a privacy risk.

## Virtualization

On Apple silicon, macOS includes Apple's Virtualization framework, which supports macOS and Windows 11 ARM virtual machines through tools such as:

* [UTM](https://mac.getutm.app/) - Follow the [documentation](https://docs.getutm.app/guest-support/macos) to create macOS and other VMs.
* [VirtualBuddy](https://github.com/insidegui/VirtualBuddy) - GUI for virtualizing macOS 12+ on Apple silicon.
* [Bushel](https://getbushel.app/) - A lightweight, free VM app. On first launch, select "Ask App Not to Track".
* [VMware Fusion](https://knowledge.broadcom.com/external/article/315638/download-and-install-vmware-fusion.html) - Now free under Broadcom. Clean UI, easy macOS setup, and supports Windows 11 ARM.
* [tart (CLI)](https://tart.run/) - Command‑line VM control; install with Homebrew.
* [Parallels](https://www.parallels.com/) - Paid option with strong integration.

> [!WARNING]
> VMware requires a Broadcom account and acceptance of agreements before download.
> Parallels requires an account, payment details, and other data - see the [privacy notice](https://my.parallels.com/data_reminder).

# First boot

When macOS starts for the first time, **Setup Assistant** requires the creation of a primary account.

Set a [strong password](https://www.eff.org/dice) without a hint.

Avoid using personally-identifiable names, as the respective system attributes (such as *John Appleseed's MacBook*) appear on networks.

The system name can be configured in **System Settings > About** or with the following commands:

```bash
sudo scutil --set ComputerName MacBook
sudo scutil --set LocalHostName MacBook
```

# Admin and user accounts

The first user account created is always an administrator account. Administrator accounts belong to the admin group and can use sudo to run commands with elevated privileges, including as root. Any program the administrator executes can potentially obtain the same access, making this a security risk.

Utilities like `sudo` may have vulnerabilities which can be [exploited](https://bogner.sh/2014/03/another-mac-os-x-sudo-password-bypass/) by concurrently-running software.

It is considered a [best practice](https://help.apple.com/machelp/mac/10.12/index.html#/mh11389) to use a separate standard account for day-to-day work and use the admin account for installations and system configuration.

It is not strictly required to ever login with the admin account via the macOS login screen. When a Terminal command requires administrator privileges, the system will prompt for authentication and Terminal then continues using those privileges. To that end, Apple provides [recommendations](https://support.apple.com/102099) for hiding the admin account and its home directory.

## Caveats

* Only administrators can install applications in `/Applications` (local directory). Finder and Installer will prompt a standard user with an authentication dialog. Many applications can be installed in `~/Applications` instead (the directory can be created). As a rule of thumb: applications that do not require admin access – or do not complain about not being installed in `/Applications` – should be installed in the user directory, the rest in the local directory. Mac App Store applications are still installed in `/Applications` and require no additional authentication.
* `sudo` is not available in shells of the standard user, which requires using `su` or `login` to enter a shell of the admin account. This can make some maneuvers trickier and requires some basic experience with command-line interfaces.
* System Settings and several system utilities (e.g. Wi-Fi Diagnostics) will require root privileges for full functionality. Many panels in System Settings need to be unlocked by selecting the lock icon. Some applications will simply prompt for authentication upon opening, others must be opened by an admin account directly to get access to all functions (e.g. Console).
* There are third-party applications that will not work correctly because they assume that the user account is an admin. These programs may have to be executed by logging into the admin account, or by using the `open` utility.
* See additional discussion in [issue 167](https://github.com/drduh/macOS-Security-and-Privacy-Guide/issues/167).

## Setup

Accounts can be created and managed in System Settings. On settled systems, it is generally easier to create a second admin account and then demote the first account. This avoids data migration. Newly installed systems can also just add a standard account.

Demoting an account can be done either from the new admin account in System Settings – the other account must be logged out – or by executing these commands (it may not be necessary to execute both, see [issue 179](https://github.com/drduh/macOS-Security-and-Privacy-Guide/issues/179)):

```bash
sudo dscl . -delete /Groups/admin GroupMembership <username>
sudo dscl . -delete /Groups/admin GroupMembers <GeneratedUID>
```

To find the **GeneratedUID** of an account:

```bash
dscl . -read /Users/<username> GeneratedUID
```

See also [this post](https://superuser.com/a/395738) for more information about how macOS determines group membership.

# Firmware

Verify that firmware security is set to [Full Security](https://support.apple.com/guide/mac-help/mchl768f7291/mac) to prevent tampering with the system. This is the default setting.

# FileVault

All Apple silicon Macs encrypt storage by default. Enabling [FileVault](https://support.apple.com/guide/mac-help/mh11785/mac) requires a password before macOS can access the encrypted volume. The EFF has a guide on generating [strong but memorable passwords](https://www.eff.org/dice).

The FileVault password also acts as a [firmware password](https://support.apple.com/102384) which prevents booting from anything other than the designated startup disk, accessing [Recovery](https://support.apple.com/guide/mac-help/macos-recovery-a-mac-apple-silicon-mchl82829c17/15.0/mac/15.0#mchl5abfbb29), and [reviving](https://support.apple.com/108900) it with DFU mode.

FileVault will prompt to set a recovery key - store this key somewhere safe. You will have the option to use iCloud to unlock the disk; however, anyone with access to this iCloud account will be able to unlock it as well.

# Lockdown Mode

[Lockdown Mode](https://support.apple.com/105120), which disables certain system and application features, is recommended and may significantly reduce attack surface.

When Lockdown Mode is enabled, Safari has an option to exclude individual trusted websites from its restrictions.

# Firewall

There are several types of firewalls available for macOS.

## Application layer firewall

The built-in firewall provides basic protection and blocks incoming connections only. It can neither monitor nor block outgoing connections.

It can be controlled by the **Firewall** tab of **Network** in **System Settings**, or with the following commands.

Enable the firewall and Stealth Mode:

```bash
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on
```

Attackers scan networks to identify systems they may be able to target. When Stealth Mode is enabled, the system does not respond to ICMP ping requests and does not answer to connection attempts from closed ports.

Prevent built-in and downloaded software from automatically receiving incoming connections:

```bash
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setallowsigned off
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setallowsignedapp off
```

Applications signed by a valid certificate authority are automatically added to the allowlist, rather than prompting the user to authorize them. Apps included in macOS are signed by Apple and are allowed to receive incoming connections when this setting is enabled.

If an unsigned app not listed in the firewall list is opened, a dialog appears with options to Allow or Deny connections. If allowed, macOS signs the application and adds it to the firewall list. If denied, macOS adds it to the list and denies incoming connections.

After interacting with `socketfilterfw`, restart the process by sending a line hangup signal:

```bash
sudo pkill -HUP socketfilterfw
```

## Third-party firewalls

Applications such as [Little Snitch](https://www.obdev.at/products/littlesnitch/index.html), [Radio Silence](https://radiosilenceapp.com/), and [LuLu](https://objective-see.com/products/lulu.html) provide a balance between usability and security.

These programs are capable of monitoring and blocking both incoming and outgoing connections. However, they may require the use of a closed-source [system extension](https://support.apple.com/HT210999).

If frequent allow-or-block prompts are overwhelming, begin with Silent Mode configured to allow connections. Review the configuration periodically to understand each application's network activity.

> [!NOTE]
> A root-level compromise can undermine host-based network controls, depending on the product and system configuration.

## Packet filter

macOS also includes a powerful, highly customizable kernel-level firewall. However, it is the most complex option and is managed with `pfctl` and configuration files.

pf can also be controlled with a GUI application such as [Murus](https://www.murusfirewall.com/).

Many books and articles cover the pf firewall. The following example shows how to block traffic by IP address.

Add the following into a file called `pf.rules`:

```
wifi = "en0"
ether = "en7"
set block-policy drop
set fingerprints "/etc/pf.os"
set ruleset-optimization basic
set skip on lo0
scrub in all no-df
table <blocklist> persist
block in log
block in log quick from no-route to any
block log on $wifi from { <blocklist> } to any
block log on $wifi from any to { <blocklist> }
antispoof quick for { $wifi $ether }
pass out proto tcp from { $wifi $ether } to any keep state
pass out proto udp from { $wifi $ether } to any keep state
pass out proto icmp from $wifi to any keep state
```

Use the following commands to control the firewall:

function | command
-: | :-
enable firewall with config | `sudo pfctl -e -f pf.rules`
disable firewall | `sudo pfctl -d`
add address to blocklist | `sudo pfctl -t blocklist -T add 1.2.3.4`
view the blocklist | `sudo pfctl -t blocklist -T show`
create log interface | `sudo ifconfig pflog0 create`
monitor blocked packets | `sudo tcpdump -ni pflog0`

pf can block access to ranges of network addresses, for example to an entire organization:

Query [Merit RADb](https://www.radb.net/) for the list of networks in use by an autonomous system, like [Facebook](https://ipinfo.io/AS32934):

```bash
whois -h whois.radb.net '!gAS32934'
```

Copy and paste the list of networks returned into the blocklist command:

```bash
sudo pfctl -t blocklist -T add 31.13.24.0/21 31.13.64.0/24 157.240.0.0/16
```

Confirm the addresses were added:

```console
$ sudo pfctl -t blocklist -T show
No ALTQ support in kernel
ALTQ related functions disabled
   31.13.24.0/21
   31.13.64.0/24
   157.240.0.0/16
```

Confirm network traffic is blocked to those addresses (DNS requests will still work):

```console
$ dig a +short facebook.com
157.240.2.35

$ curl --connect-timeout 5 -I http://facebook.com/
*   Trying 157.240.2.35...
* TCP_NODELAY set
* Connection timed out after 5002 milliseconds
* Closing connection 0
curl: (28) Connection timed out after 5002 milliseconds

$ sudo tcpdump -tqni pflog0 'host 157.240.2.35'
IP 192.168.1.1.62771 > 157.240.2.35.80: tcp 0
IP 192.168.1.1.62771 > 157.240.2.35.80: tcp 0
IP 192.168.1.1.62771 > 157.240.2.35.80: tcp 0
IP 192.168.1.1.62771 > 157.240.2.35.80: tcp 0
IP 192.168.1.1.62771 > 157.240.2.35.80: tcp 0
```

Outgoing TCP SYN packets are blocked, so a TCP connection is not established, blocking traffic to the destination host at the IP layer.

See [drduh/config/scripts/pf-blocklist.sh](https://github.com/drduh/config/blob/main/scripts/pf-blocklist.sh) for more inspiration.

# Services

Services on macOS are managed by [launchd](https://en.wikipedia.org/wiki/Launchd).

Administrator accounts can modify services and extensions in [System Settings](https://support.apple.com/guide/mac-help/change-login-items-settings-mtusr003).

function | command
-: | :-
view loaded user jobs | `launchctl list`
view loaded system jobs | `sudo launchctl list`
examine a service | `launchctl list com.apple.Finder`
list installed system daemons | `ls /System/Library/LaunchDaemons`
list installed system agents | `ls /System/Library/LaunchAgents`
read a service configuration  | `defaults read /System/Library/LaunchAgents/com.apple.Finder`

> [!IMPORTANT]
> System services are protected by SIP. Do not disable SIP just to modify system services as it is a fundamental part of the macOS security model. Disabling system services may also cause system instability.

To view the status of services:

```bash
find /var/db/com.apple.xpc.launchd/ -type f -print -exec defaults read {} \; 2>/dev/null
```

See [script management with launchd](https://support.apple.com/guide/terminal/script-management-with-launchd-apdc6c1077b-5d5d-4d35-9c19-60f2397b2369) and [launchd.info](https://launchd.info/) for more information.

# Siri Suggestions and Spotlight

Apple is moving many Siri functions to on-device processing, but using Siri Suggestions or Spotlight may still send some information to Apple. See Apple's [Privacy Policy](https://www.apple.com/legal/privacy/data/en/siri-suggestions-search/) to see exactly what is sent and how to disable it.

# Homebrew

If a program is not available through the App Store, consider using [Homebrew](https://brew.sh/).

> [!WARNING]
> Homebrew requests "App Management" (or "Full Disk Access") permission to Terminal.
> This is risky: any non-sandboxed application can execute code with Terminal's TCC permissions by adding a malicious command to the shell configuration.
> Treat granting App Management or Full Disk Access permissions as equivalent to disabling TCC protections for processes that can control or execute commands through Terminal.

Remember to periodically run `brew upgrade` on trusted and secure networks to download and install software updates. To get information on a package before installation, run `brew info <package>` and check its formula online. You may also wish to enable [additional security options](https://github.com/drduh/macOS-Security-and-Privacy-Guide/issues/138), such as `HOMEBREW_NO_INSECURE_REDIRECT=1`

According to [Homebrew's Anonymous Analytics](https://docs.brew.sh/Analytics), Homebrew gathers anonymous analytics and reports these to a self-hosted [InfluxDB](https://en.wikipedia.org/wiki/InfluxDB) instance.

To opt out of Homebrew analytics, run `brew analytics off` or set `HOMEBREW_NO_ANALYTICS=1` in the shell startup file.

# DNS

## DNS profiles

macOS 11 introduced "DNS configuration profiles" to configure encrypted DNS, filter domains and use DNSSEC.

DNS profiles [can be created](https://dns.notjakob.com/) or obtained from providers such as [Quad9](https://docs.quad9.net/Setup_Guides/MacOS/Big_Sur_and_later_(Encrypted)/#download-profile), [AdGuard](https://adguard-dns.io/en/public-dns.html) and [NextDNS](https://nextdns.io/).

## Hosts file

Use the [hosts file](https://en.wikipedia.org/wiki/Hosts_(file)) to block domains associated with malware, advertising, and other unwanted services.

Edit the hosts file with `sudo vim /etc/hosts`

To block a domain by [A record](https://en.wikipedia.org/wiki/List_of_DNS_record_types), append any one of the following lines to `/etc/hosts`:

```
0 example.com
0.0.0.0 example.com
127.0.0.1 example.com
```

> [!NOTE]
> IPv6 uses AAAA records rather than A records: block IPv6 connections by including `::1 example.com` entries.

Many domain lists are available online. Before appending one to `/etc/hosts`, ensure each entry begins with `0`, `0.0.0.0`, or `127.0.0.1`, and retain the `127.0.0.1 localhost` entry.

Popular hosts lists include:
* [StevenBlack/hosts](https://github.com/StevenBlack/hosts)
* [Sinfonietta/hostfiles](https://github.com/Sinfonietta/hostfiles)
* [someonewhocares.org](https://someonewhocares.org/hosts/zero/hosts)

To append a remote hosts list to `/etc/hosts`, use `tee`:

```bash
curl https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts | sudo tee -a /etc/hosts
```

[Little Snitch](#third-party-firewalls) also supports [blocklists](https://help.obdev.at/littlesnitch6/lsc-blocklists).

## DNSCrypt

To encrypt DNS traffic, consider [DNSCrypt/dnscrypt-proxy](https://github.com/DNSCrypt/dnscrypt-proxy). When combined with Dnsmasq and DNSSEC, it can improve the privacy and integrity of DNS resolution.

Install DNSCrypt from Homebrew and follow the instructions to configure and start `dnscrypt-proxy`:

```bash
brew install dnscrypt-proxy
```

When using DNSCrypt with Dnsmasq, locate the DNSCrypt configuration file by running:

```bash
brew info dnscrypt-proxy
```

This command should display a path such as `/usr/local/etc/dnscrypt-proxy.toml`.

By default, dnscrypt-proxy listens on localhost (127.0.0.1) on port 53 and balances requests across a set of resolvers. Modify the configuration and change `listen_addresses` to use a port other than 53, such as 5355:

```
listen_addresses = ['127.0.0.1:5355', '[::1]:5355']
```

Start DNSCrypt:

```bash
sudo brew services restart dnscrypt-proxy
```

Confirm DNSCrypt is running:

```console
$ sudo lsof +c 15 -Pni UDP:5355
COMMAND          PID   USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
dnscrypt-proxy 15244 nobody    7u  IPv4 0x1337f85ff9f8beef      0t0  UDP 127.0.0.1:5355
dnscrypt-proxy 15244 nobody   10u  IPv6 0x1337f85ff9f8beef      0t0  UDP [::1]:5355
dnscrypt-proxy 15244 nobody   12u  IPv4 0x1337f85ff9f8beef      0t0  UDP 127.0.0.1:5355
dnscrypt-proxy 15244 nobody   14u  IPv6 0x1337f85ff9f8beef      0t0  UDP [::1]:5355
```

Applications may use their own DNS servers. If you use dnscrypt-proxy, you can block other DNS traffic with the following pf rules:

```shell
block drop quick on !lo0 proto udp from any to any port = 53
block drop quick on !lo0 proto tcp from any to any port = 53
```

See also [What is a DNS leak](https://dnsleaktest.com/what-is-a-dns-leak.html).

## Dnsmasq

[dnsmasq](https://thekelleys.org.uk/dnsmasq/doc.html) can cache replies, prevent upstream queries for unqualified names, and block entire top-level domains.

Use it in combination with DNSCrypt to encrypt DNS traffic.

If you do not use DNSCrypt, at minimum choose a DNS resolver other than the one provided by the ISP. Two popular alternatives are [Google DNS](https://developers.google.com/speed/public-dns/) and [OpenDNS](https://www.opendns.com/home-internet-security/).

Install Dnsmasq:

```bash
brew install dnsmasq
```

Download and edit [drduh/config/dnsmasq.conf](https://github.com/drduh/config/blob/main/dnsmasq.conf) or the default configuration file.

See [drduh/config/domains](https://github.com/drduh/config/tree/main/domains) for appendable examples on blocking services by domains.

Install and start the program (sudo is required to bind to [privileged port](https://unix.stackexchange.com/questions/16564/why-are-the-first-1024-ports-restricted-to-the-root-user-only) 53):

```bash
sudo brew services start dnsmasq
```

To set dnsmasq as the local DNS server, open **System Settings** > **Network** and select the active interface, then the **DNS** tab, select **+** and add `127.0.0.1`, or use:

```bash
sudo networksetup -setdnsservers "Wi-Fi" 127.0.0.1
```

Confirm Dnsmasq is configured:

```console
$ scutil --dns | head
DNS configuration

resolver #1
  search domain[0] : whatever
  nameserver[0] : 127.0.0.1
  flags    : Request A records, Request AAAA records
  reach    : 0x00030002 (Reachable,Local Address,Directly Reachable Address)

$ networksetup -getdnsservers "Wi-Fi"
127.0.0.1
```

> [!NOTE]
> Some VPN applications override DNS settings on connect. See [issue 24](https://github.com/drduh/macOS-Security-and-Privacy-Guide/issues/24) and [drduh/config/scripts/macos-dns.sh](https://github.com/drduh/config/blob/main/scripts/macos-dns.sh).

# Certificate authorities

macOS comes with [over 150](https://support.apple.com/103723) root authority certificates installed from corporations like Apple, Verisign, Thawte, Digicert and government agencies from China, Japan, Netherlands, U.S., and more! These Certificate Authorities (CAs) are capable of issuing TLS certificates for any domain, code signing certificates, etc. Apple [blocks these certificates](https://support.apple.com/103247#blocked) when a CA proves to be untrustworthy. They also have [strict requirements](https://www.apple.com/certificateauthority/ca_program.html) that trusted CAs have to meet.

For more information, see the [CA/Browser Forum's website](https://cabforum.org/resources/browser-os-info/).

Inspect root certificates in [Keychain Access](https://support.apple.com/guide/keychain-access/toc), under the **System Roots** tab or by using the `security` command line tool and `/System/Library/Keychains/SystemRootCertificates.keychain` file.

To disable a certificate authority, mark it as **Never Trust** and close the window to confirm.

The risk of a [MITM](https://wikipedia.org/wiki/Man-in-the-middle_attack) attack, in which a coerced or compromised certificate authority trusted by a system root store issues a fake/rogue TLS certificate, is relatively low, but [possible](https://wikipedia.org/wiki/DigiNotar#Issuance_of_fraudulent_certificates).

# Privoxy

Consider using [Privoxy](https://www.privoxy.org/) as a local proxy to filter Web traffic.

Install and start privoxy using Homebrew:

```bash
brew install privoxy
brew services start privoxy
```

Alternatively, a signed installation package for Privoxy is available from [their website](https://www.privoxy.org/sf-download-mirror/Macintosh%20%28OS%20X%29/) or [Sourceforge](https://sourceforge.net/projects/ijbswa/files/Macintosh%20%28OS%20X%29/). The signed package is [more secure](https://github.com/drduh/macOS-Security-and-Privacy-Guide/issues/65) than the Homebrew version and receives support from the Privoxy project.

By default, Privoxy listens on local TCP port 8118.

Set the system **HTTP** proxy for the active network interface `127.0.0.1` and `8118`:

```bash
sudo networksetup -setwebproxy "Wi-Fi" 127.0.0.1 8118
```

Set the system **HTTPS** proxy:

```bash
sudo networksetup -setsecurewebproxy "Wi-Fi" 127.0.0.1 8118
```

This can also be done through **System Settings > Network > Advanced > Proxies**

Confirm the proxy is set:

```console
$ scutil --proxy
<dictionary> {
  ExceptionsList : <array> {
    0 : *.local
    1 : 169.254/16
  }
  FTPPassive : 1
  HTTPEnable : 1
  HTTPPort : 8118
  HTTPProxy : 127.0.0.1
}
```

Although the majority of Web traffic is encrypted, Privoxy can filter by domain name patterns. For example, the following rules block all traffic, except to `.net` and `github.com` and all `apple` domains:

```console
{ +block{all} }
.

{ -block }
.apple.
.github.com
.net
```

To block Facebook domains:

```console
{ +block{facebook} }
.cdninstagram.
.facebook*.
.fb.
.fbcdn*.
.fbinfra.
.fbsbx.
.fbstatic*.
.fbsv.
.fburl.
.instagr.am
.tfbnw.
.thefacebook.
fb*.akamaihd.net
```

See [drduh/config/privoxy/config](https://github.com/drduh/config/blob/main/privoxy/config) and [drduh/config/privoxy/user.action](https://github.com/drduh/config/blob/main/privoxy/user.action) for additional Privoxy examples. Privoxy does **not** need to be restarted after editing `user.action` filter rules.

To verify traffic is blocked or redirected, use curl or the open the Privoxy interface at <http://p.p> in a browser:

```console
$ ALL_PROXY=127.0.0.1:8118 curl example.com -IL | head

HTTP/1.1 403 Request blocked by Privoxy
Content-Length: 9001
Content-Type: text/html
Cache-Control: no-cache
Pragma: no-cache

$ ALL_PROXY=127.0.0.1:8118 curl github.com -IL | head

HTTP/1.1 302 Local Redirect from Privoxy
Location: https://github.com/
Content-Length: 0

HTTP/1.1 200 Connection established

HTTP/2 200
content-type: text/html; charset=utf-8
```

> [!NOTE]
> Applications and services may bypass system proxy settings. Ensure applications are correctly configured and verify connections. *pf* can also be used to transparently proxy traffic.

# Browser

The Web browser creates numerous security and privacy risks, as its fundamental job is to download and execute untrusted code from the Internet.

An important property of modern browsers is the Same Origin Policy ([SOP](https://en.wikipedia.org/wiki/Same-origin_policy)) which prevents a malicious script on one page from obtaining access to sensitive data on another web page through the Document Object Model ([DOM](https://en.wikipedia.org/wiki/Document_Object_Model)). If SOP is compromised, the security of the entire browser is compromised.

Many browser exploits are based on social engineering as a means of gaining persistence. Always be mindful of visiting untrusted sites and especially careful with downloading new software.

Another important consideration about browser security is extensions. This is an issue affecting Firefox and [Chrome](https://courses.csail.mit.edu/6.857/2016/files/24.pdf) alike. The use of browser extensions should be limited to only critically necessary ones published by trustworthy developers.

[Mozilla Firefox](https://www.mozilla.org/firefox/new), [Google Chrome](https://www.google.com/chrome), [Safari](https://www.apple.com/safari), and [Tor Browser](https://www.torproject.org/download) are all recommended browsers for their own unique and individual purposes.

## Firefox

[Mozilla Firefox](https://www.mozilla.org/firefox/new) is a popular open source browser. Firefox replaced major parts of its infrastructure and codebase under the projects [Quantum](https://wiki.mozilla.org/Quantum) and [Photon](https://wiki.mozilla.org/Firefox/Photon/Updates). Part of the Quantum project is to replace C++ code with [Rust](https://rust-lang.org/). Rust is a systems programming language with a focus on security and thread safety. It is expected that Rust adoption will greatly improve the overall security posture of Firefox.

Firefox offers a similar security model to Chrome: it has a [bug bounty program](https://www.mozilla.org/security/bug-bounty), although it is not as lucrative. Firefox follows a four-week release cycle.

Firefox supports user-supplied configuration files. See [drduh/config/firefox.user.js](https://github.com/drduh/config/blob/main/firefox.user.js) and [arkenfox/user.js](https://github.com/arkenfox/user.js) for recommended preferences and hardening measures. Also see [NoScript](https://noscript.net/), an extension which allows selective script blocking.

Firefox [focuses on user privacy](https://www.mozilla.org/firefox/privacy). It supports [tracking protection](https://developer.mozilla.org/docs/Web/Privacy/Firefox_tracking_protection) in Private Browsing mode. The tracking protection can be enabled for the default account, although it may break the browsing experience on some websites. Firefox in Strict tracking protection mode will [randomize fingerprints](https://support.mozilla.org/kb/firefox-protection-against-fingerprinting) to defend against tracking. Firefox offers separate user [profiles](https://support.mozilla.org/kb/profile-manager-create-remove-switch-firefox-profiles). Browsing can also be delineated with [Multi-Account Containers](https://support.mozilla.org/kb/containers).

Firefox only supports Web Extensions through the [WebExtension API](https://developer.mozilla.org/docs/Mozilla/Add-ons/WebExtensions), which is very similar to Chrome. Submission of Web Extensions in Firefox is free. Web Extensions in Firefox most of the time are open source, although certain Web Extensions are proprietary.

## Chrome

[Google Chrome](https://www.google.com/chrome/) is based on the open source [Chromium project](https://www.chromium.org/) with certain [proprietary components](https://fossbytes.com/difference-google-chrome-vs-chromium-browser), such as:

* Automatic updates with GoogleSoftwareUpdateDaemon
* Usage tracking and crash reporting, which can be disabled through Chrome's settings
* Media Codec support for proprietary codecs
* Chrome Web Store
* PDF viewer
* Non-optional tracking. Google Chrome installer includes a randomly generated token. The token is sent to Google after the installation completes in order to measure the success rate. The RLZ identifier stores information – in the form of encoded strings – like the source of chrome download and installation week. It doesn't include any personal information and it's used to measure the effectiveness of a promotional campaign. **Chrome downloaded from Google's website doesn't have the RLZ identifier**. The source code to decode the strings is made open by Google.

Chrome offers account sync between multiple devices. Part of the sync data includes credentials to Web sites. The data is encrypted with the account password.

The Chrome Web Store requires a [5 USD registration fee](https://developer.chrome.com/docs/webstore/register) in order to submit extensions. The low cost allows the development of many quality open source Web Extensions that do not aim to monetize through usage.

Chrome has the largest share of global usage and is the preferred target platform for the majority of developers. Major technologies are based on Chrome's open-source components, such as [node.js](https://nodejs.org/) which uses [Chrome's V8](https://developers.google.com/v8) Engine and the [Electron](https://electron.atom.io/) framework, which is based on Chromium and node.js. Chrome's vast user base makes it the most attractive target for threat actors and security researchers. Despite constant attacks, Chrome has retained an impressive security track record over the years. This is not a small feat.

Chrome offers [separate profiles](https://www.chromium.org/user-experience/multi-profiles), [robust sandboxing](https://chromium.googlesource.com/chromium/src/+/HEAD/docs/design/sandbox.md), [frequent updates](https://chromereleases.googleblog.com/), and carries [impressive credentials](https://www.chromium.org/Home/chromium-security/brag-sheet). In addition, Google offers a very lucrative [bounty program](https://bughunters.google.com/about/rules/5745167867576320/chrome-vulnerability-reward-program-rules) for reporting vulnerabilities, along with its own [Project Zero](https://googleprojectzero.blogspot.com/) team. This means that a large number of highly talented and motivated people are constantly auditing and securing Chrome code.

Create separate Chrome profiles to reduce XSS risk and compartmentalize cookies/identities. In each profile, disable JavaScript in settings and configure allowed origins. Also consider disabling V8 optimization in Settings - see [this explanation](https://microsoftedge.github.io/edgevr/posts/Super-Duper-Secure-Mode) for the security trade-offs.

Block trackers with [uBlock Origin Lite](https://chromewebstore.google.com/detail/ublock-origin-lite/ddkjiahejlhfcafbddmgiahcphecmpfh).

Disable [DNS prefetching](https://www.chromium.org/developers/design-documents/dns-prefetching) (see also [DNS Prefetching and Its Privacy Implications](https://www.usenix.org/legacy/event/leet10/tech/full_papers/Krishnan.pdf) (pdf)). Chrome [may attempt](https://github.com/drduh/macOS-Security-and-Privacy-Guide/issues/350) to resolve DNS using Google's `8.8.8.8` and `8.8.4.4` public nameservers.

See [Chromium Security](https://www.chromium.org/Home/chromium-security) and [Chromium Privacy](https://www.chromium.org/Home/chromium-privacy) for more information. Read [Google's privacy policy](https://policies.google.com/privacy) to understand how personal information is collected and used.

## Safari

[Safari](https://www.apple.com/safari) is the default browser on macOS. It is also the most optimized browser for reducing battery use. Safari, like Chrome, has both open source and proprietary components. Safari is based on the open source Web Engine [WebKit](https://webkit.org/), which is ubiquitous among the macOS ecosystem. WebKit is used by Apple apps such as Mail, Books, and the App Store. Chrome's [Blink](https://www.chromium.org/blink) engine is a fork of WebKit and both engines share a number of similarities.

Safari supports certain unique features that benefit user security and privacy. [Content blockers](https://webkit.org/blog/3476/content-blockers-first-look) enable the creation of content blocking rules without using JavaScript. This rule based approach greatly improves memory use, security, and privacy. Safari 11 introduced [Intelligent Tracking Prevention](https://webkit.org/blog/7675/intelligent-tracking-prevention), which removes tracking data stored in Safari after a period of non-interaction by the user from the tracker's website. Safari can randomize the browser fingerprint to reduce tracking. Safari does not support certain features like WebUSB or the Battery API intentionally for security and privacy reasons. Private tabs in Safari have isolated cookies and cache that is destroyed when you close the tab. Safari also support Profiles which are equivalent to Firefox's Multi-Account Containers for separating cookies and browsing. Safari can be made significantly more secure with [lockdown mode](#lockdown-mode), which can be disabled per-site. Read more about [tracking prevention](https://webkit.org/tracking-prevention/) in Safari.

Safari offers an invite-only [bounty program](https://developer.apple.com/bug-reporting) for bug reporting to a select number of security researchers. The bounty program was announced during Apple's [presentation](https://www.blackhat.com/docs/us-16/materials/us-16-Krstic.pdf) at [BlackHat](https://www.blackhat.com/us-16/briefings.html#behind-the-scenes-of-ios-security) 2016.

Web Extensions in Safari have an additional option to use native code in Safari's sandbox environment, in addition to Web Extension APIs. Web Extensions in Safari are also distributed through Apple App Store. App Store submission comes with the added benefit of Web Extension code being audited by Apple. On the other hand App Store submission comes at a steep cost. Yearly [developer subscription](https://developer.apple.com/support/compare-memberships) fee costs 100 USD (in contrast to Chrome's 5 USD fee and Firefox's free submission). The high cost is prohibitive for the majority of open source developers. As a result, Safari has very few extensions to choose from. However, keep the high cost in mind when installing extensions. It is expected that most Web Extensions will have some way of monetizing usage in order to cover developer costs. Avoid Web Extensions without open source code.

Safari syncs user preferences and passwords with [iCloud Keychain](https://support.apple.com/HT202303). In order to be viewed in plain text, a user must input the account password of the current device. This means that users can sync data across devices with added security.

Safari follows a slower release cycle than Chrome and Firefox (3-4 minor releases, 1 major release, per year). Newer features are slower to be adopted to the stable channel. Security updates in Safari are handled independent of the stable release schedule and are installed through the App Store.

See also [el1t/uBlock-Safari](https://github.com/el1t/uBlock-Safari/wiki/Disable-hyperlink-auditing-beacon) to disable hyperlink auditing beacons.

## Web browser privacy

Web browsers reveal information in several ways, for example through the [Navigator](https://developer.mozilla.org/docs/Web/API/Navigator) interface, which may include information such as the browser version, operating system, site permissions, and the device's battery level. Many websites also use [canvas fingerprinting](https://en.wikipedia.org/wiki/Canvas_fingerprinting) to uniquely identify users across sessions.

For more information about security conscious browsing and what data is sent by the browser, see [HowTo: Privacy & Security Conscious Browsing](https://gist.github.com/atcuno/3425484ac5cce5298932), [browserleaks.com](https://browserleaks.com/), [Am I Unique?](https://amiunique.org/fingerprint) and [EFF Cover Your Tracks](https://coveryourtracks.eff.org/) resources.

To hinder third-party trackers, it is recommended to **disable third-party cookies** altogether. Safari, Firefox, and Chrome all block third-party cookies by default. A third-party cookie is a cookie associated with a file requested by a different domain than the one the user is currently viewing. Most of the time third-party cookies are used to create browsing profiles by tracking a user's movement on the web. Disabling third-party cookies prevents HTTP responses and scripts from other domains from setting cookies. Moreover, cookies are removed from requests to domains that are not the document origin domain, so cookies are only sent to the current site that is being viewed.

Also be aware of [WebRTC](https://en.wikipedia.org/wiki/WebRTC#Concerns), which may reveal local or public (if connected to VPN) IP address(es). In Firefox and Chrome/Chromium this can be disabled with extensions such as [uBlock Origin](https://github.com/gorhill/uBlock/wiki/Prevent-WebRTC-from-leaking-local-IP-address). [Lockdown mode](#lockdown-mode) [disables WebRTC](https://www.sevarg.net/2022/07/20/ios16-lockdown-mode-browser-analysis) in Safari.

# Tor

Tor is an anonymizing network which can be used for browsing the Web with additional privacy. Tor Browser is a modified version of Firefox with a proxy to access the Tor network.

Download Tor Browser from [Tor Project](https://www.torproject.org/download/).

Do **not** attempt to configure other browsers or applications to use Tor as you may make a mistake which will compromise anonymity.

Download both `dmg` and `asc` files to [verify](https://support.torproject.org/tor-browser/getting-started/verifying-tor-browser/) the software:

```console
$ cd ~/Downloads

$ file tor-browser-macos-*
tor-browser-macos-15.0.17.dmg:     XZ compressed data, checksum NONE
tor-browser-macos-15.0.17.dmg.asc: PGP signature Signature (old)

$ gpg --verify tor-browser-macos-*.asc
[...]
gpg: Can't check signature: No public key

$ gpg --auto-key-locate nodefault,wkd --locate-keys torbrowser@torproject.org
gpg: key 0x4E2C6E8793298290: public key "Tor Browser Developers (signing key) <torbrowser@torproject.org>" imported
gpg: Total number processed: 1
gpg:               imported: 1
pub   rsa4096/0x4E2C6E8793298290 2014-12-15 [C] [expires: 2027-07-15]
      Key fingerprint = EF6E 286D DA85 EA2A 4BA7  DE68 4E2C 6E87 9329 8290
uid                   [ unknown] Tor Browser Developers (signing key) <torbrowser@torproject.org>
sub   rsa4096/0x157432CF78A65729 2024-07-15 [S] [expires: 2026-10-26]
      Key fingerprint = CAAE 408A EBE2 288E 96FC  5D5E 1574 32CF 78A6 5729

$ gpg --verify tor-browser-macos-*.asc
gpg: assuming signed data in 'tor-browser-macos-15.0.17.dmg'
gpg: Signature made Sun Jun 28 15:35:20 2026 PDT
gpg:                using RSA key CAAE408AEBE2288E96FC5D5E157432CF78A65729
gpg: Good signature from "Tor Browser Developers (signing key) <torbrowser@torproject.org>" [unknown]
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: EF6E 286D DA85 EA2A 4BA7  DE68 4E2C 6E87 9329 8290
     Subkey fingerprint: CAAE 408A EBE2 288E 96FC  5D5E 1574 32CF 78A6 5729
```

Make sure `Good signature from "Tor Browser Developers (signing key) <torbrowser@torproject.org>"` appears in the output. The warning about the key not being certified is benign, as it has not yet been assigned trust.

See [How can I verify Tor Browser's signature?](https://support.torproject.org/tbb/how-to-verify-signature/) for more information.

To finish installing Tor Browser, open the disk image and drag it to the Applications folder, or:

```bash
hdiutil mount TorBrowser-8.0.4-osx64_en-US.dmg
cp -r /Volumes/Tor\ Browser/Tor\ Browser.app/ ~/Applications/
```

Verify the application was signed by The Tor Project's Apple Developer ID **MADPSAYN6T**, using the `spctl -a -v` and/or `pkgutil --check-signature` commands:

```console
$ spctl -a -vv ~/Applications/Tor\ Browser.app
/Users/drduh/Applications/Tor Browser.app: accepted
source=Notarized Developer ID
origin=Developer ID Application: The Tor Project, Inc (MADPSAYN6T)

$ pkgutil --check-signature ~/Applications/Tor\ Browser.app
Package "Tor Browser.app":
   Status: signed by a certificate trusted by macOS
   Certificate Chain:
    1. Developer ID Application: The Tor Project, Inc (MADPSAYN6T)
       Expires: 2028-10-11 17:57:46 +0000
       SHA256 Fingerprint:
           76 3C 89 02 ED CB AD 8E 59 86 1E 93 D3 05 5B 28 F9 04 0C 96 03 8B
           16 28 9F 38 64 ED 53 45 B4 DA
       ------------------------------------------------------------------------
    2. Developer ID Certification Authority
       Expires: 2031-09-17 00:00:00 +0000
       SHA256 Fingerprint:
           F1 6C D3 C5 4C 7F 83 CE A4 BF 1A 3E 6A 08 19 C8 AA A8 E4 A1 52 8F
           D1 44 71 5F 35 06 43 D2 DF 3A
       ------------------------------------------------------------------------
    3. Apple Root CA
       Expires: 2035-02-09 21:40:36 +0000
       SHA256 Fingerprint:
           B0 B1 73 0E CB C7 FF 45 05 14 2C 49 F1 29 5E 6E DA 6B CA ED 7E 2C
           68 C5 BE 91 B5 A1 10 01 F0 24
```

The command `codesign` can also be used to examine an application's code signature:

```console
$ codesign -dvv ~/Applications/Tor\ Browser.app
Executable=/Users/drduh/Applications/Tor Browser.app/Contents/MacOS/firefox
Identifier=org.torproject.torbrowser
Format=app bundle with Mach-O universal (x86_64 arm64)
CodeDirectory v=20500 size=805 flags=0x10000(runtime) hashes=14+7 location=embedded
Signature size=9054
Authority=Developer ID Application: The Tor Project, Inc (MADPSAYN6T)
Authority=Developer ID Certification Authority
Authority=Apple Root CA
Timestamp=Jun 28, 2026 at 14:01:57
Notarization Ticket=stapled
Info.plist entries=27
TeamIdentifier=MADPSAYN6T
Runtime Version=15.5.0
Sealed Resources version=2 rules=13 files=208
Internal requirements count=1 size=188
```

To view full certificate details for a signed application, extract with `codesign` and decode with `openssl`:

```console
$ codesign -d --extract-certificates ~/Applications/Tor\ Browser.app
Executable=/Users/drduh/Applications/Tor Browser.app/Contents/MacOS/firefox

$ file codesign*
codesign0: Certificate, Version=3
codesign1: Certificate, Version=3
codesign2: Certificate, Version=3 Certificate, Version=02

$ openssl x509 -inform der -in codesign0 -subject -issuer -startdate -enddate -noout
subject= /UID=MADPSAYN6T/CN=Developer ID Application: The Tor Project, Inc (MADPSAYN6T)/OU=MADPSAYN6T/O=The Tor Project, Inc/C=US
issuer= /CN=Developer ID Certification Authority/OU=G2/O=Apple Inc./C=US
notBefore=Oct 11 17:57:47 2023 GMT
notAfter=Oct 11 17:57:46 2028 GMT

$ openssl x509 -inform der -in codesign0 -fingerprint -noout
SHA256 Fingerprint=76:3C:89:02:ED:CB:AD:8E:59:86:1E:93:D3:05:5B:28:F9:04:0C:96:03:8B:16:28:9F:38:64:ED:53:45:B4:DA
```

Tor traffic can be obfuscated using a [pluggable transport](https://support.torproject.org/tor-browser/circumvention/). This can be done by setting up a [relay](https://support.torproject.org/relays/) or using an existing [bridge](https://bridges.torproject.org/).

The Tor network provides [anonymity](https://www.privateinternetaccess.com/blog/2013/10/how-does-privacy-differ-from-anonymity-and-why-are-both-important/), which is not necessarily synonymous with privacy. The network does not defend against a global observer capable of traffic analysis and correlation. See also [Seeking Anonymity in an Internet Panopticon](https://bford.info/pub/net/panopticon-cacm.pdf) (pdf) and [Traffic Correlation on Tor by Realistic Adversaries](https://www.ohmygodel.com/publications/usersrouted-ccs13.pdf) (pdf).

See [Tor Protocol Specification](https://spec.torproject.org/tor-spec/) for more information.

Also see [Invisible Internet Project (I2P)](https://geti2p.net/en/about/intro) and its [Tor comparison](https://geti2p.net/en/comparison/tor).

# VPN

When choosing a VPN service or self-hosting, be sure to research the protocols, key exchange algorithms, authentication mechanisms, and type of encryption being used. Some protocols, such as [PPTP](https://en.wikipedia.org/wiki/Point-to-Point_Tunneling_Protocol#Security), should be avoided in favor of [OpenVPN](https://en.wikipedia.org/wiki/OpenVPN) or Linux-based [Wireguard](https://www.wireguard.com/) [on a Linux VM](https://github.com/mrash/Wireguard-macOS-LinuxVM) or via a set of [cross platform tools](https://www.wireguard.com/xplatform/).

Some clients may send traffic over the next available interface when VPN is interrupted or disconnected. See [scy/8122924](https://gist.github.com/scy/8122924) for an example on how to allow traffic only over VPN.

There is an updated guide to setting up an [IPsec](https://en.wikipedia.org/wiki/Ipsec) VPN on a virtual machine ([hwdsl2/setup-ipsec-vpn](https://github.com/hwdsl2/setup-ipsec-vpn)) or a Docker container ([hwdsl2/docker-ipsec-vpn-server](https://github.com/hwdsl2/docker-ipsec-vpn-server)).

It may be worthwhile to consider the geographical location of the VPN provider. See further discussion in [issue 114](https://github.com/drduh/macOS-Security-and-Privacy-Guide/issues/114).

Also see this [technical overview](https://blog.timac.org/2018/0717-macos-vpn-architecture/) of the macOS built-in VPN L2TP/IPsec and IKEv2 client.

# PGP/GPG

PGP is a standard for signing and encrypting data (especially email) end-to-end, so only the sender and recipients can access it.

GPG (GNU Privacy Guard) is a GPL-licensed, open-source program compliant with the PGP standard.

GPG is used to verify signatures of software you download and install, as well as [symmetrically](https://en.wikipedia.org/wiki/Symmetric-key_algorithm) or [asymmetrically](https://en.wikipedia.org/wiki/Public-key_cryptography) encrypt files and text.

Install from Homebrew with `brew install gnupg` or using [GPG Suite](https://gpgtools.org/).

Download [gpg.conf](https://github.com/drduh/YubiKey-Guide/blob/master/config/gpg.conf) to use recommended settings:

```bash
curl -o ~/.gnupg/gpg.conf https://raw.githubusercontent.com/drduh/YubiKey-Guide/master/config/gpg.conf
```

See [drduh/YubiKey-Guide](https://github.com/drduh/YubiKey-Guide) to generate and manage GPG credentials.

# Messengers

## XMPP

[XMPP](https://en.wikipedia.org/wiki/XMPP) is an [open protocol](https://xmpp.org/extensions/) developed by the [IETF](https://www.ietf.org/) which features cross-platform federated messaging. There are many [client options](https://xmpp.org/getting-started/). Consider using one of the browser-based clients to take advantage of the browser's sandbox.

Depending on the provider, you might not need anything other than a username and password to set up an account.

XMPP is not E2EE by default - use [OMEMO](https://omemo.top) encryption with a supported client.

## Signal

[Signal](https://signal.org/) is a popular E2EE messenger whose [double-ratchet](https://signal.org/docs/specifications/doubleratchet/) protocol is used by many other applications including WhatsApp, Google Messages, and Facebook Messenger.

To use the Signal desktop app, Signal must first be installed on a phone.

## iMessage

[iMessage](https://en.wikipedia.org/wiki/IMessage) is Apple's first party messenger. It requires an [Apple Account](#apple-account) in order to use it.

Enable [Contact Key Verification](https://support.apple.com/118246) and verify contacts.

iMessage can be used with either a [phone number or an email](https://support.apple.com/108758#help).

> [!WARNING]
> By default, iCloud backup is enabled, which stores copies of message encryption keys on [Apple's servers](https://support.apple.com/102651) without E2EE. Either [disable iCloud backup](https://support.apple.com/guide/icloud/view-and-manage-backups-mm122d3ef202/1.0/icloud/1.0) or enable [Advanced Data Protection](https://support.apple.com/guide/security/advanced-data-protection-for-icloud-sec973254c5f) to prevent this. Remind messaging recipients to do the same.

# Viruses and malware

See [Methods of malware persistence on Mac OS X](https://www.virusbtn.com/pdf/conference/vb2014/VB2014-Wardle.pdf) (pdf) and [Malware Persistence on OS X Yosemite](https://www.rsaconference.com/events/us15/agenda/sessions/1591/malware-persistence-on-os-x-yosemite) to learn about how basic malware functions.

Also check out [Hacking Team](https://www.schneier.com/blog/archives/2015/07/hacking_team_is.html) malware for macOS: [root installation for MacOS](https://github.com/hackedteam/vector-macos-root), [Support driver for Mac Agent](https://github.com/hackedteam/driver-macos) and [RCS Agent for Mac](https://github.com/hackedteam/core-macos), which is a good example of advanced malware capabilities. For more, see [A Brief Analysis of an RCS Implant Installer](https://objective-see.com/blog/blog_0x0D.html) and [reverse.put.as](https://reverse.put.as/2016/02/29/the-italian-morons-are-back-what-are-they-up-to-this-time/)

## Downloading Software

Running applications from the App Store or that are [Notarized](https://support.apple.com/guide/security/app-code-signing-process-sec3ad8e6e53/web) by Apple may reduce malware risk: Apple performs an automated scan on notarized applications and App Store requires a [review process](https://developer.apple.com/app-store/review/guidelines/).

Otherwise, obtain software from trusted sources like directly from the developer's website or GitHub. Always make sure that the browser/terminal is using HTTPS.

## App Sandbox

Check if a program uses [App Sandbox](https://developer.apple.com/documentation/security/app_sandbox/protecting_user_data_with_app_sandbox):

```bash
codesign -dvvv --entitlements - /path/to/application.app
```

With App Sandbox enabled, output will include:

```console
[Key] com.apple.security.app-sandbox
[Value]
    [Bool] true
```

Alternatively, check **Activity Monitor** while the application is running and adding the "Sandbox" column.

App Store software is required to use App Sandbox. Applications such as Google Chrome use their own [sandbox](https://chromium.googlesource.com/chromium/src/+/HEAD/docs/design/sandbox.md) and might not use App Sandbox.

> [!NOTE]
> Sandboxing limits an application's default access, but entitlements and user-granted permissions can expand access.

## Hardened Runtime

Check if a program uses the [Hardened Runtime](https://developer.apple.com/documentation/security/hardened_runtime) before running it using the following command:

```bash
codesign --display --verbose /path/to/application.app
```

If Hardened Runtime is enabled, `flags=0x10000(runtime)` will appear in output.

**Activity Monitor** has the option to display a "Restricted" column which indicates a program is restricted from injecting code via macOS's [dynamic linker](https://pewpewthespells.com/blog/blocking_code_injection_on_ios_and_os_x.html).

The Hardened Runtime is a prerequisite for notarization of distributed apps.

## Antivirus

To scan files and applications, consider uploading them to [VirusTotal](https://www.virustotal.com/gui/home/upload), keeping in mind this makes them publicly-viewable.

macOS includes built-in antivirus software called [XProtect](https://support.apple.com/guide/security/protecting-against-malware-sec469d47bd8), which runs in the background and updates signatures used to detect malware automatically. If malware is detected, XProtect attempts to remove and quarantine it.

Applications such as [BlockBlock](https://objective-see.com/products/blockblock.html) or [hazcod/maclaunch](https://github.com/hazcod/maclaunch) might help prevent or detect persistent malware.

Antivirus software may act as a "double-edged sword": capable of countering common, "garden-variety" malware, but having potential to increase attack surface with system-level privileges. They may also send telemetry and malware samples, increasing privacy risk.

See [Sophail: Applied attacks against Antivirus](https://lock.cmpxchg8b.com/sophailv2.pdf) (pdf), [Analysis and Exploitation of an ESET Vulnerability](https://googleprojectzero.blogspot.ro/2015/06/analysis-and-exploitation-of-eset.html), [Popular Security Software Came Under Relentless NSA and GCHQ Attacks](https://theintercept.com/2015/06/22/nsa-gchq-targeted-kaspersky/), and [How Israel Caught Russian Hackers Scouring the World for U.S. Secrets](https://www.nytimes.com/2017/10/10/technology/kaspersky-lab-israel-russia-hacking.html).

## Gatekeeper

**Gatekeeper** tries to prevent non-notarized applications from running.

If you try to run an app that isn't notarized, Gatekeeper will give you a warning. This can be easily bypassed if you go to **Privacy & Security**, scroll down to the bottom and select **Open** on the app. Then Gatekeeper will allow it to run.

Gatekeeper only protects applications, so exercise caution running other binaries.

# System Integrity Protection

To verify System Integrity Protection is enabled, use the command `csrutil status`, which should return: `System Integrity Protection status: enabled.` Otherwise, [enable SIP](https://developer.apple.com/documentation/security/disabling_and_enabling_system_integrity_protection) using [Recovery Mode](https://support.apple.com/en-us/102518).

# Metadata and artifacts

macOS attaches metadata ([APFS extended attributes](https://en.wikipedia.org/wiki/Extended_file_attributes#macOS)) to downloaded files, which can be viewed with the `mdls` and `xattr` commands:

```console
$ ls -l@ ~/Downloads/TorBrowser-8.0.4-osx64_en-US.dmg
-rw-r--r--@ 1 drduh staff 63M Jan 1 12:00 TorBrowser-8.0.4-osx64_en-US.dmg
	com.apple.metadata:kMDItemWhereFroms	  46B
	com.apple.quarantine	  57B

$ mdls ~/Downloads/TorBrowser-8.0.4-osx64_en-US.dmg
kMDItemContentCreationDate         = 2019-01-01 00:00:00 +0000
kMDItemContentCreationDate_Ranking = 2019-01-01 00:00:00 +0000
kMDItemContentModificationDate     = 2019-01-01 00:00:00 +0000
kMDItemContentType                 = "com.apple.disk-image-udif"
kMDItemContentTypeTree             = (
    "public.archive",
    "public.item",
    "public.data",
    "public.disk-image",
    "com.apple.disk-image",
    "com.apple.disk-image-udif"
)
kMDItemDateAdded                   = 2019-01-01 00:00:00 +0000
kMDItemDateAdded_Ranking           = 2019-01-01 00:00:00 +0000
kMDItemDisplayName                 = "TorBrowser-8.0.4-osx64_en-US.dmg"
kMDItemFSContentChangeDate         = 2019-01-01 00:00:00 +0000
kMDItemFSCreationDate              = 2019-01-01 00:00:00 +0000
kMDItemFSCreatorCode               = ""
kMDItemFSFinderFlags               = 0
kMDItemFSHasCustomIcon             = (null)
kMDItemFSInvisible                 = 0
kMDItemFSIsExtensionHidden         = 0
kMDItemFSIsStationery              = (null)
kMDItemFSLabel                     = 0
kMDItemFSName                      = "TorBrowser-8.0.4-osx64_en-US.dmg"
kMDItemFSNodeCount                 = (null)
kMDItemFSOwnerGroupID              = 5000
kMDItemFSOwnerUserID               = 501
kMDItemFSSize                      = 65840402
kMDItemFSTypeCode                  = ""
kMDItemInterestingDate_Ranking     = 2019-01-01 00:00:00 +0000
kMDItemKind                        = "Disk Image"
kMDItemWhereFroms                  = (
    "https://dist.torproject.org/torbrowser/8.0.4/TorBrowser-8.0.4-osx64_en-US.dmg",
    "https://www.torproject.org/projects/torbrowser.html.en"
)

$ xattr -l ~/Downloads/TorBrowser-8.0.4-osx64_en-US.dmg
com.apple.metadata:kMDItemWhereFroms:
00000000  62 70 6C 69 73 74 30 30 A2 01 02 5F 10 4D 68 74  |bplist00..._.Mht|
00000010  74 70 73 3A 2F 2F 64 69 73 74 2E 74 6F 72 70 72  |tps://dist.torpr|
00000020  6F 6A 65 63 74 2E 6F 72 67 2F 74 6F 72 62 72 6F  |oject.org/torbro|
[...]
com.apple.quarantine: 0081;58519ffa;Google Chrome.app;1F032CAB-F5A1-4D92-84EB-CBECA971B7BC
```

Metadata attributes can also be removed with the `-d` flag:

```bash
xattr -d com.apple.metadata:kMDItemWhereFroms ~/Downloads/TorBrowser-8.0.4-osx64_en-US.dmg
xattr -d com.apple.quarantine ~/Downloads/TorBrowser-8.0.4-osx64_en-US.dmg
xattr -l ~/Downloads/TorBrowser-8.0.4-osx64_en-US.dmg
```

Other metadata and artifacts may be found in the directories including, but not limited to, `~/Library/Preferences/`, `~/Library/Containers/<APP>/Data/Library/Preferences`, `/Library/Preferences`, some of which is detailed below.

`~/Library/Preferences/com.apple.sidebarlists.plist` contains historical list of volumes attached. To clear it, use the command `/usr/libexec/PlistBuddy -c "delete :systemitems:VolumesList" ~/Library/Preferences/com.apple.sidebarlists.plist`

`/Library/Preferences/com.apple.Bluetooth.plist` contains Bluetooth metadata, including device history. If Bluetooth is not used, the metadata can be cleared with:

```bash
sudo defaults delete /Library/Preferences/com.apple.Bluetooth.plist DeviceCache
sudo defaults delete /Library/Preferences/com.apple.Bluetooth.plist IDSPairedDevices
sudo defaults delete /Library/Preferences/com.apple.Bluetooth.plist PANDevices
sudo defaults delete /Library/Preferences/com.apple.Bluetooth.plist PANInterfaces
sudo defaults delete /Library/Preferences/com.apple.Bluetooth.plist SCOAudioDevices
```

`/var/spool/cups` contains the CUPS printer job cache. To clear it, use the commands:

```bash
sudo rm -rfv /var/spool/cups/c0*
sudo rm -rfv /var/spool/cups/tmp/*
sudo rm -rfv /var/spool/cups/cache/job.cache*
```

To clear the list of iOS devices connected, use:

```bash
sudo defaults delete /Users/$USER/Library/Preferences/com.apple.iPod.plist "conn:128:Last Connect"
sudo defaults delete /Users/$USER/Library/Preferences/com.apple.iPod.plist Devices
sudo defaults delete /Library/Preferences/com.apple.iPod.plist "conn:128:Last Connect"
sudo defaults delete /Library/Preferences/com.apple.iPod.plist Devices
sudo rm -rfv /var/db/lockdown/*
```

Quicklook thumbnail data can be cleared using the `qlmanage -r cache` command, but this writes to the file `resetreason` in the Quicklook directories, and states that the Quicklook cache was manually cleared. Disable the thumbnail cache with `qlmanage -r disablecache`

It can also be cleared by getting the directory names with `getconf DARWIN_USER_CACHE_DIR` and `sudo getconf DARWIN_USER_CACHE_DIR`, then removing them:

```bash
rm -rfv $(getconf DARWIN_USER_CACHE_DIR)/com.apple.QuickLook.thumbnailcache/exclusive
rm -rfv $(getconf DARWIN_USER_CACHE_DIR)/com.apple.QuickLook.thumbnailcache/index.sqlite
rm -rfv $(getconf DARWIN_USER_CACHE_DIR)/com.apple.QuickLook.thumbnailcache/index.sqlite-shm
rm -rfv $(getconf DARWIN_USER_CACHE_DIR)/com.apple.QuickLook.thumbnailcache/index.sqlite-wal
rm -rfv $(getconf DARWIN_USER_CACHE_DIR)/com.apple.QuickLook.thumbnailcache/resetreason
rm -rfv $(getconf DARWIN_USER_CACHE_DIR)/com.apple.QuickLook.thumbnailcache/thumbnails.data
```

Similarly, for the root user:

```bash
sudo rm -rfv $(getconf DARWIN_USER_CACHE_DIR)/com.apple.QuickLook.thumbnailcache/thumbnails.fraghandler
sudo rm -rfv $(getconf DARWIN_USER_CACHE_DIR)/com.apple.QuickLook.thumbnailcache/exclusive
sudo rm -rfv $(getconf DARWIN_USER_CACHE_DIR)/com.apple.QuickLook.thumbnailcache/index.sqlite
sudo rm -rfv $(getconf DARWIN_USER_CACHE_DIR)/com.apple.QuickLook.thumbnailcache/index.sqlite-shm
sudo rm -rfv $(getconf DARWIN_USER_CACHE_DIR)/com.apple.QuickLook.thumbnailcache/index.sqlite-wal
sudo rm -rfv $(getconf DARWIN_USER_CACHE_DIR)/com.apple.QuickLook.thumbnailcache/resetreason
sudo rm -rfv $(getconf DARWIN_USER_CACHE_DIR)/com.apple.QuickLook.thumbnailcache/thumbnails.data
sudo rm -rfv $(getconf DARWIN_USER_CACHE_DIR)/com.apple.QuickLook.thumbnailcache/thumbnails.fraghandler
```

Also see ['quicklook' cache may leak encrypted data](https://objective-see.com/blog/blog_0x30.html).

To clear Finder preferences:

```bash
defaults delete ~/Library/Preferences/com.apple.finder.plist FXDesktopVolumePositions
defaults delete ~/Library/Preferences/com.apple.finder.plist FXRecentFolders
defaults delete ~/Library/Preferences/com.apple.finder.plist RecentMoveAndCopyDestinations
defaults delete ~/Library/Preferences/com.apple.finder.plist RecentSearches
defaults delete ~/Library/Preferences/com.apple.finder.plist SGTRecentFileSearches
```

Additional diagnostic files may be found in the following directories - but caution should be taken before removing any, as it may break logging or cause other issues:

```
/var/db/CoreDuet/
/var/db/diagnostics/
/var/db/systemstats/
/var/db/uuidtext/
/var/log/DiagnosticMessages/
```

macOS stored preferred Wi-Fi data (including credentials) in NVRAM. To clear it, use the following commands:

```bash
sudo nvram -d 36C28AB5-6566-4C50-9EBD-CBB920F83843:current-network
sudo nvram -d 36C28AB5-6566-4C50-9EBD-CBB920F83843:preferred-networks
sudo nvram -d 36C28AB5-6566-4C50-9EBD-CBB920F83843:preferred-count
```

macOS may collect sensitive information about what you type, even if user dictionary and suggestions are off. To remove them, and prevent them from being created again, use the following commands:

```bash
rm -rfv "~/Library/LanguageModeling/*" "~/Library/Spelling/*" "~/Library/Suggestions/*"
chmod -R 000 ~/Library/LanguageModeling ~/Library/Spelling ~/Library/Suggestions
chflags -R uchg ~/Library/LanguageModeling ~/Library/Spelling ~/Library/Suggestions
```

QuickLook application support metadata can be cleared and locked with the following commands:

```bash
rm -rfv "~/Library/Application Support/Quick Look/*"
chmod -R 000 "~/Library/Application Support/Quick Look"
chflags -R uchg "~/Library/Application Support/Quick Look"
```

Document revision metadata is stored in `/.DocumentRevisions-V100` and can be cleared and locked with the following commands - caution should be taken as this may break some core Apple applications:

```bash
sudo rm -rfv /.DocumentRevisions-V100/*
sudo chmod -R 000 /.DocumentRevisions-V100
sudo chflags -R uchg /.DocumentRevisions-V100
```

Saved application state metadata may be cleared and locked with the following commands:

```bash
rm -rfv ~/Library/Saved\ Application\ State/*
rm -rfv ~/Library/Containers/<APPNAME>/Data/Library/Saved\ Application\ State
chmod -R 000 ~/Library/Saved\ Application\ State/
chmod -R 000 ~/Library/Containers/<APPNAME>/Data/Library/Saved\ Application\ State
chflags -R uchg ~/Library/Saved\ Application\ State/
chflags -R uchg ~/Library/Containers/<APPNAME>/Data/Library/Saved\ Application\ State
```

Autosave metadata can be cleared and locked with the following commands:

```bash
rm -rfv "~/Library/Containers/<APP>/Data/Library/Autosave Information"
rm -rfv "~/Library/Autosave Information"
chmod -R 000 "~/Library/Containers/<APP>/Data/Library/Autosave Information"
chmod -R 000 "~/Library/Autosave Information"
chflags -R uchg "~/Library/Containers/<APP>/Data/Library/Autosave Information"
chflags -R uchg "~/Library/Autosave Information"
```

The Siri analytics database, which is created even if the Siri launch agent disabled, can be cleared and locked with the following commands:

```bash
rm -rfv ~/Library/Assistant/SiriAnalytics.db
chmod -R 000 ~/Library/Assistant/SiriAnalytics.db
chflags -R uchg ~/Library/Assistant/SiriAnalytics.db
```

Media played in QuickTime Player can be found in:

```bash
~/Library/Containers/com.apple.QuickTimePlayerX/Data/Library/Preferences/com.apple.QuickTimePlayerX.plist
```

Additional metadata may exist in the following files:

```bash
~/Library/Containers/com.apple.appstore/Data/Library/Preferences/com.apple.commerce.knownclients.plist
~/Library/Preferences/com.apple.commerce.plist
~/Library/Preferences/com.apple.QuickTimePlayerX.plist
```

# Passwords

The [Passwords](https://support.apple.com/guide/passwords/the-passwords-app-mchl901b1b95/mac) app creates [secure credentials](https://support.apple.com/guide/security/automatic-strong-passwords-secc84c811c4/web).

**Passwords** supports [passkeys](https://fidoalliance.org/passkeys/) - credentials which are more resilient to phishing. Make sure to use them instead of passwords whenever you can.

Consider using [Diceware](https://secure.research.vt.edu/diceware/) for memorable passwords.

GnuPG can also be used to manage passwords and other encrypted files - see [drduh/Purse](https://github.com/drduh/Purse) and [drduh/pwd.sh](https://github.com/drduh/pwd.sh).

Ensure online accounts have [multi-factor authentication](https://en.wikipedia.org/wiki/Multi-factor_authentication) enabled. The strongest form of multi-factor authentication is [WebAuthn](https://en.wikipedia.org/wiki/WebAuthn), followed by [TOTP](https://datatracker.ietf.org/doc/html/rfc6238), then [HOTP](https://datatracker.ietf.org/doc/html/rfc4226), and SMS-based codes are weakest.

[YubiKey](https://www.yubico.com/products/) is an affordable hardware token with WebAuthn support. It can also store cryptographic keys for encryption and authentication - see [drduh/YubiKey-Guide](https://github.com/drduh/YubiKey-Guide).

# Backup

Encrypt files locally before backing them up to external media or online services.

Follow the [3-2-1 backup model](https://www.cisa.gov/sites/default/files/publications/data_backup_options.pdf): keep 3 copies (original and two backups); keep backups on 2 different media types; store 1 backup copy remotely.

[Time Machine](https://support.apple.com/104984) is the built-in tool for handling backups on macOS. Get an external drive or network drive to create [encrypted](https://support.apple.com/guide/mac-help/keep-your-time-machine-backup-disk-secure-mh21241) backups.

GnuPG can be used with a password or public key, with the private key stored on [YubiKey](https://github.com/drduh/YubiKey-Guide).

Compress and encrypt a directory using a password:

```bash
tar zcvf - ~/Downloads | gpg -c > ~/Downloads/backup-$(date +%F-%H%M).tar.gz.gpg
```

Decrypt and decompress the directory:

```bash
gpg -o ~/Downloads/decrypted-backup.tar.gz -d ~/Downloads/backup-*.tar.gz.gpg
tar zxvf ~/Downloads/decrypted-backup.tar.gz
```

Encrypted volumes can also be created using **Disk Utility** or `hdiutil`:

```bash
hdiutil create ~/Downloads/encrypted.dmg -encryption -size 50M -volname "secretStuff"
hdiutil mount ~/Downloads/encrypted.dmg
cp -v ~/Documents/passwords.txt /Volumes/secretStuff
hdiutil eject /Volumes/secretStuff
```

[Tresorit](https://tresorit.com/) and [restic](https://restic.net/) may also be of interest.

# Wi-Fi

Wi-Fi networks continuously broadcast a **service set identifier (SSID)** which allows devices to passively scan for previously-connected networks. **Hidden** networks do not transmit an SSID and devices send a probe with the SSID to connect, which can reveal metadata. Avoid using [hidden networks](https://support.apple.com/guide/security/wi-fi-privacy-with-apple-devices-sec31e483abf/web#sec059998a98).

Set a [private Wi-Fi address](https://support.apple.com/guide/mac-help/use-a-private-wi-fi-address-on-mac-mchlb1cb3eb4/mac) to reduce network tracking.

Set wireless network security to [WPA3](https://en.wikipedia.org/wiki/WPA3#WPA3). Follow [Apple guidance](https://support.apple.com/102766) to set recommended settings for routers and access points.

# SSH

For outgoing SSH connections, use hardware or password-protected keys, [set up](http://nerderati.com/2011/03/17/simplify-your-life-with-an-ssh-config-file/) remote hosts and consider [hashing](http://nms.csail.mit.edu/projects/ssh/) them for added privacy. See [drduh/config/ssh_config](https://github.com/drduh/config/blob/main/ssh_config) for recommended client options.

SSH can also be used to create an [encrypted tunnel](http://blog.trackets.com/2014/05/17/ssh-tunnel-local-and-remote-port-forwarding-explained-with-examples.html) to send traffic through, similar to a VPN.

For example, to use Privoxy running on a remote host port 8118:

```bash
ssh -C -L 5555:127.0.0.1:8118 you@remote-host.tld
sudo networksetup -setwebproxy "Wi-Fi" 127.0.0.1 5555
sudo networksetup -setsecurewebproxy "Wi-Fi" 127.0.0.1 5555
```

Or to use an ssh connection as a [SOCKS proxy](https://www.mikeash.com/ssh_socks.html):

```bash
ssh -NCD 3000 you@remote-host.tld
```

By default, macOS does not have enable [Remote Login](https://support.apple.com/guide/mac-help/allow-a-remote-computer-to-access-your-mac-mchlp1066/mac) (SSH server).

To enable it and allow incoming SSH connections, use **System Settings** > **General** > **Sharing** or the command:

```bash
sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist
```

Disable password authentication and consider further [hardening](https://stribika.github.io/2015/01/04/secure-secure-shell.html) the SSH server configuration. See [drduh/config/sshd_config](https://github.com/drduh/config/blob/main/sshd_config) for recommended options.

Confirm the SSH server is running:

```bash
sudo lsof -Pni TCP:22
```

# Physical access

Do not leave the computer unattended in unsafe locations. A skilled attacker with unsupervised physical access could install a [hardware keylogger](https://trmm.net/Thunderstrike_31c3) to record keystrokes, including passwords. Using a Mac with a built-in keyboard or a bluetooth keyboard makes this more difficult as many off-the-shelf versions of this attack are designed to be plugged in between a USB keyboard and the computer.

To protect against physical theft during use, use an anti-forensic tool like [BusKill](https://github.com/buskill/buskill-app) or [swiftGuard](https://github.com/Lennolium/swiftGuard) (updated usbkill, with graphical user interface). All respond to USB events and can immediately shut the computer down if the device is physically separated or an unauthorized device is connected.

Consider purchasing a privacy screen/filter for use in public.

[Nail polish](https://trmm.net/Glitter) and tamper-evidence seals can be applied to components to detect tampering.

# System monitoring

## Logs

Monitor system logs with the **Console** application or `/usr/bin/log stream` command.

## OpenBSM audit

macOS has a powerful OpenBSM (Basic Security Module) auditing capability, which can be used to monitor processes, network activity, etc.

To tail audit logs, use the `praudit` utility:

```console
$ sudo praudit -l /dev/auditpipe
header,201,11,execve(2),0,Thu Sep  1 12:00:00 2015, + 195 msec,exec arg,/Applications/.evilapp/rootkit,path,/Applications/.evilapp/rootkit,path,/Applications/.evilapp/rootkit,attribute,100755,root,wheel,16777220,986535,0,subject,drduh,root,wheel,root,wheel,412,100005,50511731,0.0.0.0,return,success,0,trailer,201,
header,88,11,connect(2),0,Thu Sep  1 12:00:00 2015, + 238 msec,argument,1,0x5,fd,socket-inet,2,443,173.194.74.104,subject,drduh,root,wheel,root,wheel,326,100005,50331650,0.0.0.0,return,failure : Operation now in progress,4354967105,trailer,88
header,111,11,OpenSSH login,0,Thu Sep  1 12:00:00 2015, + 16 msec,subject_ex,drduh,drduh,staff,drduh,staff,404,404,49271,::1,text,successful login drduh,return,success,0,trailer,111,
```

See the manual pages for `audit`, `praudit`, `audit_control` and other files in `/etc/security`

Although `man audit` says the `-s` flag will synchronize the audit configuration, it appears necessary to reboot for changes to take effect.

See articles on [ilostmynotes.blogspot.com](https://ilostmynotes.blogspot.com/2013/10/openbsm-auditd-on-os-x-these-are-logs.html) and [derflounder.wordpress.com](https://derflounder.wordpress.com/2012/01/30/openbsm-auditing-on-mac-os-x/) for more information.

## DTrace

[System Integrity Protection](https://github.com/drduh/macOS-Security-and-Privacy-Guide#system-integrity-protection) interferes with DTrace, so it is not possible to use it in recent macOS versions without disabling SIP.

* `iosnoop` monitors disk I/O
* `opensnoop` monitors file opens
* `execsnoop` monitors processes
* `errinfo` monitors failed system calls
* `dtruss` monitors all system calls

See `man -k dtrace` for more information.

## Processes

List running processes with [Activity Monitor](https://support.apple.com/guide/activity-monitor/toc) or the `ps -ef` command.

## Network

List open network connections:

```bash
sudo lsof -Pni
```

List contents of various network-related data structures:

```bash
sudo netstat -atln
```

[Wireshark](https://www.wireshark.org/) can be used from the command line with `tshark`.

Monitor DNS:

```bash
tshark -Y "dns.flags.response == 1" -Tfields \
  -e frame.time_delta \
  -e dns.qry.name \
  -e dns.a \
  -Eseparator=,
```

Monitor HTTP:

```bash
tshark -Y "http.request or http.response" -Tfields \
  -e ip.dst \
  -e http.request.full_uri \
  -e http.request.method \
  -e http.response.code \
  -e http.response.phrase \
  -Eseparator=/s
```

Monitor x509/TLS certificates:

```bash
tshark -Y "ssl.handshake.certificate" -Tfields \
  -e ip.src \
  -e x509sat.uTF8String \
  -e x509sat.printableString \
  -e x509sat.universalString \
  -e x509sat.IA5String \
  -e x509sat.teletexString \
  -Eseparator=/s -Equote=d
```

# Miscellaneous

## Diagnostic data

Disable [Diagnostics & Usage Data](https://support.apple.com/guide/mac-help/share-analytics-information-mac-apple-mh27990).

Disable crash reporter (the dialog which appears after an application crashes and prompts to report the problem to Apple):

```bash
defaults write com.apple.CrashReporter DialogType none
```

## Media player

Use [QuickTime Player](https://en.wikipedia.org/wiki/Quicktime_player), the built-in media application, for playing music and video files. It uses [App Sandbox](https://developer.apple.com/documentation/security/app_sandbox/protecting_user_data_with_app_sandbox), [Hardened Runtime](https://developer.apple.com/documentation/xcode/configuring-the-hardened-runtime), and benefits from the [Signed System Volume](https://support.apple.com/guide/security/signed-system-volume-security-secd698747c9/web) as part of the base system.

## File handlers

Manage [default file handlers](https://support.apple.com/guide/mac-help/choose-an-app-to-open-a-file-on-mac-mh35597) to reduce risk of opening dangerous types.

Change the default application used to open shell script files.

In Finder, locate and select any .sh file, right-click it and select Get Info or press Command-I. In the "Open with" section, select TextEdit from the dropdown menu. If it is not listed, select "Other..." and Applications > TextEdit.app. Select "Change All..." and confirm by selecting Continue.

From then on, double-clicking any .sh file will open it in TextEdit instead of Terminal.

## Screensaver

Set the screen to lock as soon as the screensaver starts:

```bash
defaults write com.apple.screensaver askForPassword -int 1
defaults write com.apple.screensaver askForPasswordDelay -int 0
```

## Finder options

Expose hidden files and Library folder in Finder:

```bash
defaults write com.apple.finder AppleShowAllFiles -bool true
chflags nohidden ~/Library
```

Show all filename extensions (so that "Evil.jpg.app" cannot masquerade easily).

```bash
defaults write NSGlobalDomain AppleShowAllExtensions -bool true
```

Do not default to saving documents to iCloud:

```bash
defaults write NSGlobalDomain NSDocumentSaveNewDocumentsToCloud -bool false
```

Set a [custom umask](https://support.apple.com/101914):

```bash
sudo launchctl config user umask 077
```

Reboot, then create a file/directory and verify permissions (macOS default allows 'group/other' read access):

```console
$ ls -ld umask*
drwx------  2 kevin  staff       64 Dec  4 12:27 umask_testing_dir
-rw-------@ 1 kevin  staff  2026566 Dec  4 12:28 umask_testing_file
```

## Keyboard entry

Enable [Secure Keyboard Entry](https://support.apple.com/guide/terminal/use-secure-keyboard-entry-trml109) in Terminal (may interfere with [YubiKey](https://mig5.net/content/secure-keyboard-entry-os-x-blocks-interaction-yubikeys) or applications such as [TextExpander](https://smilesoftware.com/textexpander/secure-input)).

## Networking

Disable [Bonjour multicast advertisements](https://www.tenable.com/audits/items/CIS_Apple_macOS_10.13_v1.1.0_Level_2.audit:d9dcee7e4d2b8d2ee54f437158992d88) (also disabling AirPlay and AirPrint features):

```bash
sudo defaults write /Library/Preferences/com.apple.mDNSResponder NoMulticastAdvertisements -bool YES
```

[Disable Handoff](https://support.apple.com/guide/mac-help/change-airdrop-handoff-settings-mchl6a407f99) and [Bluetooth](https://support.apple.com/guide/mac-help/turn-bluetooth-on-or-off-blth1008) features.

macOS comes with this line in `/etc/sudoers`:

```bash
Defaults env_keep += "HOME MAIL"
```

This stops sudo from changing the HOME variable when privileges are elevanted. This means it will execute as root the zsh dotfiles in the non-root user's home directory when running `sudo zsh`. It is advisable to comment this line out to avoid a potential way for malware or a local attacker to escalate root privileges.

To retain the convenience of the root user having a non-root user's home directory, append an export line to `/var/root/.zshrc`, e.g.:

```bash
export HOME=/Users/blah
```

# Related software

* [CISOfy/lynis](https://github.com/CISOfy/lynis) - Cross-platform security auditing tool and assists with compliance testing and system hardening.
* [Zentral](https://github.com/zentralopensource/zentral) - A log and configuration server for osquery. Run audit and probes on inventory, events, logfiles, combine with point-in-time alerting. A full Framework and Django web server build on top of the elastic stack (formerly known as ELK stack).
* [osquery](https://github.com/osquery/osquery) - Can be used to retrieve low level system information.  Users can write SQL queries to retrieve system information.
* [Pareto Security](https://github.com/paretoSecurity/pareto-mac) - A MenuBar app to automatically audit your Mac for basic security hygiene.

# Additional resources

* [Apple Open Source](https://opensource.apple.com/)
* [CIS Benchmarks](https://www.cisecurity.org/benchmark/apple_os/)
* [EFF Surveillance Self-Defense Guide](https://ssd.eff.org/)
* [iOS, The Future Of macOS, Freedom, Security And Privacy In An Increasingly Hostile Global Environment](https://gist.github.com/iosecure/357e724811fe04167332ef54e736670d)
* [Patrick Wardle's Objective-See blog](https://objective-see.com/blog.html)
* [Reverse Engineering macOS blog](https://reverse.put.as/)
* [Reverse Engineering Resources](http://samdmarshall.com/re.html)
* [iCloud security and privacy overview](https://support.apple.com/102651)
* [Malwarebytes Blog](https://www.malwarebytes.com/blog)
