This guide is a collection of techniques for improving the security and privacy of macOS on [Apple silicon](https://support.apple.com/116943) Macs. It targets experienced users who want security practices commonly used by organizations, but is also suitable for novice users with an interest in privacy and security.

For securing computers in an organization, refer to the [security guidelines from NIST](https://github.com/usnistgov/macos_security), a U.S. government cybersecurity standards [organization](https://en.wikipedia.org/wiki/National_Institute_of_Standards_and_Technology)

This guide is provided "as is" - without warranties of any kind. You are solely responsible for any consequences of following it.

To suggest a change, submit a [pull request](https://github.com/drduh/macOS-Security-and-Privacy-Guide/pulls) or open an [issue](https://github.com/drduh/macOS-Security-and-Privacy-Guide/issues).

- [Basics](#basics)
- [Threat modeling](#threat-modeling)
  - [Assets](#assets)
  - [Adversaries](#adversaries)
  - [Capabilities](#capabilities)
  - [Mitigations](#mitigations)
- [Hardware](#hardware)
- [Installing macOS](#installing-macos)
  - [System activation](#system-activation)
  - [Apple Account](#apple-account)
  - [App Store](#app-store)
  - [Virtualization](#virtualization)
    - [Apple containers](#apple-containers)
- [First boot](#first-boot)
- [Admin and user accounts](#admin-and-user-accounts)
  - [Caveats](#caveats)
  - [Setup](#setup)
- [Firmware](#firmware)
- [FileVault](#filevault)
- [Lockdown Mode](#lockdown-mode)
- [Firewall](#firewall)
  - [Application layer firewall](#application-layer-firewall)
  - [Third-party firewalls](#third-party-firewalls)
  - [Packet filter](#packet-filter)
- [Services](#services)
- [Siri Suggestions and Spotlight](#siri-suggestions-and-spotlight)
- [Homebrew](#homebrew)
- [DNS](#dns)
  - [DNS profiles](#dns-profiles)
  - [Hosts file](#hosts-file)
  - [DNSCrypt](#dnscrypt)
  - [Dnsmasq](#dnsmasq)
- [Certificate authorities](#certificate-authorities)
- [Privoxy](#privoxy)
- [Browser](#browser)
  - [Firefox](#firefox)
  - [Chrome](#chrome)
  - [Safari](#safari)
  - [Web browser privacy](#web-browser-privacy)
- [Tor](#tor)
- [VPN](#vpn)
- [PGP/GPG](#pgpgpg)
- [Email](#email)
  - [Thunderbird](#thunderbird)
- [Messengers](#messengers)
  - [XMPP](#xmpp)
  - [Signal](#signal)
  - [iMessage](#imessage)
- [Viruses and malware](#viruses-and-malware)
  - [Downloading Software](#downloading-software)
  - [App Sandbox](#app-sandbox)
  - [Hardened Runtime](#hardened-runtime)
  - [Antivirus](#antivirus)
  - [Gatekeeper](#gatekeeper)
- [System Integrity Protection](#system-integrity-protection)
- [Metadata and artifacts](#metadata-and-artifacts)
- [Authentication](#authentication)
- [Backup](#backup)
- [Wi-Fi](#wi-fi)
- [SSH](#ssh)
- [Physical access](#physical-access)
- [Monitoring](#monitoring)
  - [Logs](#logs)
  - [DTrace](#dtrace)
  - [Processes](#processes)
  - [Network](#network)
- [Miscellaneous](#miscellaneous)
- [Related software](#related-software)
- [Additional resources](#additional-resources)

# Basics

Apply general security best practices:

- Create a [threat model](#threat-modeling)
  - What needs protection and from whom? Is the adversary a three-letter agency, an eavesdropper on a network, or a determined [Advanced Persistent Threat (APT)](https://en.wikipedia.org/wiki/Advanced_persistent_threat) orchestrating a campaign against you?
  - Recognize threats and learn how to reduce the number of ways an attacker could potentially access a system or data.

- Keep the system and software up to date
  - Regularly install available updates for the operating system and all applications.
  - Updates are installed in [System Settings](https://support.apple.com/guide/mac-help/keep-your-mac-up-to-date-mchlpx1065) or with the `softwareupdate` command-line utility. Neither requires an Apple Account.
  - Subscribe to the [Apple security-announce](https://lists.apple.com/archives/list/security-announce@lists.apple.com/) mailing list or check [Apple security releases](https://support.apple.com/100100).

- Encrypt sensitive data
  - In addition to [FileVault](https://support.apple.com/guide/mac-help/protect-data-on-your-mac-with-filevault-mh11785) storage encryption, use the [built-in password manager](https://support.apple.com/105115) to protect passwords and other sensitive data.

- Ensure data availability
  - Create [regular backups](https://support.apple.com/104984) of critical data and be ready to [restore from a backup](https://support.apple.com/102551) in case of compromise.
  - [Encrypt locally](https://support.apple.com/guide/mac-help/keep-your-time-machine-backup-disk-secure-mh21241) before copying backups to unencrypted external media or the "cloud"; alternatively, enable [end-to-end encryption](https://support.apple.com/guide/security/advanced-data-protection-for-icloud-sec973254c5f).
  - Verify backups by accessing them on a scheduled basis.

- Click carefully
  - Ultimately, the security of a system depends on the capabilities and habits of its administrator.
  - Take care when installing new software: install it only from sources the developer identifies as official, such as their website or GitHub repository.

# Threat modeling

The most important step to meaningfully improve security and privacy is to create a [threat model](https://owasp.org/www-community/Threat_Modeling). This creates an understanding of potential adversaries and their motivations, which leads to stronger defenses. Each individual should develop their own unique threat model. Threat models are likely to change over time and should be periodically re-assessed.

## Assets

Assets may include a phone, laptop, credentials, and personal information, such as browsing history.

List them in order of importance, starting with those most worth protecting.

## Adversaries

Define whom you are defending against. Start by defining the motivation each adversary might have to attack important assets. [Financial gain](https://www.verizon.com/business/resources/reports/dbir/) is a big motivator for many attackers, for example.

## Capabilities

To counter adversaries, understand both their capabilities and limitations. Rank them from least to most capable. For example, a common thief operates opportunistically: they will likely be defeated by the basics, such as screen lock and encrypted storage with strong passwords. A more sophisticated and determined adversary may require fully powering off a device when not in use to clear credentials from memory and stronger authentication mechanisms.

## Mitigations

Choose the best mitigation for each threat. For example, avoid writing passwords on paper if a roommate might find them, or encrypt storage to protect its data if it is stolen.

Security should be balanced with usability: every mitigation should counter some adversarial capability to justify any inconvenience. If you can't think of any more capabilities your adversaries might have and you've implemented mitigations for them all, your work is done.

The following is an example of assets to protect:

Adversary | Motivation | Capabilities | Mitigation
:-: | :-: | :-: | :-:
Roommate | See private chats or browsing history | Close proximity; can see screen or observe credentials | Use biometric (fingerprint or face) authentication, use privacy screen, keep phone locked when not using it
Thief | Unlock phone and steal personal info and drain bank accounts, sell phone for money | Observe password being entered, steal logged-in device left unattended | Maintain physical custody of device at all times, lock devices when not in use, avoid typing password in public view, use Find My or similar services to track or remotely disable stolen devices
Criminal | Financial gain | Social engineering (tricking a user into revealing information or taking unsafe actions), readily-available malware, password reuse, exploiting vulnerabilities | Sandbox software, enable OS security features, maintain software updates automatically
Corporation | Marketing based on user data | Telemetry and behavioral data collection | Block network connections, reset device-specific identifiers, avoid adding payment data
Nation State/APT | Targeted surveillance | Passive surveillance of internet infrastructure, advanced encryption analysis | Use open-source software, strong diceware credentials, hardware with secure element, shut down devices when not in use, tripwire/honeypot/[canary tokens](https://canarytokens.org/) alerts

Read more about [threat modeling](https://www.netmeister.org/blog/threat-model-101.html).

# Hardware

> [!IMPORTANT]
> Macs with Intel CPUs have [security vulnerabilities](https://github.com/axi0mX/ipwndfu?tab%253Dreadme-ov-file#checkm8) on a hardware level which cannot be patched.

macOS is most secure when running on [Apple silicon hardware](https://support.apple.com/guide/security/hardware-security-overview-secf020d1074/1/web/1). In general, newer models offer stronger security guarantees. Avoid non-Apple hardware running macOS and systems that do not support the latest macOS release, as Apple does not [patch all vulnerabilities](https://support.apple.com/guide/deployment/about-software-updates-depc4c80847a) in legacy versions.

Apple accessories generally receive firmware updates through macOS and support current [Bluetooth security features](https://support.apple.com/guide/security/bluetooth-security-sec82597d97e/web). For example, [Bluetooth Low Energy](https://en.wikipedia.org/wiki/Bluetooth_Low_Energy) (BLE) Privacy uses rotating device addresses to reduce tracking; third-party accessories may not support this feature.

When purchasing a Mac, consider paying in cash rather than ordering online or purchasing with a credit/debit card, to limit identifying information linked to the purchase.

# Installing macOS

There are several ways to [install macOS](https://support.apple.com/102662).

Install the latest supported version of macOS; newer versions of macOS include security fixes and other improvements not available in previous releases.

## System activation

As part of Apple's [theft prevention system](https://support.apple.com/102541), Apple silicon Macs connect to Apple servers when macOS is installed to check against the database of lost or stolen systems.

Read about [how this process works](https://support.apple.com/guide/security/localpolicy-signing-key-creation-management-sec1f90fbad1).

## Apple Account

An [Apple Account](https://www.apple.com/legal/privacy/data/en/apple-id/) is not required to use macOS, but it is necessary to access the App Store and most Apple services, including iCloud and Apple Music.

You can later [disable synchronization](https://support.apple.com/102651), [enable end-to-end encryption](https://support.apple.com/guide/security/advanced-data-protection-for-icloud-sec973254c5f/web) for eligible iCloud data, [manage Apple Account data](https://support.apple.com/102283), or delete the account.

## App Store

The [App Store](https://en.wikipedia.org/wiki/Mac_app_store) is a software distribution platform where applications are [reviewed](https://developer.apple.com/app-store/review/guidelines) by Apple.

App Store applications are required to use [App Sandbox](https://developer.apple.com/documentation/security/app_sandbox/protecting_user_data_with_app_sandbox) and [Hardened Runtime](https://developer.apple.com/documentation/security/hardened_runtime) (security features restricting what apps can do, making some attacks more difficult). It also offers automatic software updates.

Using the App Store requires an Apple Account, which can pose a privacy risk.

## Virtualization

On Apple silicon, macOS includes Apple's [Virtualization framework](https://developer.apple.com/documentation/virtualization), which supports macOS and Windows 11 ARM virtual machines through tools such as:

- [UTM](https://mac.getutm.app/) - Follow the [documentation](https://docs.getutm.app/guest-support/macos) to create macOS and other virtual machines.
- [VirtualBuddy](https://github.com/insidegui/VirtualBuddy) - Application for virtualizing macOS 12+ on Apple silicon.
- [Bushel](https://getbushel.app/) - A lightweight, free app. On first launch, select "Ask App Not to Track".
- [VMware Fusion](https://knowledge.broadcom.com/external/article/315638/download-and-install-vmware-fusion.html) - Now free under Broadcom. Clean UI, easy macOS setup, and supports Windows 11 ARM.
- [tart (CLI)](https://tart.run/) - Command‑line application installed with Homebrew.
- [Parallels](https://www.parallels.com/) - Paid option with strong integration.

> [!WARNING]
> VMware requires a Broadcom account and acceptance of agreements before download.
> Parallels requires an account, payment details, and other data - see the [privacy notice](https://my.parallels.com/data_reminder).

### Apple containers

[Apple Container](https://github.com/apple/container) provides a native command-line workflow for running Linux container images on macOS. Unlike container runtimes that share a single Linux virtual machine, Apple Container runs each container in an isolated, lightweight virtual machine using macOS virtualization capabilities. This provides a stronger isolation boundary between workloads and the host operating system.

# First boot

When macOS starts for the first time, **Setup Assistant** requires the creation of a primary account.

Set a [strong password](https://www.eff.org/dice) without a hint.

Avoid personally identifiable names: the computer name (such as "John Appleseed's MacBook") is broadcast over local networks and visible to other devices.

The system name can be configured in **System Settings > About** or with the commands:

```bash
sudo scutil --set ComputerName MacBook
sudo scutil --set HostName MacBook
sudo scutil --set LocalHostName MacBook
```

# Admin and user accounts

The first user account created is always an administrator account. Administrator accounts belong to the admin group and can use [sudo](https://en.wikipedia.org/wiki/Sudo) (a command that grants temporary administrator access) to run commands with elevated privileges, up to and including root (full system) control. Any program the administrator executes can potentially obtain the same access, and sudo may have vulnerabilities [exploited](https://bogner.sh/2014/03/another-mac-os-x-sudo-password-bypass/) by concurrently-running software.

It is considered a [best practice](https://help.apple.com/machelp/mac/10.12/index.html#/mh11389) to use a dedicated standard account for regular, daily work and only use the administrator account for software and system installation, configuration and updates.

It is not required to ever log in with the admin account via the macOS login screen. When a Terminal command requires administrator privileges, the system will prompt for authentication and Terminal continues using those privileges. To that end, Apple provides [recommendations](https://support.apple.com/102099) for hiding the admin account and its home directory.

## Caveats

- Only administrators can install applications in the system-wide `/Applications` directory. Finder and Installer will prompt a standard user with a password prompt asking an administrator to approve the change. Many applications can be installed in `~/Applications` instead. As a rule of thumb, applications which do not require admin access – or do not complain about not being installed in `/Applications` – should be installed in the user directory, the rest in the local directory. App Store applications are still installed in `/Applications` and require no additional authentication.
- A standard user usually is not authorized to use `sudo`. When administrator privileges are required, macOS prompts for an administrator's credentials, or the task can be run from an administrator account.
- System Settings and several system utilities (e.g., Wi-Fi Diagnostics) require administrator permission for full functionality. Some System Settings need to be unlocked by selecting the lock icon. Some applications will simply prompt for authentication upon opening, others must be opened by an admin account directly to access all functions (e.g., Console).
- There are third-party applications that will not work correctly because they assume the user account is an admin. These programs may have to be executed by the admin account, or by using the `open` utility.
- See additional discussion in [issue 167](https://github.com/drduh/macOS-Security-and-Privacy-Guide/issues/167).

## Setup

Accounts can be created and managed in System Settings. On existing systems, it is generally easier to create a second admin account and then change the original account from an administrator account to a standard account.  Newly-installed systems should instead add a standard account after setup.

Demoting an account can be done either from the new admin account in System Settings – the other account must be logged out – or by executing these commands (it may not be necessary to execute both, see [issue 179](https://github.com/drduh/macOS-Security-and-Privacy-Guide/issues/179)):

```bash
sudo dscl . -delete /Groups/admin GroupMembership <username>
sudo dscl . -delete /Groups/admin GroupMembers <GeneratedUID>
```

To obtain an account's **GeneratedUID**:

```bash
dscl . -read /Users/<username> GeneratedUID
```

See also [this post](https://superuser.com/a/395738) for more information about how macOS determines group membership.

# Firmware

Verify that firmware security is set to [Full Security](https://support.apple.com/guide/mac-help/mchl768f7291/mac) to prevent tampering with the system. This is the default setting.

# FileVault

Apple silicon Macs use hardware-backed storage encryption by default. [FileVault](https://support.apple.com/guide/mac-help/protect-data-on-your-mac-with-filevault-mh11785/mac) additionally requires an authorized user's password to unlock the startup volume after restart.

On Apple silicon, FileVault authorization also protects the [firmware](https://support.apple.com/102384), which prevents booting from anything other than the designated startup disk, accessing [Recovery](https://support.apple.com/guide/mac-help/macos-recovery-a-mac-apple-silicon-mchl82829c17/15.0/mac/15.0#mchl5abfbb29), and [reviving](https://support.apple.com/108900) it with device firmware update (DFU) mode.

FileVault will prompt to set a recovery key, which should be stored in a safe location if used. FileVault also offers an option to use iCloud for recovery.

Confirm FileVault state:

```bash
fdesetup status
```

# Lockdown Mode

[Lockdown Mode](https://support.apple.com/105120) significantly reduces attack surface by disabling system and application features commonly exploited in targeted attacks.

When Lockdown Mode is enabled, Safari has an option to [exclude trusted websites](https://ssd.eff.org/module/how-to-enable-lockdown-mode-on-iphone) from restrictions.

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

Attackers scan networks to identify systems to target. When Stealth Mode is enabled, responses are not sent to connection attempts from closed ports, making the system more difficult to detect.

Prevent built-in and downloaded software from automatically receiving incoming connections:

```bash
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setallowsigned off
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setallowsignedapp off
```

Applications signed by a valid certificate authority are automatically added to the list of allowed apps, rather than prompting the user to authorize them. Apps included in macOS are signed by Apple and are allowed to receive incoming connections when this setting is enabled.

If an unsigned app not listed in the firewall list is opened, a dialog appears with options to Allow or Deny connections. If allowed, macOS signs the application and adds it to the firewall list. If denied, macOS adds it to the list and denies incoming connections.

After interacting with `socketfilterfw`, restart the process by sending a [SIGHUP](https://en.wikipedia.org/wiki/SIGHUP) signal:

```bash
sudo pkill -HUP socketfilterfw
```

Confirm firewall state:

```console
for firewallFlag in \
  --getglobalstate \
  --getblockall \
  --getallowsigned \
  --getstealthmode \
  --listapps
do /usr/libexec/ApplicationFirewall/socketfilterfw "$firewallFlag"
done
```

### AirDrop

Enabling the application layer firewall and disabling incoming connections for built-in software prevents [AirDrop](https://support.apple.com/119857) from functioning correctly. For AirDrop to work, both `sharingd` and `rapportd` require firewall exceptions:

```bash
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add /usr/libexec/sharingd
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --unblockapp /usr/libexec/sharingd
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --add /usr/libexec/rapportd
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --unblockapp /usr/libexec/rapportd
```

## Third-party firewalls

Applications such as [Little Snitch](https://www.obdev.at/products/littlesnitch/index.html), [Radio Silence](https://radiosilenceapp.com/), and [LuLu](https://objective-see.com/products/lulu.html) provide a balance between usability and security.

These programs are capable of monitoring and blocking both incoming and outgoing connections. However, they may require a closed-source [system extension](https://support.apple.com/HT210999).

If frequent allow-or-block prompts are overwhelming, begin with Silent Mode configured to allow connections. Review the configuration periodically to understand each application's network activity.

> [!NOTE]
> A root-level compromise can undermine host-based network controls, depending on the product and system configuration.

## Packet filter

macOS also includes [pf](https://en.wikipedia.org/wiki/PF_(firewall)), a packet-filtering firewall configured from the command line. It is powerful but considerably more complex than the built-in application firewall.

pf can also be controlled with a graphical application such as [Murus](https://www.murusfirewall.com/).

Many [books](https://nostarch.com/book-of-pf-4e) and [guides](https://www.openbsd.org/faq/pf/) cover the pf firewall. The following example shows how to configure a basic policy.

Add the following rules to a file named `pf.rules`:

```console
# Define interface
wifi = "en0"

# Global options
set block-policy drop
set skip on lo0
set state-policy if-bound
set ruleset-optimization basic
scrub in on $wifi all fragment reassemble

# Define tables
table <blocklist> persist

# Default deny both directions and log
block log all
block quick from no-route to any
antispoof quick for $wifi

# Blocklist enforcement
block log quick on $wifi from { <blocklist> } to any
block log quick on $wifi from any to { <blocklist> }

# Outbound TCP
pass out on $wifi proto tcp from ($wifi) to any flags S/SA keep state

# Outbound UDP
pass out on $wifi proto udp from ($wifi) to any keep state

# Outbound ICMP (ping)
pass out on $wifi proto icmp from ($wifi) to any keep state
```

To control the firewall:

Command | Task
-: | :-
`sudo pfctl -e -f pf.rules` | enable firewall with configuration file
`sudo pfctl -d` | disable firewall
`sudo pfctl -t blocklist -T add 1.2.3.4` | add an address to the blocklist

To monitor the firewall:

Command | Task
-: | :-
`sudo pfctl -t blocklist -T show` | view the blocklist
`sudo pfctl -sr` | show active rules
`sudo pfctl -ss` | show state table
`sudo ifconfig pflog0 create` | create packet log interface
`sudo tcpdump -ni pflog0` | monitor blocked packets

pf can block access to ranges of network addresses, for example to an entire organization. Query [Merit RADb](https://www.radb.net/) for the list of networks in use by an [autonomous system](https://en.wikipedia.org/wiki/Autonomous_system_(Internet)) (a large network operated by a single organization), such as [Facebook](https://ipinfo.io/AS32934):

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

$ curl --connect-timeout 5 -I https://facebook.com/
*   Trying 157.240.2.35...
* TCP_NODELAY set
* Connection timed out after 5002 milliseconds
* Closing connection 0
curl: (28) Connection timed out after 5002 milliseconds

$ sudo tcpdump -tqni pflog0 'host 157.240.2.35'
IP 192.168.1.1.62771 > 157.240.2.35.443: tcp 0
IP 192.168.1.1.62771 > 157.240.2.35.443: tcp 0
IP 192.168.1.1.62771 > 157.240.2.35.443: tcp 0
```

The firewall drops the outbound [SYN packets](https://en.wikipedia.org/wiki/Transmission_Control_Protocol#Connection_establishment), so the TCP connection cannot be established.

See [drduh/config/scripts/pf-blocklist.sh](https://github.com/drduh/config/blob/main/scripts/pf-blocklist.sh) for more inspiration.

# Services

Many system and user background services are managed by [launchd](https://en.wikipedia.org/wiki/Launchd).

Administrator accounts can modify services and extensions in [System Settings](https://support.apple.com/guide/mac-help/change-login-items-settings-mtusr003).

Command | Task
-: | :-
`launchctl list` | view user jobs
`sudo launchctl list` | view system jobs
`launchctl list com.apple.Finder` | examine a service
`ls /System/Library/LaunchDaemons` | list system daemons
`ls /System/Library/LaunchAgents` | list system agents
`defaults read /System/Library/LaunchAgents/com.apple.Finder` | read service configuration
`systemextensionsctl list` | list system extensions

> [!IMPORTANT]
> System services are protected by [SIP](https://github.com/drduh/macOS-Security-and-Privacy-Guide#system-integrity-protection). Do not disable SIP just to modify system services as it is a fundamental part of the macOS security model. Disabling system services may also cause system instability.

To view the status of services:

```bash
find /var/db/com.apple.xpc.launchd \
  -type f -print -exec defaults read {} \; 2>/dev/null
```

See [script management with launchd](https://support.apple.com/guide/terminal/script-management-with-launchd-apdc6c1077b-5d5d-4d35-9c19-60f2397b2369) and [launchd.info](https://launchd.info/) for more information.

# Siri Suggestions and Spotlight

Apple is moving many Siri functions to on-device processing, but using Siri Suggestions or Spotlight may still send some information to Apple. See Apple's [Privacy Policy](https://www.apple.com/legal/privacy/data/en/siri-suggestions-search/) to see exactly what is sent and how to disable it.

# Homebrew

If a program is not available through the App Store, consider using [Homebrew](https://brew.sh/).

> [!IMPORTANT]
> Some Homebrew installation or management workflows may prompt for App Management or [Full Disk Access](https://eclecticlight.co/2025/11/08/explainer-permissions-privacy-and-tcc/). Grant these permissions only when necessary: they can substantially expand the access available to commands run through Terminal.

Remember to periodically run `brew upgrade` on trusted and secure networks to download and install software updates. To get information on a package before installation, run `brew info <package>` and check its formula online. You may also wish to enable [additional security options](https://github.com/drduh/macOS-Security-and-Privacy-Guide/issues/138), such as `HOMEBREW_NO_INSECURE_REDIRECT=1`

According to [Homebrew's Anonymous Analytics](https://docs.brew.sh/Analytics), Homebrew collects anonymous usage analytics and reports them to a self-hosted [InfluxDB](https://en.wikipedia.org/wiki/InfluxDB) instance.

To opt out of Homebrew analytics, run `brew analytics off` or set `HOMEBREW_NO_ANALYTICS=1` in the shell startup file.

# DNS

## DNS profiles

macOS features "DNS configuration profiles" for configuring encrypted DNS, filtering, and [DNSSEC](https://en.wikipedia.org/wiki/Domain_Name_System_Security_Extensions).

DNS profiles can be [created](https://dns.notjakob.com/) or obtained from providers such as [Quad9](https://docs.quad9.net/Setup_Guides/MacOS/Big_Sur_and_later_(Encrypted)/#download-profile), [AdGuard](https://adguard-dns.io/en/public-dns.html) and [NextDNS](https://nextdns.io/).

## Hosts file

Use the [hosts file](https://en.wikipedia.org/wiki/Hosts_(file)) to block domains associated with malware, advertising, and other unwanted services.

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
- [StevenBlack/hosts](https://github.com/StevenBlack/hosts)
- [Sinfonietta/hostfiles](https://github.com/Sinfonietta/hostfiles)
- [someonewhocares.org](https://someonewhocares.org/hosts/zero/hosts)

To download and append a list to the hosts file, use the [tee](https://man7.org/linux/man-pages/man1/tee.1.html) command:

```bash
curl https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts | sudo tee -a /etc/hosts
```

[Little Snitch](#third-party-firewalls) also supports [blocklists](https://help.obdev.at/littlesnitch6/lsc-blocklists).

## DNSCrypt

To encrypt DNS traffic, consider [DNSCrypt/dnscrypt-proxy](https://github.com/DNSCrypt/dnscrypt-proxy). When configured with a trusted resolver, DNSCrypt encrypts DNS queries. DNSSEC can additionally validate signed DNS responses where supported.

Install DNSCrypt from Homebrew and follow the instructions to configure and start `dnscrypt-proxy`:

```bash
brew install dnscrypt-proxy
```

When using DNSCrypt with Dnsmasq, locate the DNSCrypt configuration file by running:

```bash
brew info dnscrypt-proxy
```

This command should display a path such as `/usr/local/etc/dnscrypt-proxy.toml`.

By default, dnscrypt-proxy listens on `127.0.0.1:53` and sends queries to one or more configured DNS providers. Modify the configuration and change `listen_addresses` to use a port other than 53, such as 5355:

```toml
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

Additionally, these pf rules block conventional DNS traffic to port 53 outside the loopback interface, to reduce the risk of [DNS leaks](https://dnsleaktest.com/):

```shell
block drop quick on !lo0 proto udp from any to any port = 53
block drop quick on !lo0 proto tcp from any to any port = 53
```

## Dnsmasq

[dnsmasq](https://thekelleys.org.uk/dnsmasq/doc.html) can cache replies, prevent upstream queries for unqualified names, and block entire top-level domains.

Use it in combination with DNSCrypt to encrypt DNS traffic.

If you do not use DNSCrypt, at minimum choose a DNS resolver other than the one provided by the ISP. Two popular alternatives are [Google DNS](https://developers.google.com/speed/public-dns/) and [OpenDNS](https://www.opendns.com/home-internet-security/).

Install Dnsmasq:

```bash
brew install dnsmasq
```

Download and edit [drduh/config/dnsmasq.conf](https://github.com/drduh/config/blob/main/dnsmasq.conf) or the default configuration file.

See [drduh/config/domains](https://github.com/drduh/config/tree/main/domains) for example domain lists that can be added to block specific destinations.

Install and start the program (sudo is required to bind to [privileged port](https://unix.stackexchange.com/questions/16564/why-are-the-first-1024-ports-restricted-to-the-root-user-only) 53):

```bash
sudo brew services start dnsmasq
```

To set dnsmasq as the local DNS server, open **System Settings** > **Network** and select the network connection currently in use (such as Wi-Fi), then open the **DNS** tab, select **+**, and add `127.0.0.1`, or use:

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

macOS includes more than 150 [trusted root](https://support.apple.com/103723) certificate authority (CA) certificates, operated by corporations and government agencies from around the world. These CAs are capable of issuing valid TLS and code-signing certificates.

Apple [blocks certificates](https://support.apple.com/103247#blocked) when a CA proves to be untrustworthy and requires [certain criteria](https://www.apple.com/certificateauthority/ca_program.html) for inclusion. For more information, see [CA/Browser Forum](https://cabforum.org/resources/browser-os-info/).

Inspect root certificates in [Keychain Access](https://support.apple.com/guide/keychain-access/toc), under the **System Roots** tab or by using the `security` command line tool and `/System/Library/Keychains/SystemRootCertificates.keychain` file.

To disable a certificate authority, mark it as **Never Trust** and close the window to confirm. Doing so may reduce the risk of [MITM](https://wikipedia.org/wiki/Man-in-the-middle_attack) attacks, in which a coerced or compromised certificate authority could issue a fraudulent certificate, allowing encrypted traffic to be [silently intercepted](https://en.wikipedia.org/wiki/DigiNotar#Issuance_of_fraudulent_certificates).

# Privoxy

Consider using [Privoxy](https://www.privoxy.org/) as a local proxy to filter web traffic.

Install and start Privoxy using Homebrew:

```bash
brew install privoxy
brew services start privoxy
```

Alternatively, a signed installation package for Privoxy is available from [their website](https://www.privoxy.org/sf-download-mirror/Macintosh%20%28OS%20X%29/) or [Sourceforge](https://sourceforge.net/projects/ijbswa/files/Macintosh%20%28OS%20X%29/). The signed package is [more secure](https://github.com/drduh/macOS-Security-and-Privacy-Guide/issues/65) than the Homebrew version and receives support from the Privoxy project.

By default, Privoxy listens on local TCP port 8118.

Set the system **HTTP** proxy for the active network interface to `127.0.0.1` and port `8118`:

```bash
sudo networksetup -setwebproxy "Wi-Fi" 127.0.0.1 8118
```

Set the system **HTTPS** proxy:

```bash
sudo networksetup -setsecurewebproxy "Wi-Fi" 127.0.0.1 8118
```

The proxy can also be set in **System Settings** > **Network** > **Details** > **Proxies**.

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

Although most web traffic is encrypted, Privoxy can filter requests by hostname. For example, the following rules block all traffic except traffic to .net, github.com, and Apple domains:

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

See [drduh/config/privoxy/config](https://github.com/drduh/config/blob/main/privoxy/config) and [drduh/config/privoxy/user.action](https://github.com/drduh/config/blob/main/privoxy/user.action) for additional Privoxy examples. Privoxy does **not** need to be restarted after editing filter rules.

To verify traffic is blocked or redirected, use [curl](https://en.wikipedia.org/wiki/CURL) or open the Privoxy interface at <http://p.p> in a browser:

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
> Applications and services can ignore the proxy settings. pf can redirect traffic through a proxy without configuring each application separately.

# Browser

Web browsers create significant security and privacy risks because they download and execute untrusted Internet content.

A key browser security boundary is the [same-origin policy](https://en.wikipedia.org/wiki/Same-origin_policy) (SOP), which prevents one website from reading another website's data. A bypass can expose data or actions from other sites in the same browser profile.

Some browser exploits rely on social engineering to gain persistence (ability to remain active after the initial attack). Be mindful when visiting untrusted sites and especially careful when downloading unrecognized software.

Browser extensions also pose a significant security risk: a malicious or poorly-made extension can compromise everything in the browser, including credentials. The use of browser extensions should be limited to critically necessary ones, published by trustworthy developers only.

Use separate browser profiles to compartmentalize identities, cookies, and site data. If practical, disable JavaScript and only allow it on trusted sites using browser site permissions.

[Mozilla Firefox](https://www.firefox.com/), [Google Chrome](https://www.google.com/chrome), [Safari](https://www.apple.com/safari), and [Tor Browser](https://www.torproject.org/download) are popular browsers, each with unique features and individual purposes.

## Firefox

Firefox modernized major parts of its codebase through the [Quantum](https://wiki.mozilla.org/Quantum) and [Photon](https://wiki.mozilla.org/Firefox/Photon/Updates) projects. Quantum includes moving some components from C++ to [Rust](https://rust-lang.org/), a programming language designed to improve memory safety and concurrency safety.

Firefox offers a comparable security model to Chrome, including a [bug bounty program](https://www.mozilla.org/security/bug-bounty/) for responsible disclosure of vulnerabilities. Firefox follows a four-week release cycle.

See [drduh/config/firefox.user.js](https://github.com/drduh/config/blob/main/firefox.user.js) and [arkenfox/user.js](https://github.com/arkenfox/user.js) for recommended configurations for Firefox. Also see [NoScript](https://noscript.net/), an extension which allows selective script blocking.

Firefox [focuses on user privacy](https://www.mozilla.org/firefox/privacy). It supports [tracking protection](https://developer.mozilla.org/docs/Web/Privacy/Firefox_tracking_protection) in Private Browsing mode. The tracking protection can be enabled for the default account, although it may break the browsing experience on some websites. Firefox in Strict tracking protection mode will [randomize fingerprints](https://support.mozilla.org/kb/firefox-protection-against-fingerprinting) to defend against tracking. Firefox offers separate user [profiles](https://support.mozilla.org/kb/profile-manager-create-remove-switch-firefox-profiles). Browsing can also be delineated with [Multi-Account Containers](https://support.mozilla.org/kb/containers).

Firefox only supports Web Extensions through the [WebExtension API](https://developer.mozilla.org/docs/Mozilla/Add-ons/WebExtensions), which is very similar to Chrome. Submission of Web Extensions in Firefox is free. Web Extensions in Firefox most of the time are open-source, although certain Web Extensions are proprietary.

## Chrome

[Google Chrome](https://www.google.com/chrome/) is based on the open-source [Chromium project](https://www.chromium.org/) with certain [proprietary components](https://fossbytes.com/difference-google-chrome-vs-chromium-browser), such as:

- [Chrome Web Store](https://chromewebstore.google.com/)
- Automatic updates with GoogleSoftwareUpdateDaemon
- Usage tracking and crash reporting, which can be disabled through Chrome's settings
- Media Codec support for proprietary codecs
- PDF viewer
- Non-optional tracking. Google Chrome installer includes a randomly generated token, which is sent to Google. The RLZ identifier stores information in the form of encoded strings, such as the source of the download and install time. It does not include personal information and it's used to measure the effectiveness of a promotional campaign. **Chrome downloaded from Google's website doesn't have the RLZ identifier**. The source code to decode the strings is made open by Google.

Chrome offers account sync between multiple devices, including credentials; the data is encrypted with the account password.

The Chrome Web Store requires a [5 USD registration fee](https://developer.chrome.com/docs/webstore/register) to submit extensions. This allows development of open-source Web Extensions which do not aim to monetize through usage.

Chrome has the largest share of global usage and is the preferred target platform for the majority of developers. Major technologies are based on Chrome's open-source components, such as [node.js](https://nodejs.org/) which uses [Chrome's V8](https://developers.google.com/v8) Engine and the [Electron](https://electron.atom.io/) framework, which is based on Chromium and node.js. Chrome's vast user base makes it the most attractive target for threat actors and security researchers. Despite constant attacks, Chrome has retained an impressive security track record over the years. This is not a small feat.

Chrome offers [separate profiles](https://www.chromium.org/user-experience/multi-profiles), [robust sandboxing](https://chromium.googlesource.com/chromium/src/+/HEAD/docs/design/sandbox.md), [frequent updates](https://chromereleases.googleblog.com/), and carries [impressive credentials](https://www.chromium.org/Home/chromium-security/brag-sheet). In addition, Google offers a very lucrative [bounty program](https://bughunters.google.com/about/rules/5745167867576320/chrome-vulnerability-reward-program-rules) for reporting vulnerabilities, along with its own [Project Zero](https://googleprojectzero.blogspot.com/) team. This means that a large number of highly talented and motivated people are constantly auditing and securing Chrome code.

Consider disabling V8 optimization (JavaScript-engine performance features) in browser settings - see [this explanation](https://microsoftedge.github.io/edgevr/posts/Super-Duper-Secure-Mode) for the security trade-offs.

Block trackers with [uBlock Origin Lite](https://chromewebstore.google.com/detail/ublock-origin-lite/ddkjiahejlhfcafbddmgiahcphecmpfh).

Disable [DNS prefetching](https://www.chromium.org/developers/design-documents/dns-prefetching) (see [DNS Prefetching and Its Privacy Implications](https://www.usenix.org/legacy/event/leet10/tech/full_papers/Krishnan.pdf)). Chrome [may attempt](https://github.com/drduh/macOS-Security-and-Privacy-Guide/issues/350) to resolve DNS using Google's `8.8.8.8` and `8.8.4.4` public nameservers.

See [Chromium Security](https://www.chromium.org/Home/chromium-security) and [Chromium Privacy](https://www.chromium.org/Home/chromium-privacy) for more information. Read [Google's privacy policy](https://policies.google.com/privacy) to understand how personal information is collected and used.

## Safari

[Safari](https://www.apple.com/safari) is the default browser on macOS. It is also the most optimized browser for reducing battery use. Safari has both open-source and proprietary components. Safari is based on the open-source Web Engine [WebKit](https://webkit.org/), which is ubiquitous among the macOS ecosystem. WebKit is used by Apple apps such as Mail, Books, and the App Store. Chrome's [Blink](https://www.chromium.org/blink) engine is a fork of WebKit and both engines share a number of similarities.

Safari supports certain unique features that benefit user security and privacy. [Content blockers](https://webkit.org/blog/3476/content-blockers-first-look) enable the creation of content blocking rules without using JavaScript. This rule based approach greatly improves memory use, security, and privacy. Safari 11 introduced [Intelligent Tracking Prevention](https://webkit.org/blog/7675/intelligent-tracking-prevention), which removes tracking data stored in Safari after a period of non-interaction by the user from the tracker's website. Safari can randomize the browser fingerprint to reduce tracking. Safari does not support certain features such as WebUSB or the Battery API intentionally for security and privacy reasons. Private tabs in Safari have isolated cookies and cache that is destroyed when you close the tab. Safari also support Profiles which are equivalent to Firefox's Multi-Account Containers for separating cookies and browsing. Safari can be made significantly more secure with [lockdown mode](#lockdown-mode), which can be disabled per-site. Read more about [tracking prevention](https://webkit.org/tracking-prevention/) in Safari.

Safari offers an invite-only [bounty program](https://developer.apple.com/bug-reporting) for bug reporting to a select number of security researchers. The bounty program was announced during Apple's [presentation](https://www.blackhat.com/docs/us-16/materials/us-16-Krstic.pdf) at [BlackHat](https://www.blackhat.com/us-16/briefings.html#behind-the-scenes-of-ios-security) 2016.

Web Extensions in Safari have an additional option to use native code in Safari's sandbox environment, in addition to Web Extension APIs. Web Extensions in Safari are also distributed through Apple App Store. App Store submission comes with the added benefit of Web Extension code being audited by Apple. On the other hand App Store submission comes at a steep cost. Yearly [developer subscription](https://developer.apple.com/support/compare-memberships) fee costs 100 USD (in contrast to Chrome's 5 USD fee and Firefox's free submission). The high cost is prohibitive for the majority of open-source developers. As a result, Safari has very few extensions to choose from. However, keep the high cost in mind when installing extensions. It is expected that most Web Extensions will have some way of monetizing usage to cover development costs. Avoid Web Extensions without open-source code available for review.

Safari syncs user preferences and passwords with [iCloud Keychain](https://support.apple.com/HT202303). Viewing a saved password requires authentication with the current device account password or another configured authentication method.

Safari implements new web features more slowly than Chrome or Firefox, but security patches are delivered promptly through system updates.

See also [el1t/uBlock-Safari](https://github.com/el1t/uBlock-Safari/wiki/Disable-hyperlink-auditing-beacon) to disable hyperlink auditing beacons.

## Web browser privacy

Web browsers reveal information in several ways, for example through the [Navigator](https://developer.mozilla.org/docs/Web/API/Navigator) interface, which may include information such as the browser version, operating system, site permissions, and the device battery level. Many websites also use [canvas fingerprinting](https://en.wikipedia.org/wiki/Canvas_fingerprinting) to uniquely identify users across sessions.

For more information about security-conscious browsing and what data is sent by the browser, see [HowTo: Privacy & Security Conscious Browsing](https://gist.github.com/atcuno/3425484ac5cce5298932), [browserleaks.com](https://browserleaks.com/), [Am I Unique?](https://amiunique.org/fingerprint) and [EFF Cover Your Tracks](https://coveryourtracks.eff.org/) resources.

To reduce cross-site tracking, block [third-party cookies](https://en.wikipedia.org/wiki/Third-party_cookies).

Also be aware of [WebRTC](https://en.wikipedia.org/wiki/WebRTC#Concerns), which may reveal local or public (if connected to a VPN) IP address(es). In Firefox and Chrome/Chromium, this feature can be disabled with [uBlock Origin](https://github.com/gorhill/uBlock/wiki/Prevent-WebRTC-from-leaking-local-IP-address). [Lockdown mode](#lockdown-mode) also [disables WebRTC](https://www.sevarg.net/2022/07/20/ios16-lockdown-mode-browser-analysis) in Safari.

# Tor

[Tor](https://en.wikipedia.org/wiki/Tor_(network)) is an anonymity network that can provide additional privacy while browsing. Tor Browser is a modified Firefox-based browser configured to use the Tor network.

Download Tor Browser from [Tor Project](https://www.torproject.org/download/), both `dmg` and `asc` files for [verification](https://support.torproject.org/tor-browser/getting-started/verifying-tor-browser/):

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

Make sure `Good signature from "Tor Browser Developers (signing key) <torbrowser@torproject.org>"` appears in the output. The warning is expected, as the key has not been personally verified and added to a trusted keyring.

See [How can I verify Tor Browser's signature?](https://support.torproject.org/tbb/how-to-verify-signature/) for more information.

To finish installing Tor Browser, open the disk image and drag it to the Applications folder, or use the commands:

```bash
hdiutil mount tor-browser-macos-15.0.17.dmg
cp -r /Volumes/Tor\ Browser/Tor\ Browser.app/ ~/Applications/
```

Verify the application was signed by The Tor Project's Apple Developer ID `MADPSAYN6T` using the `spctl -a -v` or `pkgutil --check-signature` commands:

```console
$ spctl -a -vv ~/Applications/Tor\ Browser.app
/Users/user1/Applications/Tor Browser.app: accepted
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
Executable=/Users/user1/Applications/Tor Browser.app/Contents/MacOS/firefox
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
Executable=/Users/user1/Applications/Tor Browser.app/Contents/MacOS/firefox

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

The Tor network provides [anonymity](https://www.privateinternetaccess.com/blog/2013/10/how-does-privacy-differ-from-anonymity-and-why-are-both-important/), which is not necessarily the same as privacy. The network does not defend against a global observer capable of traffic analysis and correlation. See also [Seeking Anonymity in an Internet Panopticon](https://bford.info/pub/net/panopticon-cacm.pdf) and [Traffic Correlation on Tor by Realistic Adversaries](https://www.ohmygodel.com/publications/usersrouted-ccs13.pdf).

See [Tor Protocol Specification](https://spec.torproject.org/tor-spec/) for more information.

Also see [Invisible Internet Project (I2P)](https://geti2p.net/en/about/intro) and its [Tor comparison](https://geti2p.net/en/comparison/tor).

# VPN

Choose a VPN provider or self-hosted setup with a documented, modern protocol and well-audited clients. Avoid obsolete protocols such as [PPTP](https://en.wikipedia.org/wiki/Point-to-Point_Tunneling_Protocol#Security) in favor of [OpenVPN](https://en.wikipedia.org/wiki/OpenVPN) or [WireGuard](https://www.wireguard.com/) [on a Linux VM](https://github.com/mrash/Wireguard-macOS-LinuxVM) or via a set of [cross platform tools](https://www.wireguard.com/xplatform/).

Some VPN clients may send traffic over the next available network interface when the connection is interrupted or disconnected. See [scy/8122924](https://gist.github.com/scy/8122924) for an example on how to allow traffic only over VPN.

See guides to set up an [IPsec](https://en.wikipedia.org/wiki/Ipsec) VPN on a virtual machine ([hwdsl2/setup-ipsec-vpn](https://github.com/hwdsl2/setup-ipsec-vpn)) or a Docker container ([hwdsl2/docker-ipsec-vpn-server](https://github.com/hwdsl2/docker-ipsec-vpn-server)).

It may be worthwhile to consider the geographical location of the VPN provider. See further discussion in [issue 114](https://github.com/drduh/macOS-Security-and-Privacy-Guide/issues/114).

Also see this [technical overview](https://blog.timac.org/2018/0717-macos-vpn-architecture/) of the macOS built-in VPN L2TP/IPsec and [IKEv2](https://en.wikipedia.org/wiki/IKEv2) client.

# PGP/GPG

PGP is a standard for encrypting and signing data, especially email. It can protect message content between correspondents who correctly exchange and verify keys, but it does not protect metadata such as email recipients and subject lines.

GPG (GNU Privacy Guard) is a GPL-licensed, open-source program compliant with the PGP standard.

GPG is used to verify signatures of software you download and install, as well as [symmetrically](https://en.wikipedia.org/wiki/Symmetric-key_algorithm) or [asymmetrically](https://en.wikipedia.org/wiki/Public-key_cryptography) encrypt files and text.

Install from Homebrew with `brew install gnupg` or using [GPG Suite](https://gpgtools.org/).

Download [gpg.conf](https://github.com/drduh/YubiKey-Guide/blob/main/config/gpg.conf) to use recommended settings:

```bash
curl -o ~/.gnupg/gpg.conf \
  https://raw.githubusercontent.com/drduh/YubiKey-Guide/main/config/gpg.conf
```

See [drduh/YubiKey-Guide](https://github.com/drduh/YubiKey-Guide) to generate and manage credentials.

# Email

Email is not designed to provide strong privacy by default: message content may be retained by service providers, copied to recipients' mailboxes, forwarded, or exposed through account compromise. Metadata (including recipient, subject, timestamps, and mail server information) generally remains visible even when message content is encrypted.

## Thunderbird

[Thunderbird](https://www.thunderbird.net/) is a free and open-source email client with standard [IMAP](https://en.wikipedia.org/wiki/Internet_Message_Access_Protocol), [POP](https://en.wikipedia.org/wiki/Post_Office_Protocol), [CalDAV](https://en.wikipedia.org/wiki/CalDAV), and [CardDAV](https://en.wikipedia.org/wiki/CardDAV) support. It is a suitable choice for accessing and retaining mail locally rather than depend exclusively on a provider's remote server.

Thunderbird includes support for [OpenPGP](https://support.mozilla.org/kb/openpgp-thunderbird-howto-and-faq) email encryption, which can protect message content and provide cryptographic [signatures](https://www.gnupg.org/gph/en/manual/x135.html). Always verify public-key fingerprints through an independent channel before relying on a key for sensitive communication.

The [archived messages feature](https://support.mozilla.org/kb/archived-messages) can move messages out of remote mail servers to a **Local Folder**, improving privacy.

# Messengers

## XMPP

[XMPP](https://en.wikipedia.org/wiki/XMPP) is an [open protocol](https://xmpp.org/extensions/) developed by the [IETF](https://www.ietf.org/) that supports cross-platform, federated messaging. There are many [client options](https://xmpp.org/getting-started/). Consider using one of the browser-based clients to take advantage of the browser's sandbox.

Depending on the provider, you might not need anything other than a username and password to set up an account.

XMPP is not end-to-end encrypted (E2EE) by default; use [OMEMO](https://omemo.top/) with a compatible client.

## Signal

[Signal](https://signal.org/) is a popular E2EE messenger whose [double-ratchet](https://signal.org/docs/specifications/doubleratchet/) protocol is used by many other applications including WhatsApp, Google Messages, and Facebook Messenger.

To use the Signal desktop app, Signal must first be installed on a phone.

## iMessage

[iMessage](https://en.wikipedia.org/wiki/IMessage) is Apple's first-party messenger. It requires an [Apple Account](#apple-account) to use.

Enable [Contact Key Verification](https://support.apple.com/118246) and verify contacts.

iMessage can be used with either a [phone number or an email](https://support.apple.com/108758#help).

> [!WARNING]
> By default, iCloud backup is enabled, which stores copies of message encryption keys on [Apple's servers](https://support.apple.com/102651) without E2EE. Either [disable iCloud backup](https://support.apple.com/guide/icloud/view-and-manage-backups-mm122d3ef202/1.0/icloud/1.0) or enable [Advanced Data Protection](https://support.apple.com/guide/security/advanced-data-protection-for-icloud-sec973254c5f) to prevent this. Remind messaging recipients to do the same.

# Viruses and malware

See [Methods of malware persistence on Mac OS X](https://www.virusbtn.com/pdf/conference/vb2014/VB2014-Wardle.pdf) and [Malware Persistence on OS X Yosemite](https://www.rsaconference.com/events/us15/agenda/sessions/1591/malware-persistence-on-os-x-yosemite) to learn how common macOS malware persists.

For examples of advanced macOS malware capabilities, see the [Hacking Team material](https://www.schneier.com/blog/archives/2015/07/hacking_team_is.html). For further analysis, see [root installation for MacOS](https://github.com/hackedteam/vector-macos-root), [support driver for Mac Agent](https://github.com/hackedteam/driver-macos) and [RCS Agent for Mac](https://github.com/hackedteam/core-macos).

Also see [A Brief Analysis of an RCS Implant Installer](https://objective-see.com/blog/blog_0x0D.html) and [reverse.put.as](https://reverse.put.as/2016/02/29/the-italian-morons-are-back-what-are-they-up-to-this-time/).

## Downloading Software

Applications from the App Store or [notarized by Apple](https://support.apple.com/guide/security/app-code-signing-process-sec3ad8e6e53/web) may reduce malware risk, but neither process guarantees safety. Apple performs automated checks on notarized apps, and App Store apps [undergo review](https://developer.apple.com/app-store/review/guidelines/). Otherwise, obtain software from sources identified by the developer as official, and verify the website or command-line download uses HTTPS.

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

**Activity Monitor** can also indicate whether it is enabled with the "Sandbox" column displayed:

```bash
defaults write com.apple.ActivityMonitor "UserColumnsPerTab v6.0" \
  -dict-add 0 '(Command, CPUUsage, CPUTime, Threads, IdleWakeUps, Architecture, GPUUsage, GPUTime, PID, UID, Sandbox, restricted)'
```

App Store software is required to use App Sandbox. Applications such as Google Chrome use their own [sandbox](https://chromium.googlesource.com/chromium/src/+/HEAD/docs/design/sandbox.md) and might not use App Sandbox.

> [!NOTE]
> Sandboxing limits an application's default access, but entitlements and user-granted permissions can expand access.

## Hardened Runtime

Check if a program uses the [Hardened Runtime](https://developer.apple.com/documentation/security/hardened_runtime) before running it using the command:

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

See [Sophail: Applied attacks against Antivirus](https://lock.cmpxchg8b.com/sophailv2.pdf), [Analysis and Exploitation of an ESET Vulnerability](https://googleprojectzero.blogspot.ro/2015/06/analysis-and-exploitation-of-eset.html), [Popular Security Software Came Under Relentless NSA and GCHQ Attacks](https://theintercept.com/2015/06/22/nsa-gchq-targeted-kaspersky/), and [How Israel Caught Russian Hackers Scouring the World for U.S. Secrets](https://www.nytimes.com/2017/10/10/technology/kaspersky-lab-israel-russia-hacking.html).

## Gatekeeper

[Gatekeeper](https://support.apple.com/guide/security/gatekeeper-and-runtime-protection-sec5599b66df/web) verifies software notarization and provenance.

Gatekeeper warns when opening an application without notarization. It can be bypassed by selecting the application listed in **System Settings** > **Privacy & Security** after a failed attempt.

# System Integrity Protection

To verify System Integrity Protection is enabled, use the command `csrutil status`, which should return: `System Integrity Protection status: enabled.` Otherwise, [enable SIP](https://developer.apple.com/documentation/security/disabling_and_enabling_system_integrity_protection) using [Recovery Mode](https://support.apple.com/102518).

# Metadata and artifacts

macOS attaches metadata ([APFS extended attributes](https://en.wikipedia.org/wiki/Extended_file_attributes#macOS)) to files.

Metadata attributes can be viewed and removed with the `mdls` and `xattr` commands.

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

macOS stores Wi-Fi connection metadata (including credentials) in NVRAM. To clear it, use the commands:

```bash
sudo nvram -d 36C28AB5-6566-4C50-9EBD-CBB920F83843:current-network
sudo nvram -d 36C28AB5-6566-4C50-9EBD-CBB920F83843:preferred-networks
sudo nvram -d 36C28AB5-6566-4C50-9EBD-CBB920F83843:preferred-count
```

macOS may collect spelling and language suggestsions. To list them and prevent them from being created again, use the commands:

```bash
ls ~/Library/LanguageModeling/ ~/Library/Spelling/ ~/Library/Suggestions/
chmod -R 000 ~/Library/LanguageModeling ~/Library/Spelling ~/Library/Suggestions
chflags -R uchg ~/Library/LanguageModeling ~/Library/Spelling ~/Library/Suggestions
```

QuickLook application support metadata can be cleared and locked with the commands:

```bash
rm -rfv "~/Library/Application Support/Quick Look/*"
chmod -R 000 "~/Library/Application Support/Quick Look"
chflags -R uchg "~/Library/Application Support/Quick Look"
```

> [!WARNING]
> Clearing or locking this directory can break core macOS applications and prevent document-version recovery.

Document revision metadata can be cleared and disabled with the commands:

```bash
sudo rm -rfv /.DocumentRevisions-V100/*
sudo chmod -R 000 /.DocumentRevisions-V100
sudo chflags -R uchg /.DocumentRevisions-V100
```

Saved application state metadata may be cleared and locked with the commands:

```bash
rm -rfv ~/Library/Saved\ Application\ State/*
rm -rfv ~/Library/Containers/<APPNAME>/Data/Library/Saved\ Application\ State
chmod -R 000 ~/Library/Saved\ Application\ State/
chmod -R 000 ~/Library/Containers/<APPNAME>/Data/Library/Saved\ Application\ State
chflags -R uchg ~/Library/Saved\ Application\ State/
chflags -R uchg ~/Library/Containers/<APPNAME>/Data/Library/Saved\ Application\ State
```

Autosave metadata can be cleared and locked with the commands:

```bash
rm -rfv "~/Library/Containers/<APP>/Data/Library/Autosave Information"
rm -rfv "~/Library/Autosave Information"
chmod -R 000 "~/Library/Containers/<APP>/Data/Library/Autosave Information"
chmod -R 000 "~/Library/Autosave Information"
chflags -R uchg "~/Library/Containers/<APP>/Data/Library/Autosave Information"
chflags -R uchg "~/Library/Autosave Information"
```

The Siri analytics database, which is created even if the Siri launch agent is disabled, can be cleared and locked with the commands:

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

# Authentication

The [Passwords](https://support.apple.com/guide/passwords/the-passwords-app-mchl901b1b95/mac) app creates [secure credentials](https://support.apple.com/guide/security/automatic-strong-passwords-secc84c811c4/web). It supports [passkeys](https://fidoalliance.org/passkeys/) - credentials which are more resilient to phishing.

[KeePassXC](https://keepassxc.org/) is an open-source, cross-platform password manager to consider. It supports strong authentication with compatible hardware tokens and a browser extension for entering credentials automatically.

Memorable passwords can be created with [Diceware](https://secure.research.vt.edu/diceware/).

Ensure online accounts have [multi-factor authentication](https://en.wikipedia.org/wiki/Multi-factor_authentication) enabled. The strongest form of multi-factor authentication is [WebAuthn](https://en.wikipedia.org/wiki/WebAuthn), followed by [TOTP](https://datatracker.ietf.org/doc/html/rfc6238)/[HOTP](https://datatracker.ietf.org/doc/html/rfc4226) (commonly implemented by authenticator apps); SMS-based codes are weakest since they rely on the service provider.

[YubiKey](https://www.yubico.com/products/) is a popular authentication token. It can also store cryptographic keys for encryption and authentication - see [drduh/YubiKey-Guide](https://github.com/drduh/YubiKey-Guide).

GnuPG can also manage passwords and other encrypted files - see [drduh/Purse](https://github.com/drduh/Purse) and [drduh/pwd.sh](https://github.com/drduh/pwd.sh).

# Backup

Encrypt files locally before backing them up to external media or online services.

Follow the [3-2-1 backup model](https://www.cisa.gov/sites/default/files/publications/data_backup_options.pdf): keep 3 copies (original and two backups); keep backups on 2 different media types; store 1 backup copy remotely.

## Time Machine

[Time Machine](https://support.apple.com/104984) is the built-in tool for handling backups on macOS. Use an external drive or network storage to create [encrypted](https://support.apple.com/guide/mac-help/keep-your-time-machine-backup-disk-secure-mh21241) backups.

## GnuPG

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

## Disk Utility

Encrypted volumes can be created using [Disk Utility](https://support.apple.com/guide/disk-utility/toc) or `hdiutil`:

```bash
hdiutil create ~/Downloads/encrypted.dmg -encryption -size 50M -volname "secretStuff"
hdiutil mount ~/Downloads/encrypted.dmg
cp -v ~/Documents/passwords.txt /Volumes/secretStuff
hdiutil eject /Volumes/secretStuff
```

## Other

[Tresorit](https://tresorit.com/) and [restic](https://restic.net/) may also be of interest.

# Wi-Fi

Wi-Fi networks continuously broadcast a **service set identifier (SSID)** which allows devices to passively scan for previously-connected networks. **Hidden** networks do not transmit an SSID and devices send a probe with the SSID to connect, which can reveal metadata. Avoid using [hidden networks](https://support.apple.com/guide/security/wi-fi-privacy-with-apple-devices-sec31e483abf/web#sec059998a98).

Set a [private Wi-Fi address](https://support.apple.com/guide/mac-help/use-a-private-wi-fi-address-on-mac-mchlb1cb3eb4/mac) to reduce network tracking.

Set wireless network security to [WPA3](https://en.wikipedia.org/wiki/WPA3#WPA3). Follow [Apple guidance](https://support.apple.com/102766) to set recommended settings for routers and access points.

# SSH

For outgoing SSH connections, use hardware or password-protected keys, [set up](http://nerderati.com/2011/03/17/simplify-your-life-with-an-ssh-config-file/) remote hosts and consider [hashing](http://nms.csail.mit.edu/projects/ssh/) them for added privacy. See [drduh/config/ssh_config](https://github.com/drduh/config/blob/main/ssh_config) for recommended client options.

An SSH tunnel can securely route traffic through another computer, similar to a VPN.

To use Privoxy running on a remote host on port 8118:

```bash
ssh -C -L 5555:127.0.0.1:8118 you@remote-host.tld
sudo networksetup -setwebproxy "Wi-Fi" 127.0.0.1 5555
sudo networksetup -setsecurewebproxy "Wi-Fi" 127.0.0.1 5555
```

Or to use an SSH connection as a [SOCKS proxy](https://www.mikeash.com/ssh_socks.html):

```bash
ssh -NCD 3000 you@remote-host.tld
```

By default, macOS does not have [Remote Login](https://support.apple.com/guide/mac-help/allow-a-remote-computer-to-access-your-mac-mchlp1066/mac) (SSH server) enabled.

To enable SSH and allow incoming connections, use **System Settings** > **General** > **Sharing** or the command:

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

To protect against physical theft during use, use an anti-forensic tool such as [buskill/buskill-app](https://github.com/buskill/buskill-app) or [Lennolium/swiftGuard](https://github.com/Lennolium/swiftGuard) (updated usbkill, with graphical user interface). All respond to USB events and can immediately shut the computer down if the device is physically separated or an unauthorized device is connected.

Consider purchasing a privacy screen/filter for use in public.

[Nail polish](https://trmm.net/Glitter) and tamper-evidence seals can be applied to components to detect tampering.

# Monitoring

## Logs

Monitor system logs with [Console](https://support.apple.com/guide/console/toc) or the `/usr/bin/log stream` command.

To show log entries generated by the `audioaccessoryd` process during the last hour:

```bash
/usr/bin/log show \
  --last 1h \
  --predicate 'process == "audioaccessoryd"' \
  --style compact
```

## DTrace

[System Integrity Protection](https://github.com/drduh/macOS-Security-and-Privacy-Guide#system-integrity-protection) interferes with DTrace, so it is not possible to use it in recent macOS versions without disabling SIP.

- `iosnoop` monitors disk I/O
- `opensnoop` monitors file opens
- `execsnoop` monitors processes
- `errinfo` monitors failed system calls
- `dtruss` monitors all system calls

See `man -k dtrace` for more information.

## Processes

List running processes with [Activity Monitor](https://support.apple.com/guide/activity-monitor/toc) or the `ps -ef` command.

## Network

List open network connections:

```bash
sudo lsof -Pni
```

List the contents of various network-related data structures:

```bash
sudo netstat -atln
```

[Wireshark](https://www.wireshark.org/) can be used from the command line with `tshark`.

Monitor DNS:

```bash
/Applications/Wireshark.app/Contents/MacOS/tshark -i en0 \
  -Y "dns.flags.response == 1" -Tfields \
  -e frame.time_delta \
  -e dns.qry.name \
  -e dns.a \
  -Eseparator=,
```

Monitor HTTP:

```bash
/Applications/Wireshark.app/Contents/MacOS/tshark -i en0 \
  -Y "http.request or http.response" -Tfields \
  -e ip.dst \
  -e http.request.full_uri \
  -e http.request.method \
  -e http.response.code \
  -e http.response.phrase \
  -Eseparator=/s
```

Monitor x509/TLS certificates:

```bash
/Applications/Wireshark.app/Contents/MacOS/tshark -i en0 \
  -Y "ssl.handshake.certificate" -Tfields \
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

In Finder, locate and select any .sh file, right-click on it and select Get Info or press <kbd>Command</kbd> + <kbd>I</kbd>. In the "Open with" section, select TextEdit from the dropdown menu. If it is not listed, select "Other..." and Applications > TextEdit.app. Select "Change All..." and confirm by selecting Continue.

From then on, double-clicking any .sh file will open it in TextEdit instead of Terminal.

## Screensaver

Set the screen to lock as soon as the screensaver starts:

```bash
defaults write com.apple.screensaver askForPassword -int 1
defaults write com.apple.screensaver askForPasswordDelay -int 0
```

## Finder options

Show hidden files and the Library folder in Finder:

```bash
defaults write com.apple.finder AppleShowAllFiles -bool true
chflags nohidden ~/Library
```

Show all filename extensions:

```bash
defaults write NSGlobalDomain AppleShowAllExtensions -bool true
```

Do not default to saving documents to iCloud:

```bash
defaults write NSGlobalDomain NSDocumentSaveNewDocumentsToCloud -bool false
```

## umask

Set a [custom umask](https://support.apple.com/101914):

```bash
sudo launchctl config user umask 077
```

Reboot, then create a file/directory and verify permissions (macOS default allows 'group/other' read access):

```console
$ ls -ld umask*
drwx------@ 2 user1 staff  64 Jul 26 12:00 umask.dir
-rw-------@ 1 user1 staff  32 Jul 26 12:00 umask.txt
```

## Keyboard entry

Enable [secure keyboard entry](https://support.apple.com/guide/terminal/use-secure-keyboard-entry-trml109) in Terminal (this may interfere with applications such as [TextExpander](https://smilesoftware.com/textexpander/secure-input)).

## Networking

Disable [Bonjour multicast advertisements](https://www.tenable.com/audits/items/CIS_Apple_macOS_10.13_v1.1.0_Level_2.audit:d9dcee7e4d2b8d2ee54f437158992d88) (this also disables AirPlay and AirPrint features):

```bash
sudo defaults write /Library/Preferences/com.apple.mDNSResponder NoMulticastAdvertisements -bool YES
```

[Disable Handoff](https://support.apple.com/guide/mac-help/change-airdrop-handoff-settings-mchl6a407f99) and [Bluetooth](https://support.apple.com/guide/mac-help/turn-bluetooth-on-or-off-blth1008) features.

## Sudoers

macOS comes with this line in `/etc/sudoers`:

```bash
Defaults env_keep += "HOME MAIL"
```

This prevents sudo from changing HOME when privileges are elevated. As a result, programs run with sudo may use configuration files from the invoking user's home directory. Consider removing `HOME` from `env_keep` unless this behavior is specifically required.

To retain the convenience of the root user having a non-root user's home directory, append an export line to `/var/root/.zshrc`, e.g.:

```bash
export HOME=/Users/user1
```

# Related software

Software | Category | Description
:-: | :-: | :-
[lynis](https://github.com/CISOfy/lynis) | Audit scanner | Cross-platform security-auditing tool that checks system configuration and suggests hardening improvements.
[zentral](https://github.com/zentralopensource/zentral) | Monitoring & configuration platform | Fleet-management server for macOS endpoints; collects inventory, events, audits, and osquery results. Best suited to managed environments.
[osquery](https://github.com/osquery/osquery) | Monitoring engine | Exposes operating-system state as SQL tables, enabling repeatable checks of processes, users, launch items, network connections, and more.
[pareto-mac](https://github.com/paretoSecurity/pareto-mac) | Audit scanner | Menu-bar application that checks a Mac against common baseline security recommendations.

# Additional resources

- [Apple Open Source](https://opensource.apple.com/)
- [iCloud security and privacy overview](https://support.apple.com/102651)
- [EFF Surveillance Self-Defense Guide](https://ssd.eff.org/)
- [Reverse Engineering macOS blog](https://reverse.put.as/)
- [Reverse Engineering Resources](http://samdmarshall.com/re.html)
- [Malwarebytes Blog](https://www.malwarebytes.com/blog)
- [Objective-See's Blog](https://objective-see.com/blog.html)
- [CIS Benchmarks](https://www.cisecurity.org/benchmark/apple_os/)
- [iOS, The Future Of macOS, Freedom, Security And Privacy In An Increasingly Hostile Global Environment](https://gist.github.com/iosecure/357e724811fe04167332ef54e736670d)
