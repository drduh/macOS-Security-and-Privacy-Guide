This guide is a collection of techniques for improving the security and privacy of [Apple silicon](https://support.apple.com/116943) Mac computers running a [currently supported](https://support.apple.com/HT201222) version of macOS. **Using Macs with Intel CPUs leaves you open to [security vulnerabilities](https://github.com/axi0mX/ipwndfu?tab%253Dreadme-ov-file#checkm8) on the hardware level that Apple can't patch**. Apple silicon Macs are the minimum recommendation but as a general rule, newer chips are always more secure.

This guide is targeted to power users who wish to adopt enterprise-standard security, but is also suitable for novice users with an interest in improving their privacy and security on a Mac.

If you're securing computers for an organization, use the [official NIST guidelines for macOS](https://github.com/usnistgov/macos_security).

A system is only as secure as its administrator is capable of making it. There is no one single technology, software, nor technique to guarantee perfect computer security; a modern operating system and computer is very complex, and requires numerous incremental changes to meaningfully improve one's security and privacy posture.

This guide is provided on an 'as is' basis without any warranties of any kind. Only **you** are responsible if you break anything or get in any sort of trouble by following this guide.

To suggest an improvement, send a pull request or [open an issue](https://github.com/drduh/macOS-Security-and-Privacy-Guide/issues).

- [Basics](#basics)
- [Threat modeling](#threat-modeling)
   * [Identify assets](#identify-assets)
   * [Identify adversaries](#identify-adversaries)
   * [Identify capabilities](#identify-capabilities)
   * [Identify mitigations](#identify-mitigations)
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
   * [Third party firewalls](#third-party-firewalls)
   * [Kernel level packet filtering](#kernel-level-packet-filtering)
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
   * [Other browsers](#other-browsers)
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
   * [OpenBSM audit](#openbsm-audit)
   * [DTrace](#dtrace)
   * [Execution](#execution)
   * [Network](#network)
- [Binary authorization](#binary-authorization)
- [Miscellaneous](#miscellaneous)
- [Related software](#related-software)
- [Additional resources](#additional-resources)

# Basics

General security best practices apply:

- Create a [threat model](#threat-modeling)
  * What are you trying to protect and from whom? Is your adversary a three letter agency, a nosy eavesdropper on the network, or a determined [APT](https://en.wikipedia.org/wiki/Advanced_persistent_threat) orchestrating a campaign against you?
  * Recognize threats and how to reduce attack surface against them.

- Keep the system and software up to date
  * Patch the operating system and all installed software regularly.
  * macOS system updates can be completed in the [settings](https://support.apple.com/guide/mac-help/keep-your-mac-up-to-date-mchlpx1065) and set to automatically install. You can also use the `softwareupdate` command-line utility - neither requires registering an Apple account.
  * Subscribe to announcement mailing lists like [Apple security-announce](https://lists.apple.com/mailman/listinfo/security-announce).

- Encrypt sensitive data
  * In addition to [FileVault](https://support.apple.com/guide/mac-help/protect-data-on-your-mac-with-filevault-mh11785) volume encryption, consider using the [built-in password manager](https://support.apple.com/105115) to protect passwords and other sensitive data.

- Assure data availability
  * Create [regular backups](https://support.apple.com/104984) of your data and be ready to [restore from a backup](https://support.apple.com/102551) in case of compromise.
  * [Encrypt locally](https://support.apple.com/guide/mac-help/keep-your-time-machine-backup-disk-secure-mh21241) before copying backups to unencrypted external media or the "cloud"; alternatively, enable [end-to-end encryption](https://support.apple.com/guide/security/advanced-data-protection-for-icloud-sec973254c5f) if your cloud provider supports it.
  * Verify backups by accessing them regularly.

- Click carefully
  * Ultimately, the security of a system depends on the capabilities of its administrator.
  * Care should be taken when installing new software; only install from official sources that the developers indicate on their official website/github/etc.

# Threat modeling

The first and most important step for security and privacy is to create a [threat model](https://www.owasp.org/index.php/Application_Threat_Modeling). You need to understand your adversaries in order to defend against them. Each person will have their own needs so everyone's threat model will be different. Threat models tend to evolve over time as our situation changes, so be sure to periodically reassess your threat model.

## Identify assets

This is probably a lot of things: your phone, your laptop, passwords stored on your devices, internet browsing history, etc. Make a list starting with the most important assets to protect. You can put them in categories based on how important they are: public, sensitive, or secret.

## Identify adversaries

Define whom you are defending against. Start by defining the motivation they might have to attack your assets. [Financial gain](https://www.verizon.com/business/resources/reports/dbir/) is a big motivator for many attackers, for example.

## Identify capabilities

In order to counter your adversaries, you'll need to understand what they're capable of and what they're not capable of. Rank adversaries from totally unsophisticated to very advanced. For example, a common thief is not very sophisticated; they will likely be stopped by basic things like simply having a password and drive encryption on your device. A very advanced adversary like a state actor might require fully turning off your device when not in use to clear the keys from RAM and a long diceware password.

## Identify mitigations

Now is when you decide the best way to counter each threat. You might avoid writing passwords down on paper so your roommate can't find them or you might encrypt the drive on your computer so a thief can't get data from it. It's important to balance security and usability; every mitigation should counter some capability of your adversaries, otherwise you might be making your life inconvenient for little to no gain. If you can't think of any more capabilities your adversaries might have and you've implemented mitigations for them all, your work is done.

Here's an example of the type of table you should make for each asset you want to protect:

Adversary | Motivation | Capabilities | Mitigation
-|-|-|-
Roommate | See private chats or browsing history | Close proximity; can see screen or watch type in password | Use biometrics, use privacy screen, keep phone locked when not using it
Thief | Unlock phone and steal personal info and drain bank accounts, sell phone for money | Shoulder surf to see password, steal device when not looking while it's logged in | Keep phone in sight or on person at all times, keep locked when not in use, use biometrics to avoid typing password in public, use Find My or similar service to track/remotely disable stolen device
Criminal | Financial | Social engineering, readily-available malware, password reuse, exploiting vulnerabilities | Use sandboxing, enable security features in OS, keep OS and all software updated and turn on automatic updates
Corporation | User data marketing | Telemetry and behavioral data collection | Block network connections, reset unique identifiers, avoid adding payment data
Nation State/APT | Targeted surveillance | Passive surveillance of internet infrastructure, advanced computers for cracking encryption/analysis of packets | Use open source e2ee, use strong diceware passwords for devices, use hardware with secure element for secure encryption, shut down devices when not using them, software tripwire/honeypot/[canary tokens](https://canarytokens.org/)

Read more about threat modeling [here](https://www.netmeister.org/blog/threat-model-101.html).

# Hardware

macOS is most secure running on [Apple hardware](https://support.apple.com/guide/security/hardware-security-overview-secf020d1074/1/web/1) with Apple silicon. The newer the Mac, the better. Avoid hackintoshes and Macs that don't support the latest macOS, as Apple doesn't [patch all vulnerabilities](https://support.apple.com/guide/deployment/about-software-updates-depc4c80847a) in versions that aren't the most recent one.

When you purchase your Mac, you might want to avoid it being linked back to you. Depending on your threat model, you should pay for it in cash in person rather than ordering online or purchasing with a credit/debit card, that way no identifying information can be linked back to your purchase.

If you want to use a wireless keyboard, mouse, headphones or other accessory, the most secure option is Apple ones since they will automatically be updated by your system. They also support the latest [Bluetooth features](https://support.apple.com/guide/security/bluetooth-security-sec82597d97e/web) like BLE Privacy which randomizes your Bluetooth hardware address to prevent tracking. With third party accessories, this isn't a guarantee.

# Installing macOS

There are several ways to [install macOS](https://support.apple.com/102662). Choose your preferred method from the available options.

 **You should install the latest version of macOS that is compatible with your Mac**. More recent versions have security patches and other improvements that older versions lack.

## System activation

As part of Apple's [theft prevention system](https://support.apple.com/102541), Apple silicon Macs will need to activate with Apple's servers every time you reinstall macOS to check against the database of stolen or activation-locked Macs.

You can read about exactly how this process works [here](https://support.apple.com/guide/security/localpolicy-signing-key-creation-management-sec1f90fbad1).

## Apple Account

Creating an Apple Account is not required to use macOS. Making an Apple Account requires a phone number and it will by default sync a [lot of data](https://www.apple.com/legal/privacy/data/en/apple-id/) to iCloud, Apple's cloud storage service. You can [disable](https://support.apple.com/102651) the syncing later if you want or enable [end-to-end encryption](https://support.apple.com/guide/security/advanced-data-protection-for-icloud-sec973254c5f/web) for your iCloud data.

You can [control the data](https://support.apple.com/102283) associated with your Apple Account or completely delete it.

An Apple Account is required in order to access the App Store and use most Apple services like iCloud, Apple Music, etc.

## App Store

The Mac App Store is a [curated](https://developer.apple.com/app-store/review/guidelines) repository of software that is required to utilize the [App Sandbox](https://developer.apple.com/documentation/security/app_sandbox/protecting_user_data_with_app_sandbox) and [Hardened Runtime](https://developer.apple.com/documentation/security/hardened_runtime), as well as offering automatic updates that integrate with your system.

The App Store offers the greatest security guarantees for software on macOS, but it requires you to log in with an Apple Account and Apple will be able to link your Apple Account to your downloaded apps.

## Virtualization

You can easily run macOS natively in a virtual machine using [UTM](https://mac.getutm.app). It's free from their site but if you buy it from the App Store, you'll get automatic updates.

Follow their [documentation](https://docs.getutm.app/guest-support/macos) to install a macOS VM with just a few clicks.

Another option is [VMware Fusion](https://www.vmware.com/products/fusion.html). You can read their [documentation](https://docs.vmware.com/en/VMware-Fusion/13/com.vmware.fusion.using.doc/GUID-474FC78E-4E77-42B7-A1C6-12C2F378C5B9.html) to see how to install a macOS VM.

# First boot

When macOS first starts, you'll be greeted by **Setup Assistant**.

When creating the first account, use a [strong password](https://www.eff.org/dice) without a hint.

If you enter your real name at the account setup process, be aware that your computer's name and local hostname will comprise that name (e.g., *John Appleseed's MacBook*) and thus will appear on local networks and in various preference files.

Both should be verified and updated as needed in **System Settings > About** or with the following commands after installation:

```console
sudo scutil --set ComputerName MacBook
sudo scutil --set LocalHostName MacBook
```

# Admin and user accounts

The first user account is always an admin account. Admin accounts are members of the admin group and have access to `sudo`, which allows them to usurp other accounts, in particular root, and gives them effective control over the system. Any program that the admin executes can potentially obtain the same access, making this a security risk.

Utilities like `sudo` have [weaknesses that can be exploited](https://bogner.sh/2014/03/another-mac-os-x-sudo-password-bypass/) by concurrently running programs.

It is considered a best practice by [Apple](https://help.apple.com/machelp/mac/10.12/index.html#/mh11389) to use a separate standard account for day-to-day work and use the admin account for installations and system configuration.

It is not strictly required to ever log into the admin account via the macOS login screen. When a Terminal command requires administrator privileges, the system will prompt for authentication and Terminal then continues using those privileges. To that end, Apple provides some [recommendations](https://support.apple.com/HT203998) for hiding the admin account and its home directory. This can be an elegant solution to avoid having a visible 'ghost' account.

## Caveats

* Only administrators can install applications in `/Applications` (local directory). Finder and Installer will prompt a standard user with an authentication dialog. Many applications can be installed in `~/Applications` instead (the directory can be created). As a rule of thumb: applications that do not require admin access – or do not complain about not being installed in `/Applications` – should be installed in the user directory, the rest in the local directory. Mac App Store applications are still installed in `/Applications` and require no additional authentication.
* `sudo` is not available in shells of the standard user, which requires using `su` or `login` to enter a shell of the admin account. This can make some maneuvers trickier and requires some basic experience with command-line interfaces.
* System Preferences and several system utilities (e.g. Wi-Fi Diagnostics) will require root privileges for full functionality. Many panels in System Preferences are locked and need to be unlocked separately by clicking on the lock icon. Some applications will simply prompt for authentication upon opening, others must be opened by an admin account directly to get access to all functions (e.g. Console).
* There are third-party applications that will not work correctly because they assume that the user account is an admin. These programs may have to be executed by logging into the admin account, or by using the `open` utility.
* See additional discussion in [issue 167](https://github.com/drduh/macOS-Security-and-Privacy-Guide/issues/167).

## Setup

Accounts can be created and managed in System Preferences. On settled systems, it is generally easier to create a second admin account and then demote the first account. This avoids data migration. Newly installed systems can also just add a standard account.

Demoting an account can be done either from the the new admin account in System Preferences – the other account must be logged out – or by executing these commands (it may not be necessary to execute both, see [issue 179](https://github.com/drduh/macOS-Security-and-Privacy-Guide/issues/179)):

```console
sudo dscl . -delete /Groups/admin GroupMembership <username>
sudo dscl . -delete /Groups/admin GroupMembers <GeneratedUID>
```

To find the **GeneratedUID** of an account:

```console
dscl . -read /Users/<username> GeneratedUID
```

See also [this post](https://superuser.com/a/395738) for more information about how macOS determines group membership.

# Firmware

You should check that firmware security settings are set to [Full Security](https://support.apple.com/guide/mac-help/mchl768f7291/mac) to prevent tampering with your OS. This is the default setting.

# FileVault

All Mac models with Apple silicon are encrypted by default. Enabling [FileVault](https://support.apple.com/guide/mac-help/mh11785/mac) makes it so that you need to enter a password in order to access the data on your drive. The EFF has a guide on generating [strong but memorable passwords](https://www.eff.org/dice).

Your FileVault password also acts as a [firmware password](https://support.apple.com/en-us/102384) that will prevent people that don't know it from booting from anything other than the designated startup disk, accessing [Recovery](https://support.apple.com/guide/mac-help/macos-recovery-a-mac-apple-silicon-mchl82829c17/15.0/mac/15.0#mchl5abfbb29), and [reviving](https://support.apple.com/en-us/108900) it with DFU mode.

FileVault will ask you to set a recovery key in case you forget your password. Keep this key stored somewhere safe. You'll have the option use your iCloud account to unlock your disk; however, anyone with access to your iCloud account will be able to unlock it as well.

# Lockdown Mode

macOS offers [Lockdown Mode](https://support.apple.com/105120), a security feature that disables several features across the OS, significantly reducing attack surface for attackers while keeping the OS usable. You can read about exactly what is disabled and decide for yourself if it is acceptable to you.

When Lockdown Mode is on, you can disable it per site in Safari on trusted sites.

# Firewall

There are several types of firewalls available for macOS.

## Application layer firewall

Built-in, basic firewall which blocks **incoming** connections only. This firewall does not have the ability to monitor, nor block **outgoing** connections.

It can be controlled by the **Firewall** tab of **Network** in **System Settings**, or with the following commands.

Enable the firewall with logging and stealth mode:

```console
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on

sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setloggingmode on

sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on
```

Computer hackers scan networks so they can attempt to identify computers to attack. You can prevent your computer from responding to some of these scans by using **stealth mode**. When stealth mode is enabled, your computer does not respond to ICMP ping requests, and does not answer to connection attempts from a closed TCP or UDP port. This makes it more difficult for attackers to find your computer.

To prevent *built-in software* as well as *code-signed, downloaded software from being whitelisted automatically*:

```console
sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setallowsigned off

sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setallowsignedapp off
```

Applications that are signed by a valid certificate authority are automatically added to the list of allowed apps, rather than prompting the user to authorize them. Apps included in macOS are signed by Apple and are allowed to receive incoming connections when this setting is enabled. For example, since iTunes is already signed by Apple, it is automatically allowed to receive incoming connections through the firewall.

If you run an unsigned app that is not listed in the firewall list, a dialog appears with options to Allow or Deny connections for the app. If you choose "Allow", macOS signs the application and automatically adds it to the firewall list. If you choose "Deny", macOS adds it to the list but denies incoming connections intended for this app.

After interacting with `socketfilterfw`, restart the process by sending a line hangup signal:

```console
sudo pkill -HUP socketfilterfw
```

## Third party firewalls

Programs such as [Little Snitch](https://www.obdev.at/products/littlesnitch/index.html), [Radio Silence](https://radiosilenceapp.com/), and [LuLu](https://objective-see.com/products/lulu.html) provide a good balance of usability and security.

These programs are capable of monitoring and blocking **incoming** and **outgoing** network connections. However, they may require the use of a closed source [system extension](https://support.apple.com/HT210999).

If the number of choices of allowing/blocking network connections is overwhelming, use **Silent Mode** with connections allowed, then periodically check the configuration to gain understanding of applications and what they are doing.

It is worth noting that these firewalls can be bypassed by programs running as **root** or through [OS vulnerabilities](https://www.blackhat.com/docs/us-15/materials/us-15-Wardle-Writing-Bad-A-Malware-For-OS-X.pdf) (pdf), but they are still worth having - just don't expect absolute protection. However, some malware actually [deletes itself](https://www.cnet.com/how-to/how-to-remove-the-flashback-malware-from-os-x/) and doesn't execute if Little Snitch, or other security software, is installed.

## Kernel level packet filtering

A highly customizable, powerful, but also most complicated firewall exists in the kernel. It can be controlled with `pfctl` and various configuration files.

pf can also be controlled with a GUI application such as [Murus](https://www.murusfirewall.com/).

There are many books and articles on the subject of pf firewall. Here's is just one example of blocking traffic by IP address.

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

Then use the following commands to manipulate the firewall:

* `sudo pfctl -e -f pf.rules` to enable the firewall and load the configuration
* `sudo pfctl -d` to disable the firewall
* `sudo pfctl -t blocklist -T add 1.2.3.4` to add an IP address to the blocklist
* `sudo pfctl -t blocklist -T show` to view the blocklist
* `sudo ifconfig pflog0 create` to create an interface for logging
* `sudo tcpdump -ni pflog0` to view filtered packets

Unless you're already familiar with packet filtering, spending too much time configuring pf is not recommended. It is also probably unnecessary if your Mac is behind a [NAT](https://www.grc.com/nat/nat.htm) on a private home network.

It is possible to use the pf firewall to block network access to entire ranges of network addresses, for example to a whole organization:

Query [Merit RADb](https://www.radb.net/) for the list of networks in use by an autonomous system, like [Facebook](https://ipinfo.io/AS32934):

```console
whois -h whois.radb.net '!gAS32934'
```

Copy and paste the list of networks returned into the blocklist command:

```console
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
IP 192.168.1.1.162771 > 157.240.2.35.80: tcp 0
```

Outgoing TCP SYN packets are blocked, so a TCP connection is not established and thus a Web site is effectively blocked at the IP layer.

See [drduh/config/scripts/pf-blocklist.sh](https://github.com/drduh/config/blob/master/scripts/pf-blocklist.sh) for more inspiration.

# Services

Services on macOS are managed by **launchd**. See [launchd.info](https://launchd.info).

You can manage and see more information about software that runs at login in [System Settings](https://support.apple.com/guide/mac-help/change-login-items-settings-mtusr003). You can see installed System, Quick Look, Finder, and other extensions in [System Settings](https://support.apple.com/guide/mac-help/change-extensions-settings-mchl8baf92fe) as well.

* Use `launchctl list` to view running user agents
* Use `sudo launchctl list` to view running system daemons
* Specify the service name to examine it, e.g. `launchctl list com.apple.Maps.mapspushd`
* Use `defaults read` to examine job plists in `/System/Library/LaunchDaemons` and `/System/Library/LaunchAgents`
* Use `man` and `strings` to find out more about what an agent/daemon does

For example, to learn what a system launch daemon or agent does, start with:

```console
defaults read /System/Library/LaunchDaemons/com.apple.apsd.plist
```

Look at the `Program` or `ProgramArguments` section to see which binary is run, in this case `apsd`. To find more information about that, look at the man page with `man apsd`

**Note** System services are protected by SIP, don't disable SIP just to tinker with system services as SIP is an integral part of security on macOS. Disabling system services could cause breakage and unstable behavior!

To view the status of services:

```console
find /var/db/com.apple.xpc.launchd/ -type f -print -exec defaults read {} \; 2>/dev/null
```

Annotated lists of launch daemons and agents, the respective program executed, and the programs' hash sums are included in this repository.

Read more about launchd and where login items can be found on [Apple's website](https://support.apple.com/guide/terminal/script-management-with-launchd-apdc6c1077b-5d5d-4d35-9c19-60f2397b2369).

# Siri Suggestions and Spotlight

Apple is moving to on-device processing for a lot of Siri functions, but some info is still sent to Apple when you use Siri Suggestions or Spotlight. You can read Apple's [Privacy Policy](https://www.apple.com/legal/privacy/data/en/siri-suggestions-search/) to see exactly what is sent and how to disable it.

# Homebrew

If your program isn't available through the App Store you can consider using [Homebrew](https://brew.sh/).

**Important!** Homebrew asks you to grant “App Management” (or “Full Disk Access”) permission to your terminal. This is a bad idea, as it would make you vulnerable to these attacks again: any non-sandboxed application can execute code with the TCC permissions of your terminal by adding a malicious command to (e.g.) ~/.zshrc. Granting “App Management” or “Full Disk Access” to your terminal should be considered the same as disabling TCC completely.

Remember to periodically run `brew upgrade` on trusted and secure networks to download and install software updates. To get information on a package before installation, run `brew info <package>` and check its formula online. You may also wish to enable [additional security options](https://github.com/drduh/macOS-Security-and-Privacy-Guide/issues/138), such as `HOMEBREW_NO_INSECURE_REDIRECT=1`

According to [Homebrew's Anonymous Analytics](https://docs.brew.sh/Analytics), Homebrew gathers anonymous analytics and reports these to a self-hosted InfluxDB instance.
To opt out of Homebrew's analytics, you can set `export HOMEBREW_NO_ANALYTICS=1` in your environment or shell rc file, or use `brew analytics off`


# DNS

## DNS profiles

macOS 11 introduced "DNS configuration profiles" to configure encrypted DNS, filter domains and use DNSSEC.

DNS profiles [can be created](https://dns.notjakob.com/) or obtained from providers such as [Quad9](https://docs.quad9.net/Setup_Guides/MacOS/Big_Sur_and_later_(Encrypted)/#download-profile), [AdGuard](https://adguard-dns.io/en/public-dns.html) and [NextDNS](https://nextdns.io/).

## Hosts file

Use the [hosts file](https://en.wikipedia.org/wiki/Hosts_(file)) to block known malware, advertising or otherwise unwanted domains.

Edit the hosts file as root, for example with `sudo vi /etc/hosts`

To block a domain by `A` record, append any one of the following lines to `/etc/hosts`:

```
0 example.com
0.0.0.0 example.com
127.0.0.1 example.com
```

**Note** IPv6 uses the `AAAA` DNS record type, rather than `A` record type, so you may also want to block those connections by *also* including `::1 example.com` entries, like shown [here](https://someonewhocares.org/hosts/ipv6/).

There are many lists of domains available online which you can paste in, just make sure each line starts with `0`, `0.0.0.0`, `127.0.0.1`, and the line `127.0.0.1 localhost` is included.

Here are some popular and useful hosts lists:

* [Sinfonietta/hostfiles](https://github.com/Sinfonietta/hostfiles)
* [StevenBlack/hosts](https://github.com/StevenBlack/hosts)
* [someonewhocares.org](https://someonewhocares.org/hosts/zero/hosts)

Append a list of hosts with `tee`:

```console
curl https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts | sudo tee -a /etc/hosts
```

If you're using a firewall like [Little Snitch](#third-party-firewalls), you could use the [StevenBlack/hosts](https://github.com/StevenBlack/hosts) importing the rules from [leohidalgo/little-snitch---rule-groups](https://github.com/leohidalgo/little-snitch---rule-groups) repository, these rules are updated every 12 hours from the [StevenBlack/hosts](https://github.com/StevenBlack/hosts) repository.

## DNSCrypt

To encrypt DNS traffic, consider using [DNSCrypt/dnscrypt-proxy](https://github.com/DNSCrypt/dnscrypt-proxy). Used in combination with dnsmasq and DNSSEC, the integrity of DNS traffic can be significantly improved.

Install DNSCrypt from Homebrew and follow the instructions to configure and start `dnscrypt-proxy`:

```console
brew install dnscrypt-proxy
```

If using in combination with Dnsmasq, find the file `homebrew.mxcl.dnscrypt-proxy.plist` by running

```console
brew info dnscrypt-proxy
```

which will show a location like `/usr/local/etc/dnscrypt-proxy.toml`

Open it in a text editor, find the line starting with `listen_addresses =` and edit that line to use DNScrypt on a port other than 53, like 5355:

```
listen_addresses = ['127.0.0.1:5355', '[::1]:5355']
```

Start DNSCrypt:

```console
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

> By default, dnscrypt-proxy runs on localhost (127.0.0.1), port 53, balancing traffic across a set of resolvers. If you would like to change these settings, you will have to edit the configuration file: $HOMEBREW_PREFIX/etc/dnscrypt-proxy.toml

**Note** Applications and programs may resolve DNS using their own provided servers. If dnscrypt-proxy is used, it is possible to disable all other, non-dnscrypt DNS traffic with the following pf rules:

```shell
block drop quick on !lo0 proto udp from any to any port = 53
block drop quick on !lo0 proto tcp from any to any port = 53
```

See also [What is a DNS leak](https://dnsleaktest.com/what-is-a-dns-leak.html) and [ipv6-test.com](http://ipv6-test.com/)

## Dnsmasq

Among other features, [dnsmasq](https://www.thekelleys.org.uk/dnsmasq/doc.html) is able to cache replies, prevent upstream queries for unqualified names, and block entire top-level domains.

Use in combination with DNSCrypt to additionally encrypt DNS traffic.

If you don't wish to use DNSCrypt, you should at least use DNS [not provided](https://bcn.boulder.co.us/~neal/ietf/verisign-abuse.html) [by your ISP](https://hackercodex.com/guide/how-to-stop-isp-dns-server-hijacking/). Two popular alternatives are [Google DNS](https://developers.google.com/speed/public-dns/) and [OpenDNS](https://www.opendns.com/home-internet-security/).

**Optional** [DNSSEC](https://en.wikipedia.org/wiki/Domain_Name_System_Security_Extensions) is a set of extensions to DNS which provide to DNS clients (resolvers) origin authentication of DNS data, authenticated denial of existence, and data integrity. All answers from DNSSEC protected zones are digitally signed. The signed records are authenticated via a chain of trust, starting with a set of verified public keys for the DNS root-zone. The current root-zone trust anchors may be downloaded [from IANA website](https://www.iana.org/dnssec/files). There are a number of resources on DNSSEC, but probably the best one is [dnssec.net website](https://www.dnssec.net).

Install Dnsmasq:

```console
brew install dnsmasq --with-dnssec
```

Download and edit [drduh/config/dnsmasq.conf](https://github.com/drduh/config/blob/master/dnsmasq.conf) or the default configuration file.

See [drduh/config/domains](https://github.com/drduh/config/tree/master/domains) for appendable examples on blocking services by domains.

Install and start the program (sudo is required to bind to [privileged port](https://unix.stackexchange.com/questions/16564/why-are-the-first-1024-ports-restricted-to-the-root-user-only) 53):

```console
sudo brew services start dnsmasq
```

To set dnsmasq as the local DNS server, open **System Preferences** > **Network** and select the active interface, then the **DNS** tab, select **+** and add `127.0.0.1`, or use:

```console
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

**Note** Some VPN software overrides DNS settings on connect. See [issue 24](https://github.com/drduh/macOS-Security-and-Privacy-Guide/issues/24) and [drduh/config/scripts/macos-dns.sh](https://github.com/drduh/config/blob/master/scripts/macos-dns.sh).

**Optional** Test DNSSEC validation for signed zones - the reply should have `NOERROR` status and contain `ad` flag:

```console
$ dig +dnssec icann.org | head
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 47039
;; flags: qr rd ra ad; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 1
```

Test DNSSEC validation fails for zones that are signed improperly - the reply should have `SERVFAIL` status:

```console
$ dig www.dnssec-failed.org | head
;; ->>HEADER<<- opcode: QUERY, status: SERVFAIL, id: 15190
;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1
```

# Certificate authorities

macOS comes with [over 100](https://support.apple.com/103723) root authority certificates installed from corporations like Apple, Verisign, Thawte, Digicert and government agencies from China, Japan, Netherlands, U.S., and more! These Certificate Authorities (CAs) are capable of issuing TLS certificates for any domain, code signing certificates, etc. Apple [blocks these certificates](https://support.apple.com/103247#blocked) when a CA proves to be untrustworthy. They also have [strict requirements](https://www.apple.com/certificateauthority/ca_program.html) that trusted CAs have to meet.

For more information, see the [CA/Browser Forum's website](https://cabforum.org/resources/browser-os-info/).

Inspect system root certificates in **Keychain Access**, under the **System Roots** tab or by using the `security` command line tool and `/System/Library/Keychains/SystemRootCertificates.keychain` file.

You can manually disable certificate authorities through Keychain Access by marking them as **Never Trust** and closing the window:

<img width="450" alt="A certificate authority certificate" src="https://cloud.githubusercontent.com/assets/12475110/19222972/6b7aabac-8e32-11e6-8efe-5d3219575a98.png">

**Warning:** This will cause your browser to give a warning when you visit a site using certificates signed by these CAs and may cause breakage in other software. Don't distrust Apple root certificates or it will cause lots of breakage in macOS!

The risk of a [man in the middle](https://wikipedia.org/wiki/Man-in-the-middle_attack) attack in which a coerced or compromised certificate authority trusted by your system issues a fake/rogue TLS certificate is quite low, but still [possible](https://wikipedia.org/wiki/DigiNotar#Issuance_of_fraudulent_certificates).

# Privoxy

Consider using [Privoxy](https://www.privoxy.org/) as a local proxy to filter Web traffic.

Install and start privoxy using Homebrew:

```console
brew install privoxy

brew services start privoxy
```

Alternatively, a signed installation package for Privoxy is available from [their website](https://www.privoxy.org/sf-download-mirror/Macintosh%20%28OS%20X%29/) or [Sourceforge](https://sourceforge.net/projects/ijbswa/files/Macintosh%20%28OS%20X%29/). The signed package is [more secure](https://github.com/drduh/macOS-Security-and-Privacy-Guide/issues/65) than the Homebrew version and receives support from the Privoxy project.

By default, Privoxy listens on local TCP port 8118.

Set the system **HTTP** proxy for the active network interface `127.0.0.1` and `8118`:

```console
sudo networksetup -setwebproxy "Wi-Fi" 127.0.0.1 8118
```

Set the system **HTTPS** proxy:

```console
sudo networksetup -setsecurewebproxy "Wi-Fi" 127.0.0.1 8118
```

This can also be done through **System Preferences > Network > Advanced > Proxies**

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

Although most Web traffic today is encrypted, Privoxy is still useful for filtering by domain name patterns, and for upgrading insecure HTTP requests.

For example, the following rules block all traffic, except to `.net` and `github.com` and all `apple` domains:

```console
{ +block{all} }
.

{ -block }
.apple.
.github.com
.net
```

Or to just block Facebook domains, for example:

```console
{ +block{facebook} }
.facebook*.
.fb.
.fbcdn*.
.fbinfra.
.fbsbx.
.fbsv.
.fburl.
.tfbnw.
.thefacebook.
fb*.akamaihd.net
```

Wildcards are also supported.

See [drduh/config/privoxy/config](https://github.com/drduh/config/blob/master/privoxy/config) and [drduh/config/privoxy/user.action](https://github.com/drduh/config/blob/master/privoxy/user.action) for additional Privoxy examples. Privoxy does **not** need to be restarted after editing `user.action` filter rules.

To verify traffic is blocked or redirected, use curl or the Privoxy interface available at <http://p.p> in the browser:

```console
ALL_PROXY=127.0.0.1:8118 curl example.com -IL | head

HTTP/1.1 403 Request blocked by Privoxy
Content-Length: 9001
Content-Type: text/html
Cache-Control: no-cache
Pragma: no-cache

ALL_PROXY=127.0.0.1:8118 curl github.com -IL | head
HTTP/1.1 302 Local Redirect from Privoxy
Location: https://github.com/
Content-Length: 0

HTTP/1.1 200 Connection established

HTTP/2 200
server: GitHub.com
```

**Note** macOS proxy settings are not universal; apps and services may not honor system proxy settings. Ensure the application you wish to proxy is correctly configured and verify connections don't leak. Additionally, *pf* can be configured to transparently proxy traffic on certain ports.

# Browser

The Web browser likely poses the largest security and privacy risk, as its fundamental job is to download and execute untrusted code from the Internet.

An important property of modern browsers is the Same Origin Policy ([SOP](https://en.wikipedia.org/wiki/Same-origin_policy)) which prevents a malicious script on one page from obtaining access to sensitive data on another web page through the Document Object Model (DOM). If SOP is compromised, the security of the entire browser is compromised.

Many browser exploits are based on social engineering as a means of gaining persistence. Always be mindful of opening untrusted sites and especially careful when downloading new software.

Another important consideration about browser security is extensions. This is an issue affecting Firefox and [Chrome](https://courses.csail.mit.edu/6.857/2016/files/24.pdf) alike. The use of browser extensions should be limited to only critically necessary ones published by trustworthy developers.

[Mozilla Firefox](https://www.mozilla.org/firefox/new), [Google Chrome](https://www.google.com/chrome), [Safari](https://www.apple.com/safari), and [Tor Browser](https://www.torproject.org/download) are all recommended browsers for their own unique and individual purposes.

## Firefox

[Mozilla Firefox](https://www.mozilla.org/firefox/new) is a popular open source browser. Firefox replaced major parts of its infrastructure and code base under the projects [Quantum](https://wiki.mozilla.org/Quantum) and [Photon](https://wiki.mozilla.org/Firefox/Photon/Updates). Part of the Quantum project is to replace C++ code with [Rust](https://www.rust-lang.org). Rust is a systems programming language with a focus on security and thread safety. It is expected that Rust adoption will greatly improve the overall security posture of Firefox.

Firefox offers a similar security model to Chrome: it has a [bug bounty program](https://www.mozilla.org/security/bug-bounty), although it is not as lucrative. Firefox follows a four-week release cycle.

Firefox supports user-supplied configuration files. See [drduh/config/firefox.user.js](https://github.com/drduh/config/blob/master/firefox.user.js) and [arkenfox/user.js](https://github.com/arkenfox/user.js) for recommended preferences and hardening measures. Also see [NoScript](https://noscript.net), an extension which allows selective script blocking.

Firefox [focuses on user privacy](https://www.mozilla.org/firefox/privacy). It supports [tracking protection](https://developer.mozilla.org/docs/Web/Privacy/Firefox_tracking_protection) in Private Browsing mode. The tracking protection can be enabled for the default account, although it may break the browsing experience on some websites. Firefox in Strict tracking protection mode will [randomize your fingerprint](https://support.mozilla.org/kb/firefox-protection-against-fingerprinting) to foil basic tracking scripts. Firefox offers separate user [profiles](https://support.mozilla.org/kb/profile-manager-create-remove-switch-firefox-profiles). You can separate your browsing inside a profile with [Multi-Account Containers](https://support.mozilla.org/kb/containers).

Firefox only supports Web Extensions through the [Web Extension Api](https://developer.mozilla.org/docs/Mozilla/Add-ons/WebExtensions), which is very similar to Chrome. Submission of Web Extensions in Firefox is free. Web Extensions in Firefox most of the time are open source, although certain Web Extensions are proprietary.

## Chrome

[Google Chrome](https://www.google.com/chrome) is based on the open source [Chromium project](https://www.chromium.org) with certain [proprietary components](https://fossbytes.com/difference-google-chrome-vs-chromium-browser):

* Automatic updates with GoogleSoftwareUpdateDaemon
* Usage tracking and crash reporting, which can be disabled through Chrome's settings
* Media Codec support for proprietary codecs
* Chrome Web Store
* PDF viewer
* Non-optional tracking. Google Chrome installer includes a randomly generated token. The token is sent to Google after the installation completes in order to measure the success rate. The RLZ identifier stores information – in the form of encoded strings – like the source of chrome download and installation week. It doesn’t include any personal information and it’s used to measure the effectiveness of a promotional campaign. **Chrome downloaded from Google’s website doesn’t have the RLZ identifier**. The source code to decode the strings is made open by Google.

Chrome offers account sync between multiple devices. Part of the sync data includes credentials to Web sites. The data is encrypted with the account password.

Chrome's Web Store for extensions requires a [5 USD lifetime fee](https://developer.chrome.com/docs/webstore/register) in order to submit extensions. The low cost allows the development of many quality Open Source Web Extensions that do not aim to monetize through usage.

Chrome has the largest share of global usage and is the preferred target platform for the majority of developers. Major technologies are based on Chrome's Open Source components, such as [node.js](https://nodejs.org) which uses [Chrome's V8](https://developers.google.com/v8) Engine and the [Electron](https://electron.atom.io) framework, which is based on Chromium and node.js. Chrome's vast user base makes it the most attractive target for threat actors and security researchers. Despite constant attacks, Chrome has retained an impressive security track record over the years. This is not a small feat.

Chrome offers [separate profiles](https://www.chromium.org/user-experience/multi-profiles), [robust sandboxing](https://chromium.googlesource.com/chromium/src/+/HEAD/docs/design/sandbox.md), [frequent updates](https://chromereleases.googleblog.com), and carries [impressive credentials](https://www.chromium.org/Home/chromium-security/brag-sheet). In addition, Google offers a very lucrative [bounty program](https://bughunters.google.com/about/rules/5745167867576320/chrome-vulnerability-reward-program-rules) for reporting vulnerabilities, along with its own [Project Zero](https://googleprojectzero.blogspot.com/) team. This means that a large number of highly talented and motivated people are constantly auditing and securing Chrome code.

Create separate Chrome profiles to reduce XSS risk and compartmentalize cookies/identities. In each profile, either disable Javascript in Chrome settings and configure allowed origins. You should also disable the V8 Optimizer for sites where you do use Javascript to further reduce attack surface. Go to **Settings** -> **Privacy and security** -> **Security** -> **Manage v8 security** -> **Don't allow sites to use the V8 optimizer**

Read more about the benefits of disabling this [here](https://microsoftedge.github.io/edgevr/posts/Super-Duper-Secure-Mode).

You can block trackers with [uBlock Origin Lite](https://chromewebstore.google.com/detail/ublock-origin-lite/ddkjiahejlhfcafbddmgiahcphecmpfh).

Change the default search engine from Google to reduce additional tracking.

Disable [DNS prefetching](https://www.chromium.org/developers/design-documents/dns-prefetching) (see also [DNS Prefetching and Its Privacy Implications](https://www.usenix.org/legacy/event/leet10/tech/full_papers/Krishnan.pdf) (pdf)). Note that Chrome [may attempt](https://github.com/drduh/macOS-Security-and-Privacy-Guide/issues/350) to resolve DNS using Google's `8.8.8.8` and `8.8.4.4` public nameservers.

Read [Chromium Security](https://www.chromium.org/Home/chromium-security) and [Chromium Privacy](https://www.chromium.org/Home/chromium-privacy) for more information. Read [Google's privacy policy](https://policies.google.com/privacy) to understand how personal information is collected and used.

## Safari

[Safari](https://www.apple.com/safari) is the default browser on macOS. It is also the most optimized browser for reducing battery use. Safari, like Chrome, has both Open Source and proprietary components. Safari is based on the open source Web Engine [WebKit](https://webkit.org), which is ubiquitous among the macOS ecosystem. WebKit is used by Apple apps such as Mail, iTunes, iBooks, and the App Store. Chrome's [Blink](https://www.chromium.org/blink) engine is a fork of WebKit and both engines share a number of similarities.

Safari supports certain unique features that benefit user security and privacy. [Content blockers](https://webkit.org/blog/3476/content-blockers-first-look) enables the creation of content blocking rules without using Javascript. This rule based approach greatly improves memory use, security, and privacy. Safari 11 introduced [Intelligent Tracking Prevention](https://webkit.org/blog/7675/intelligent-tracking-prevention), which removes tracking data stored in Safari after a period of non-interaction by the user from the tracker's website. Safari can randomize your fingerprint to reduce tracking. Safari doesn't support certain features like WebUSB or the Battery API intentionally for security and privacy reasons. Private tabs in Safari have isolated cookies and cache that is destroyed when you close the tab. Safari also support Profiles which are equivalent to Firefox's Multi-Account Containers for separating cookies and browsing. Safari can be made significantly more secure with [lockdown mode](#lockdown-mode), which can be disabled per-site. Read more about [tracking prevention](https://webkit.org/tracking-prevention) in Safari.

Safari offers an invite-only [bounty program](https://developer.apple.com/bug-reporting) for bug reporting to a select number of security researchers. The bounty program was announced during Apple's [presentation](https://www.blackhat.com/docs/us-16/materials/us-16-Krstic.pdf) at [BlackHat](https://www.blackhat.com/us-16/briefings.html#behind-the-scenes-of-ios-security) 2016.

Web Extensions in Safari have an additional option to use native code in the Safari's sandbox environment, in addition to Web Extension APIs. Web Extensions in Safari are also distributed through Apple's App store. App store submission comes with the added benefit of Web Extension code being audited by Apple. On the other hand App store submission comes at a steep cost. Yearly [developer subscription](https://developer.apple.com/support/compare-memberships) fee costs 100 USD (in contrast to Chrome's 5 USD fee and Firefox's free submission). The high cost is prohibitive for the majority of Open Source developers. As a result, Safari has very few extensions to choose from. However, you should keep the high cost in mind when installing extensions. It is expected that most Web Extensions will have some way of monetizing usage in order to cover developer costs. Be wary of Web Extensions whose source code is not open.

Safari syncs user preferences and passwords with [iCloud Keychain](https://support.apple.com/HT202303). In order to be viewed in plain text, a user must input the account password of the current device. This means that users can sync data across devices with added security.

Safari follows a slower release cycle than Chrome and Firefox (3-4 minor releases, 1 major release, per year). Newer features are slower to be adopted to the stable channel. Security updates in Safari are handled independent of the stable release schedule and are installed through the App Store.

See also [el1t/uBlock-Safari](https://github.com/el1t/uBlock-Safari/wiki/Disable-hyperlink-auditing-beacon) to disable hyperlink auditing beacons.

## Other browsers

Many Chromium-derived browsers are not recommended. They are usually [closed source](https://yro.slashdot.org/comments.pl?sid=4176879&cid=44774943), [poorly maintained](https://plus.google.com/+JustinSchuh/posts/69qw9wZVH8z), and make dubious claims to protect privacy.

Other miscellaneous browsers, such as [Brave](https://github.com/drduh/macOS-Security-and-Privacy-Guide/issues/94), are not evaluated in this guide, so are neither recommended nor actively discouraged from use.

## Web browser privacy

Web browsers reveal information in several ways, for example through the [Navigator](https://developer.mozilla.org/en-US/docs/Web/API/Navigator) interface, which may include information such as the browser version, operating system, site permissions, and the device's battery level. Many websites also use [canvas fingerprinting](https://en.wikipedia.org/wiki/Canvas_fingerprinting) to uniquely identify users across sessions.

For more information about security conscious browsing and what data is sent by your browser, see [HowTo: Privacy & Security Conscious Browsing](https://gist.github.com/atcuno/3425484ac5cce5298932), [browserleaks.com](https://browserleaks.com/), [Am I Unique?](https://amiunique.org/fingerprint) and [EFF Cover Your Tracks](https://coveryourtracks.eff.org/) resources.

To hinder third party trackers, it is recommended to **disable third-party cookies** altogether. Safari, Firefox, and Chrome all block third party cookies by default. A third party cookie is a cookie associated with a file requested by a different domain than the one the user is currently viewing. Most of the time third-party cookies are used to create browsing profiles by tracking a user's movement on the web. Disabling third-party cookies prevents HTTP responses and scripts from other domains from setting cookies. Moreover, cookies are removed from requests to domains that are not the document origin domain, so cookies are only sent to the current site that is being viewed.

Also be aware of [WebRTC](https://en.wikipedia.org/wiki/WebRTC#Concerns), which may reveal your local or public (if connected to VPN) IP address(es). In Firefox and Chrome/Chromium this can be disabled with extensions such as [uBlock Origin](https://github.com/gorhill/uBlock/wiki/Prevent-WebRTC-from-leaking-local-IP-address). [Lockdown mode](#lockdown-mode) [disables WebRTC](https://www.sevarg.net/2022/07/20/ios16-lockdown-mode-browser-analysis) in Safari.

# Tor

Tor is an anonymizing network which can be used for browsing the Web with additional privacy. Tor Browser is a modified version of Firefox with a proxy to access the Tor network.

Download Tor Browser from [Tor Project](https://www.torproject.org/download/).

Do **not** attempt to configure other browsers or applications to use Tor as you may make a mistake which will compromise anonymity.

Download both the `dmg` and `asc` signature files, then verify the disk image has been signed by Tor developers:

```console
$ cd ~/Downloads

$ file Tor*
TorBrowser-8.0.4-osx64_en-US.dmg:     bzip2 compressed data, block size = 900k
TorBrowser-8.0.4-osx64_en-US.dmg.asc: PGP signature Signature (old)

$ gpg Tor*asc
[...]
gpg: Can't check signature: No public key

$ gpg --recv 0x4E2C6E8793298290
gpg: key 0x4E2C6E8793298290: public key "Tor Browser Developers (signing key) <torbrowser@torproject.org>" imported
gpg: no ultimately trusted keys found
gpg: Total number processed: 1
gpg:               imported: 1

$ gpg --verify Tor*asc
gpg: assuming signed data in 'TorBrowser-8.0.4-osx64_en-US.dmg'
gpg: Signature made Mon Dec 10 07:16:22 2018 PST
gpg:                using RSA key 0xEB774491D9FF06E2
gpg: Good signature from "Tor Browser Developers (signing key) <torbrowser@torproject.org>" [unknown]
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: EF6E 286D DA85 EA2A 4BA7  DE68 4E2C 6E87 9329 8290
     Subkey fingerprint: 1107 75B5 D101 FB36 BC6C  911B EB77 4491 D9FF 06E2
```

Make sure `Good signature from "Tor Browser Developers (signing key) <torbrowser@torproject.org>"` appears in the output. The warning about the key not being certified is benign, as it has not yet been assigned trust.

See [How can I verify Tor Browser's signature?](https://support.torproject.org/tbb/how-to-verify-signature/) for more information.

To finish installing Tor Browser, open the disk image and drag the it into the Applications folder, or with:

```console
hdiutil mount TorBrowser-8.0.4-osx64_en-US.dmg

cp -r /Volumes/Tor\ Browser/Tor\ Browser.app/ ~/Applications/

```

Verify the Tor application's code signature was made by with The Tor Project's Apple developer ID **MADPSAYN6T**, using the `spctl -a -v` and/or `pkgutil --check-signature` commands:

```console
$ spctl -a -vv ~/Applications/Tor\ Browser.app
/Users/drduh/Applications/Tor Browser.app: accepted
source=Developer ID
origin=Developer ID Application: The Tor Project, Inc (MADPSAYN6T)

$ pkgutil --check-signature ~/Applications/Tor\ Browser.app
Package "Tor Browser.app":
   Status: signed by a certificate trusted by Mac OS X
   Certificate Chain:
    1. Developer ID Application: The Tor Project, Inc (MADPSAYN6T)
       SHA1 fingerprint: 95 80 54 F1 54 66 F3 9C C2 D8 27 7A 29 21 D9 61 11 93 B3 E8
       -----------------------------------------------------------------------------
    2. Developer ID Certification Authority
       SHA1 fingerprint: 3B 16 6C 3B 7D C4 B7 51 C9 FE 2A FA B9 13 56 41 E3 88 E1 86
       -----------------------------------------------------------------------------
    3. Apple Root CA
       SHA1 fingerprint: 61 1E 5B 66 2C 59 3A 08 FF 58 D1 4A E2 24 52 D1 98 DF 6C 60
```

You can also use the `codesign` command to examine an application's code signature:

```console
$ codesign -dvv ~/Applications/Tor\ Browser.app
Executable=/Users/drduh/Applications/Tor Browser.app/Contents/MacOS/firefox
Identifier=org.torproject.torbrowser
Format=app bundle with Mach-O thin (x86_64)
CodeDirectory v=20200 size=229 flags=0x0(none) hashes=4+3 location=embedded
Library validation warning=OS X SDK version before 10.9 does not support Library Validation
Signature size=4247
Authority=Developer ID Application: The Tor Project, Inc (MADPSAYN6T)
Authority=Developer ID Certification Authority
Authority=Apple Root CA
Signed Time=Dec 10, 2018 at 12:18:45 AM
Info.plist entries=24
TeamIdentifier=MADPSAYN6T
Sealed Resources version=2 rules=12 files=128
Internal requirements count=1 size=188
```

To view full certificate details for a signed application, extract them with `codesign` and decode it with `openssl`:

```console
$ codesign -d --extract-certificates ~/Applications/Tor\ Browser.app
Executable=/Users/drduh/Applications/Tor Browser.app/Contents/MacOS/firefox

$ file codesign*
codesign0: data
codesign1: data
codesign2: data

$ openssl x509 -inform der -in codesign0 -subject -issuer -startdate -enddate -noout
subject= /UID=MADPSAYN6T/CN=Developer ID Application: The Tor Project, Inc (MADPSAYN6T)/OU=MADPSAYN6T/O=The Tor Project, Inc/C=US
issuer= /CN=Developer ID Certification Authority/OU=Apple Certification Authority/O=Apple Inc./C=US
notBefore=Apr 12 22:40:13 2016 GMT
notAfter=Apr 13 22:40:13 2021 GMT

$ openssl x509 -inform der -in codesign0  -fingerprint -noout
SHA1 Fingerprint=95:80:54:F1:54:66:F3:9C:C2:D8:27:7A:29:21:D9:61:11:93:B3:E8

$ openssl x509 -inform der -in codesign0 -fingerprint -sha256 -noout
SHA256 Fingerprint=B5:0D:47:F0:3E:CB:42:B6:68:1C:6F:38:06:2B:C2:9F:41:FA:D6:54:F1:29:D3:E4:DD:9C:C7:49:35:FF:F5:D9
```

Tor traffic is **encrypted** to the [exit node](https://en.wikipedia.org/wiki/Tor_(network)#Exit_node_eavesdropping) (i.e., cannot be read by a passive network eavesdropper), but Tor use **can** be identified - for example, TLS handshake "hostnames" will show up in plaintext:

```console
$ sudo tcpdump -An "tcp" | grep "www"
listening on pktap, link-type PKTAP (Apple DLT_PKTAP), capture size 262144 bytes
.............". ...www.odezz26nvv7jeqz1xghzs.com.........
.............#.!...www.bxbko3qi7vacgwyk4ggulh.com.........
.6....m.....>...:.........|../*	Z....W....X=..6...C../....................................0...0..0.......'....F./0..	*.H........0%1#0!..U....www.b6zazzahl3h3faf4x2.com0...160402000000Z..170317000000Z0'1%0#..U....www.tm3ddrghe22wgqna5u8g.net0..0..
```

See [Tor Protocol Specification](https://spec.torproject.org/tor-spec/) and [Tor/TLSHistory](https://gitlab.torproject.org/legacy/trac/-/wikis/org/projects/Tor/TLSHistory) for more information.

You may wish to additionally obfuscate Tor traffic using a [pluggable transport](https://tb-manual.torproject.org/circumvention/).

This can be done by setting up your own [Tor relay](https://support.torproject.org/relay-operators/) or finding an existing private or [public bridge](https://bridges.torproject.org/) to serve as an obfuscating entry node.

For extra security, use Tor inside a [VirtualBox](https://www.virtualbox.org/wiki/Downloads) or [VMware](https://www.vmware.com/products/fusion.html) virtualized [GNU/Linux](https://www.brianlinkletter.com/2012/10/installing-debian-linux-in-a-virtualbox-virtual-machine/) or [OpenBSD](https://www.openbsd.org/faq/faq4.html) instance.

Finally, remember the Tor network provides [anonymity](https://www.privateinternetaccess.com/blog/2013/10/how-does-privacy-differ-from-anonymity-and-why-are-both-important/), which is not necessarily synonymous with privacy. The Tor network does not guarantee protection against a global observer capable of traffic analysis and correlation. See also [Seeking Anonymity in an Internet Panopticon](https://bford.info/pub/net/panopticon-cacm.pdf) (pdf) and [Traffic Correlation on Tor by Realistic Adversaries](https://www.ohmygodel.com/publications/usersrouted-ccs13.pdf) (pdf).

Also see [Invisible Internet Project (I2P)](https://geti2p.net/en/about/intro) and its [Tor comparison](https://geti2p.net/en/comparison/tor).

# VPN

When choosing a VPN service or setting up your own, be sure to research the protocols, key exchange algorithms, authentication mechanisms, and type of encryption being used. Some protocols, such as [PPTP](https://en.wikipedia.org/wiki/Point-to-Point_Tunneling_Protocol#Security), should be avoided in favor of [OpenVPN](https://en.wikipedia.org/wiki/OpenVPN) or Linux-based [Wireguard](https://www.wireguard.com/) [on a Linux VM](https://github.com/mrash/Wireguard-macOS-LinuxVM) or via a set of [cross platform tools](https://www.wireguard.com/xplatform/).

Some clients may send traffic over the next available interface when VPN is interrupted or disconnected. See [scy/8122924](https://gist.github.com/scy/8122924) for an example on how to allow traffic only over VPN.

There is an updated guide to setting up an IPSec VPN on a virtual machine ([hwdsl2/setup-ipsec-vpn](https://github.com/hwdsl2/setup-ipsec-vpn)) or a docker container ([hwdsl2/docker-ipsec-vpn-server](https://github.com/hwdsl2/docker-ipsec-vpn-server)).

It may be worthwhile to consider the geographical location of the VPN provider. See further discussion in [issue 114](https://github.com/drduh/macOS-Security-and-Privacy-Guide/issues/114).

Also see this [technical overview](https://blog.timac.org/2018/0717-macos-vpn-architecture/) of the macOS built-in VPN L2TP/IPSec and IKEv2 client.

# PGP/GPG

PGP is a standard for signing and encrypting data (especially email) end-to-end, so only the sender and recipient can access it.

GPG, or **GNU Privacy Guard**, is a GPL-licensed open source program compliant with the PGP standard.

GPG is used to verify signatures of software you download and install, as well as [symmetrically](https://en.wikipedia.org/wiki/Symmetric-key_algorithm) or [asymmetrically](https://en.wikipedia.org/wiki/Public-key_cryptography) encrypt files and text.

Install from Homebrew with `brew install gnupg`.

If you prefer a graphical application, download and install [GPG Suite](https://gpgtools.org/).

Download [drduh/config/gpg.conf](https://github.com/drduh/config/blob/master/gpg.conf) to use recommended settings:

```console
curl -o ~/.gnupg/gpg.conf https://raw.githubusercontent.com/drduh/config/master/gpg.conf
```

See [drduh/YubiKey-Guide](https://github.com/drduh/YubiKey-Guide) to securely generate and store GPG keys.

Read [online](https://alexcabal.com/creating-the-perfect-gpg-keypair/) [guides](https://security.stackexchange.com/questions/31594/what-is-a-good-general-purpose-gnupg-key-setup) and [practice](https://help.riseup.net/en/security/message-security/openpgp/best-practices) encrypting and decrypting email to yourself and your friends. Get them interested in this stuff!

# Messengers

## XMPP

XMPP is an [open standard](https://xmpp.org/extensions) developed by the [IETF](https://www.ietf.org) that allows for cross-platform federated messaging. There are many options for [clients](https://xmpp.org/getting-started). Consider using one of the browser-based clients to take advantage of your browser's sandbox.

Depending on the provider, you might not need anything other than a username and password to set up your account.

XMPP isn't E2EE by default, you'll need to use [OMEMO](https://omemo.top) encryption, so make sure your client supports it.

## Signal

[Signal](https://www.signal.org) is an advanced E2EE messenger whose [double-ratchet](https://signal.org/docs/specifications/doubleratchet/) protocol is used by countless other messengers including WhatsApp, Google Messages, and Facebook Messenger.

Signal requires a phone number to sign up and you'll need to install it on your phone first before you can use it on desktop.

## iMessage

iMessage is Apple's first party messenger. It requires an [Apple Account](#apple-account) in order to use it.

Make sure to enable [Contact Key Verification](https://support.apple.com/118246) and verify with anyone you message to ensure that you're messaging the right person.

You can use iMessage with either a [phone number or an email](https://support.apple.com/108758#help), so pick one that you're comfortable with your contacts seeing.

**Note:** By default, iCloud backup is enabled which stores copies of your message encryption keys on [Apple's servers](https://support.apple.com/102651) without E2EE. Either [disable iCloud backup](https://support.apple.com/guide/icloud/view-and-manage-backups-mm122d3ef202/1.0/icloud/1.0) or enable [Advanced Data Protection](https://support.apple.com/guide/security/advanced-data-protection-for-icloud-sec973254c5f) to prevent this. Also remember to tell your messaging partner/s to do the same!

# Viruses and malware

There is an [ever-increasing](https://www.documentcloud.org/documents/2459197-bit9-carbon-black-threat-research-report-2015.html) amount of Mac malware in the wild. Macs aren't immune from viruses and malicious software!

Some malware comes bundled with both legitimate software, such as the [Java bundling Ask Toolbar](https://www.zdnet.com/article/oracle-extends-its-adware-bundling-to-include-java-for-macs/), and some with illegitimate software, such as [Mac.BackDoor.iWorm](https://docs.google.com/document/d/1YOfXRUQJgMjJSLBSoLiUaSZfiaS_vU3aG4Bvjmz6Dxs/edit?pli=1) bundled with pirated programs.

See [Methods of malware persistence on Mac OS X](https://www.virusbtn.com/pdf/conference/vb2014/VB2014-Wardle.pdf) (pdf) and [Malware Persistence on OS X Yosemite](https://www.rsaconference.com/events/us15/agenda/sessions/1591/malware-persistence-on-os-x-yosemite) to learn about how garden-variety malware functions.

Subscribe to updates at the [Malwarebytes Blog](https://blog.malwarebytes.com/) for current Mac security news.

Also check out [Hacking Team](https://www.schneier.com/blog/archives/2015/07/hacking_team_is.html) malware for macOS: [root installation for MacOS](https://github.com/hackedteam/vector-macos-root), [Support driver for Mac Agent](https://github.com/hackedteam/driver-macos) and [RCS Agent for Mac](https://github.com/hackedteam/core-macos), which is a good example of advanced malware with capabilities to hide from userland (e.g., `ps`, `ls`). For more, see [A Brief Analysis of an RCS Implant Installer](https://objective-see.com/blog/blog_0x0D.html) and [reverse.put.as](https://reverse.put.as/2016/02/29/the-italian-morons-are-back-what-are-they-up-to-this-time/)

## Downloading Software

Only running programs from the App Store or that are [Notarized](https://support.apple.com/guide/security/app-code-signing-process-sec3ad8e6e53/web) by Apple will help mitigate malware. Apple performs an automated scan on notarized apps for malware. App Store apps undergo a [review](https://developer.apple.com/app-store/review/guidelines/) process to catch malware.

Otherwise, get programs from trusted sources like directly from the developer's website or GitHub. Always make sure that your browser/terminal is using HTTPS when downloading any program.

You should also avoid programs that ask for lots of permissions and third party closed source programs. Open source code allows anyone to audit and examine the code for security/privacy issues.

## App Sandbox

Check if a program uses the [App Sandbox](https://developer.apple.com/documentation/security/app_sandbox/protecting_user_data_with_app_sandbox) before running it by running the following command:

```console
codesign -dvvv --entitlements - <path to your app>
```

If the App Sandbox is enabled, you will see

```console
    [Key] com.apple.security.app-sandbox
    [Value]
        [Bool] true
```

Alternatively, you can check while the app is running by opening Activity Monitor and adding the "Sandbox" column.

All App Store apps are required to use the App Sandbox.

**Note:** Browsers like Google Chrome use their own [sandbox](https://chromium.googlesource.com/chromium/src/+/HEAD/docs/design/sandbox.md) so they don't use the App Sandbox.

## Hardened Runtime

Check if a program uses the [Hardened Runtime](https://developer.apple.com/documentation/security/hardened_runtime) before running it using the following command:

```console
codesign --display --verbose /path/to/bundle.app
```

If Hardened Runtime is enabled, you will see `flags=0x10000(runtime)`. The "runtime" means Hardened Runtime is enabled. There might be other flags, but the runtime flag is what we're looking for here.

You can enable a column in Activity Monitor called "Restricted" which is a flag that prevents programs from injecting code via macOS's [dynamic linker](https://pewpewthespells.com/blog/blocking_code_injection_on_ios_and_os_x.html). Ideally, this should say "Yes".

Notarized apps are required to use the Hardened Runtime.

## Antivirus

To scan an application with multiple AV products and examine its behavior, upload it to [VirusTotal](https://www.virustotal.com/#/home/upload) before running it.

macOS comes with a built-in AV program called [XProtect](https://support.apple.com/guide/security/protecting-against-malware-sec469d47bd8). XProtect automatically runs in the background and updates its signatures that it uses to detect malware without you having to do anything. If it detects malware already running, it will work to remove and mitigate it just like any other AV program.

Applications such as [BlockBlock](https://objective-see.com/products/blockblock.html) or [maclaunch.sh](https://github.com/hazcod/maclaunch) might help prevent persistent malware.

Locally installed **Anti-virus** programs are generally a double-edged sword: they may catch "garden variety" malware, but also may increase the attack surface for sophisticated adversaries due to their privileged operating mode. They also typically phone home to send samples in order to catch the newest malware. This can be a privacy concern.

See [Sophail: Applied attacks against Antivirus](https://lock.cmpxchg8b.com/sophailv2.pdf) (pdf), [Analysis and Exploitation of an ESET Vulnerability](https://googleprojectzero.blogspot.ro/2015/06/analysis-and-exploitation-of-eset.html), [Popular Security Software Came Under Relentless NSA and GCHQ Attacks](https://theintercept.com/2015/06/22/nsa-gchq-targeted-kaspersky/), and [How Israel Caught Russian Hackers Scouring the World for U.S. Secrets](https://www.nytimes.com/2017/10/10/technology/kaspersky-lab-israel-russia-hacking.html).

## Gatekeeper

**Gatekeeper** tries to prevent non-notarized apps from running.

If you try to run an app that isn't notarized, Gatekeeper will give you a warning. This can be easily bypassed if you go to **Privacy & Security**, scroll down to the bottom and click **Open** on your app. Then Gatekeeper will allow you to run it.

Gatekeeper doesn't cover all binaries, only apps so be careful when running other file types.

# System Integrity Protection

To verify SIP is enabled, use the command `csrutil status`, which should return: `System Integrity Protection status: enabled.` Otherwise, [enable SIP](https://developer.apple.com/documentation/security/disabling_and_enabling_system_integrity_protection) through Recovery Mode.

# Metadata and artifacts

macOS attaches metadata ([APFS extended attributes](https://en.wikipedia.org/wiki/Extended_file_attributes#OS_X)) to downloaded files, which can be viewed with the `mdls` and `xattr` commands:

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

```console
xattr -d com.apple.metadata:kMDItemWhereFroms ~/Downloads/TorBrowser-8.0.4-osx64_en-US.dmg

xattr -d com.apple.quarantine ~/Downloads/TorBrowser-8.0.4-osx64_en-US.dmg

xattr -l ~/Downloads/TorBrowser-8.0.4-osx64_en-US.dmg
```

Other metadata and artifacts may be found in the directories including, but not limited to, `~/Library/Preferences/`, `~/Library/Containers/<APP>/Data/Library/Preferences`, `/Library/Preferences`, some of which is detailed below.

`~/Library/Preferences/com.apple.sidebarlists.plist` contains historical list of volumes attached. To clear it, use the command `/usr/libexec/PlistBuddy -c "delete :systemitems:VolumesList" ~/Library/Preferences/com.apple.sidebarlists.plist`

`/Library/Preferences/com.apple.Bluetooth.plist` contains Bluetooth metadata, including device history. If Bluetooth is not used, the metadata can be cleared with:

```console
sudo defaults delete /Library/Preferences/com.apple.Bluetooth.plist DeviceCache
sudo defaults delete /Library/Preferences/com.apple.Bluetooth.plist IDSPairedDevices
sudo defaults delete /Library/Preferences/com.apple.Bluetooth.plist PANDevices
sudo defaults delete /Library/Preferences/com.apple.Bluetooth.plist PANInterfaces
sudo defaults delete /Library/Preferences/com.apple.Bluetooth.plist SCOAudioDevices
```

`/var/spool/cups` contains the CUPS printer job cache. To clear it, use the commands:

```console
sudo rm -rfv /var/spool/cups/c0*
sudo rm -rfv /var/spool/cups/tmp/*
sudo rm -rfv /var/spool/cups/cache/job.cache*
```

To clear the list of iOS devices connected, use:

```console
sudo defaults delete /Users/$USER/Library/Preferences/com.apple.iPod.plist "conn:128:Last Connect"
sudo defaults delete /Users/$USER/Library/Preferences/com.apple.iPod.plist Devices
sudo defaults delete /Library/Preferences/com.apple.iPod.plist "conn:128:Last Connect"
sudo defaults delete /Library/Preferences/com.apple.iPod.plist Devices
sudo rm -rfv /var/db/lockdown/*
```

Quicklook thumbnail data can be cleared using the `qlmanage -r cache` command, but this writes to the file `resetreason` in the Quicklook directories, and states that the Quicklook cache was manually cleared. Disable the thumbnail cache with `qlmanage -r disablecache`

It can also be cleared by getting the directory names with `getconf DARWIN_USER_CACHE_DIR` and `sudo getconf DARWIN_USER_CACHE_DIR`, then removing them:

```console
rm -rfv $(getconf DARWIN_USER_CACHE_DIR)/com.apple.QuickLook.thumbnailcache/exclusive
rm -rfv $(getconf DARWIN_USER_CACHE_DIR)/com.apple.QuickLook.thumbnailcache/index.sqlite
rm -rfv $(getconf DARWIN_USER_CACHE_DIR)/com.apple.QuickLook.thumbnailcache/index.sqlite-shm
rm -rfv $(getconf DARWIN_USER_CACHE_DIR)/com.apple.QuickLook.thumbnailcache/index.sqlite-wal
rm -rfv $(getconf DARWIN_USER_CACHE_DIR)/com.apple.QuickLook.thumbnailcache/resetreason
rm -rfv $(getconf DARWIN_USER_CACHE_DIR)/com.apple.QuickLook.thumbnailcache/thumbnails.data
```

Similarly, for the root user:

```console
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

```console
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

```console
sudo nvram -d 36C28AB5-6566-4C50-9EBD-CBB920F83843:current-network
sudo nvram -d 36C28AB5-6566-4C50-9EBD-CBB920F83843:preferred-networks
sudo nvram -d 36C28AB5-6566-4C50-9EBD-CBB920F83843:preferred-count
```

macOS may collect sensitive information about what you type, even if user dictionary and suggestions are off. To remove them, and prevent them from being created again, use the following commands:

```console
rm -rfv "~/Library/LanguageModeling/*" "~/Library/Spelling/*" "~/Library/Suggestions/*"
chmod -R 000 ~/Library/LanguageModeling ~/Library/Spelling ~/Library/Suggestions
chflags -R uchg ~/Library/LanguageModeling ~/Library/Spelling ~/Library/Suggestions
```

QuickLook application support metadata can be cleared and locked with the following commands:

```console
rm -rfv "~/Library/Application Support/Quick Look/*"
chmod -R 000 "~/Library/Application Support/Quick Look"
chflags -R uchg "~/Library/Application Support/Quick Look"
```

Document revision metadata is stored in `/.DocumentRevisions-V100` and can be cleared and locked with the following commands - caution should be taken as this may break some core Apple applications:

```console
sudo rm -rfv /.DocumentRevisions-V100/*
sudo chmod -R 000 /.DocumentRevisions-V100
sudo chflags -R uchg /.DocumentRevisions-V100
```

Saved application state metadata may be cleared and locked with the following commands:

```console
rm -rfv ~/Library/Saved\ Application\ State/*
rm -rfv ~/Library/Containers/<APPNAME>/Data/Library/Saved\ Application\ State
chmod -R 000 ~/Library/Saved\ Application\ State/
chmod -R 000 ~/Library/Containers/<APPNAME>/Data/Library/Saved\ Application\ State
chflags -R uchg ~/Library/Saved\ Application\ State/
chflags -R uchg ~/Library/Containers/<APPNAME>/Data/Library/Saved\ Application\ State
```

Autosave metadata can be cleared and locked with the following commands:

```console
rm -rfv "~/Library/Containers/<APP>/Data/Library/Autosave Information"
rm -rfv "~/Library/Autosave Information"
chmod -R 000 "~/Library/Containers/<APP>/Data/Library/Autosave Information"
chmod -R 000 "~/Library/Autosave Information"
chflags -R uchg "~/Library/Containers/<APP>/Data/Library/Autosave Information"
chflags -R uchg "~/Library/Autosave Information"
```

The Siri analytics database, which is created even if the Siri launch agent disabled, can be cleared and locked with the following commands:

```console
rm -rfv ~/Library/Assistant/SiriAnalytics.db
chmod -R 000 ~/Library/Assistant/SiriAnalytics.db
chflags -R uchg ~/Library/Assistant/SiriAnalytics.db
```

`~/Library/Preferences/com.apple.iTunes.plist` contains iTunes metadata. Recent iTunes search data may be cleared with the following command:

```console
defaults delete ~/Library/Preferences/com.apple.iTunes.plist recentSearches
```

If you do not use Apple Account-linked services, the following keys may be cleared, too, using the following commands:

```console
defaults delete ~/Library/Preferences/com.apple.iTunes.plist StoreUserInfo
defaults delete ~/Library/Preferences/com.apple.iTunes.plist WirelessBuddyID
```

All media played in QuickTime Player can be found in:

```console
~/Library/Containers/com.apple.QuickTimePlayerX/Data/Library/Preferences/com.apple.QuickTimePlayerX.plist
```

Additional metadata may exist in the following files:

```console
~/Library/Containers/com.apple.appstore/Data/Library/Preferences/com.apple.commerce.knownclients.plist
~/Library/Preferences/com.apple.commerce.plist
~/Library/Preferences/com.apple.QuickTimePlayerX.plist
```

# Passwords

Generate strong passwords using [`urandom`](https://en.wikipedia.org/wiki//dev/random) and [`tr`](https://linux.die.net/man/1/tr):

```console
tr -dc '[:graph:]' < /dev/urandom | fold -w 20 | head -1
```

The password assistant in **Keychain Access** can also generate secure credentials.

Consider using [Diceware](https://secure.research.vt.edu/diceware/) for memorable passwords.

GnuPG can also be used to manage passwords and other encrypted files (see [drduh/Purse](https://github.com/drduh/Purse) and [drduh/pwd.sh](https://github.com/drduh/pwd.sh)).

Ensure all eligible online accounts have [multi-factor authentication](https://en.wikipedia.org/wiki/Multi-factor_authentication) enabled. The strongest form of multi-factor authentication is [WebAuthN](https://en.wikipedia.org/wiki/WebAuthn), followed by app-based authenticators, and SMS-based codes are weakest.

[YubiKey](https://www.yubico.com/products/) is an affordable hardware token with WebAuthN support. It can also be used to store cryptographic keys for GnuPG encryption and SSH authentication - see [drduh/YubiKey-Guide](https://github.com/drduh/YubiKey-Guide).

# Backup

Encrypt files locally before backing them up to external media or online services.

If your threat model allows it, you should follow the [3-2-1 backup model](https://www.cisa.gov/sites/default/files/publications/data_backup_options.pdf) as outlined by CISA. Keep 3 copies: the original and two backups. Keep backups on 2 different media types, e.g. on a local drive and cloud storage. Store 1 copy offsite. 

[Time Machine](https://support.apple.com/104984) is the built-in tool for handling backups on macOS. Get an external drive or network drive to back up to and [encrypt](https://support.apple.com/guide/mac-help/keep-your-time-machine-backup-disk-secure-mh21241) your backups.

GnuPG can be used with a static password or public key (with the private key stored on [YubiKey](https://github.com/drduh/YubiKey-Guide)).

Compress and encrypt a directory using with a password:

```console
tar zcvf - ~/Downloads | gpg -c > ~/Desktop/backup-$(date +%F-%H%M).tar.gz.gpg
```

Decrypt and decompress the directory:

```console
gpg -o ~/Desktop/decrypted-backup.tar.gz -d ~/Desktop/backup-*.tar.gz.gpg

tar zxvf ~/Desktop/decrypted-backup.tar.gz
```

Encrypted volumes can also be created using **Disk Utility** or `hdiutil`:

```console
hdiutil create ~/Desktop/encrypted.dmg -encryption -size 50M -volname "secretStuff"

hdiutil mount ~/Desktop/encrypted.dmg

cp -v ~/Documents/passwords.txt /Volumes/secretStuff

hdiutil eject /Volumes/secretStuff
```

Additional applications and services which offer backups include:

* [Tresorit](https://www.tresorit.com)
* [restic](https://restic.github.io)

# Wi-Fi

macOS remembers access points it has connected to. Like all wireless devices, the Mac will broadcast all access point names it remembers (e.g., *MyHomeNetwork*) each time it looks for a network, such as when waking from sleep.

This is a privacy risk, so remove networks from the list in **System Preferences** > **Network** > **Advanced** when they are no longer needed.

Also see [Signals from the Crowd: Uncovering Social Relationships through Smartphone Probes](https://conferences.sigcomm.org/imc/2013/papers/imc148-barberaSP106.pdf) (pdf).

Saved Wi-Fi information (SSID, last connection, etc.) can be found in `/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`

You can have a different, [random MAC address](https://support.apple.com/en-gb/guide/mac-help/mchlb1cb3eb4/mac) for each network that rotates over time. This will help prevent you from being tracked across networks and on the same network over time.

macOS stores Wi-Fi SSIDs and passwords in NVRAM in order for Recovery Mode to access the Internet. Be sure to either clear NVRAM or de-authenticate your Mac from your Apple account, which will clear the NVRAM, before passing a Mac along. Resetting the SMC will clear some of the NVRAM, but not all.

Finally, WEP protection on wireless networks is [not secure](http://www.howtogeek.com/167783/htg-explains-the-difference-between-wep-wpa-and-wpa2-wireless-encryption-and-why-it-matters/) and you should only connect to **WPA3** protected networks when possible.

# SSH

For outgoing SSH connections, use hardware or password-protected keys, [set up](http://nerderati.com/2011/03/17/simplify-your-life-with-an-ssh-config-file/) remote hosts and consider [hashing](http://nms.csail.mit.edu/projects/ssh/) them for added privacy. See [drduh/config/ssh_config](https://github.com/drduh/config/blob/master/ssh_config) for recommended client options.

You can also use ssh to create an [encrypted tunnel](http://blog.trackets.com/2014/05/17/ssh-tunnel-local-and-remote-port-forwarding-explained-with-examples.html) to send traffic through, similar to a VPN.

For example, to use Privoxy running on a remote host port 8118:

```console
ssh -C -L 5555:127.0.0.1:8118 you@remote-host.tld

sudo networksetup -setwebproxy "Wi-Fi" 127.0.0.1 5555

sudo networksetup -setsecurewebproxy "Wi-Fi" 127.0.0.1 5555
```

Or to use an ssh connection as a [SOCKS proxy](https://www.mikeash.com/ssh_socks.html):

```console
ssh -NCD 3000 you@remote-host.tld
```

By default, macOS does **not** have sshd or *Remote Login* enabled.

To enable sshd and allow incoming ssh connections:

```console
sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist
```

Or use the **System Preferences** > **Sharing** menu.

If enabling sshd, be sure to disable password authentication and consider further [hardening](https://stribika.github.io/2015/01/04/secure-secure-shell.html) your configuration. See [drduh/config/sshd_config](https://github.com/drduh/config/blob/master/sshd_config) for recommended options.

Confirm whether sshd is running:

```console
sudo lsof -Pni TCP:22
```

# Physical access

Keep your Mac physically secure at all times and do not leave it unattended in public.

A skilled attacker with unsupervised physical access could install a [hardware keylogger](https://trmm.net/Thunderstrike_31c3) to record all of your keystrokes. Using a Mac with a built-in keyboard or a bluetooth keyboard makes this more difficult as many off-the-shelf versions of this attack are designed to be plugged in between a USB keyboard and your computer.

To protect against physical theft during use, you can use an anti-forensic tool like [BusKill](https://github.com/buskill/buskill-app) or [swiftGuard](https://github.com/Lennolium/swiftGuard) (updated usbkill, with graphical user interface). All respond to USB events and can immediately shutdown your computer if your device is physically separated from you or an unauthorized device is connected.

Consider purchasing a privacy screen/filter for use in public.

[Nail polish](https://trmm.net/Glitter) and tamper-evidence seals can be applied to components to detect tampering.

# System monitoring

## OpenBSM audit

macOS has a powerful OpenBSM (Basic Security Module) auditing capability. You can use it to monitor process execution, network activity, and much more.

To tail audit logs, use the `praudit` utility:

```console
$ sudo praudit -l /dev/auditpipe
header,201,11,execve(2),0,Thu Sep  1 12:00:00 2015, + 195 msec,exec arg,/Applications/.evilapp/rootkit,path,/Applications/.evilapp/rootkit,path,/Applications/.evilapp/rootkit,attribute,100755,root,wheel,16777220,986535,0,subject,drduh,root,wheel,root,wheel,412,100005,50511731,0.0.0.0,return,success,0,trailer,201,
header,88,11,connect(2),0,Thu Sep  1 12:00:00 2015, + 238 msec,argument,1,0x5,fd,socket-inet,2,443,173.194.74.104,subject,drduh,root,wheel,root,wheel,326,100005,50331650,0.0.0.0,return,failure : Operation now in progress,4354967105,trailer,88
header,111,11,OpenSSH login,0,Thu Sep  1 12:00:00 2015, + 16 msec,subject_ex,drduh,drduh,staff,drduh,staff,404,404,49271,::1,text,successful login drduh,return,success,0,trailer,111,
```

See the manual pages for `audit`, `praudit`, `audit_control` and other files in `/etc/security`

**Note** although `man audit` says the `-s` flag will synchronize the audit configuration, it appears necessary to reboot for changes to take effect.

See articles on [ilostmynotes.blogspot.com](https://ilostmynotes.blogspot.com/2013/10/openbsm-auditd-on-os-x-these-are-logs.html) and [derflounder.wordpress.com](https://derflounder.wordpress.com/2012/01/30/openbsm-auditing-on-mac-os-x/) for more information.

## DTrace

**Note** [System Integrity Protection](https://github.com/drduh/macOS-Security-and-Privacy-Guide#system-integrity-protection) interferes with DTrace, so it is not possible to use it in recent macOS versions without disabling SIP.

* `iosnoop` monitors disk I/O
* `opensnoop` monitors file opens
* `execsnoop` monitors execution of processes
* `errinfo` monitors failed system calls
* `dtruss` monitors all system calls

See `man -k dtrace` for more information.

## Execution

`ps -ef` lists information about all running processes.

You can also view processes with **Activity Monitor**.

`launchctl list` and `sudo launchctl list` list loaded and running user and system launch daemons and agents.

## Network

List open network files:

```console
sudo lsof -Pni
```

List contents of various network-related data structures:

```console
sudo netstat -atln
```

[Wireshark](https://www.wireshark.org/) can be used from the command line with `tshark`.

Monitor DNS queries and replies:

```console
tshark -Y "dns.flags.response == 1" -Tfields \
  -e frame.time_delta \
  -e dns.qry.name \
  -e dns.a \
  -Eseparator=,
```

Monitor HTTP requests and responses:

```console
tshark -Y "http.request or http.response" -Tfields \
  -e ip.dst \
  -e http.request.full_uri \
  -e http.request.method \
  -e http.response.code \
  -e http.response.phrase \
  -Eseparator=/s
```

Monitor x509 (SSL/TLS) certificates:

```console
tshark -Y "ssl.handshake.certificate" -Tfields \
  -e ip.src \
  -e x509sat.uTF8String \
  -e x509sat.printableString \
  -e x509sat.universalString \
  -e x509sat.IA5String \
  -e x509sat.teletexString \
  -Eseparator=/s -Equote=d
```

# Binary authorization

[google/santa](https://github.com/google/santa/) is a security software developed for Google's corporate Macintosh fleet and open sourced.

> Santa is a binary and file access authorization system for macOS. It consists of a system extension that monitors for executions, a daemon that makes execution decisions based on the contents of a local database, a GUI agent that notifies the user in case of a block decision and a command-line utility for managing the system and synchronizing the database with a server.

Santa uses the [Endpoint Security API](https://developer.apple.com/documentation/endpointsecurity) to monitor and allow/disallow binaries from executing. Binaries can be white- or black-listed by unique hash or signing developer certificate. Santa can be used to only allow trusted code execution, or to blacklist known malware from executing on a Mac, similar to Bit9 software for Windows.

**Note** Santa does not currently have a graphical user interface for managing rules. The following instructions are for advanced users only!

To install Santa, visit the [Releases](https://github.com/google/santa/releases) page and download the latest disk image, the mount it and install the contained package:

```console
hdiutil mount ~/Downloads/santa-2024.9.dmg

sudo installer -pkg /Volumes/santa-2024.9/santa-2024.9.pkg -tgt /
```

By default, Santa installs in "Monitor" mode (meaning, nothing gets blocked, only logged) and comes with two rules: one for Apple binaries and another for Santa software itself.

Verify Santa is running and its kernel module is loaded:

```console
$ santactl status
>>> Daemon Info
  Mode                   | Monitor
  File Logging           | No
  Watchdog CPU Events    | 0  (Peak: 0.00%)
  Watchdog RAM Events    | 0  (Peak: 0.00MB)
>>> Kernel Info
  Kernel cache count     | 0
>>> Database Info
  Binary Rules           | 0
  Certificate Rules      | 2
  Events Pending Upload  | 0

$ ps -ef | grep "[s]anta"
    0   786     1   0 10:01AM ??         0:00.39 /Library/Extensions/santa-driver.kext/Contents/MacOS/santad --syslog

$ kextstat | grep santa
  119    0 0xffffff7f822ff000 0x6000     0x6000     com.google.santa-driver (0.9.14) 693D8E4D-3161-30E0-B83D-66A273CAE026 <5 4 3 1>
```

Create a blacklist rule to prevent iTunes from executing:

```console
$ sudo santactl rule --blacklist --path /Applications/iTunes.app/
Added rule for SHA-256: e1365b51d2cb2c8562e7f1de36bfb3d5248de586f40b23a2ed641af2072225b3.
```

Try to launch iTunes - it will be blocked.

```console
$ open /Applications/iTunes.app/
LSOpenURLsWithRole() failed with error -10810 for the file /Applications/iTunes.app.
```

<img width="450" alt="Santa block dialog when attempting to run a blacklisted program" src="https://cloud.githubusercontent.com/assets/12475110/21062284/14ddde88-be1e-11e6-8e9b-32f8a44c0cf6.png">

To remove the rule:

```console
$ sudo santactl rule --remove --path /Applications/iTunes.app/
Removed rule for SHA-256: e1365b51d2cb2c8562e7f1de36bfb3d5248de586f40b23a2ed641af2072225b3.
```

Open iTunes:

```console
$ open /Applications/iTunes.app/
[iTunes will open successfully]
```

Create a new, example C program:

```console
$ cat <<EOF > foo.c
> #include <stdio.h>
> main() { printf("Hello World\n”); }
> EOF
```

Compile the program with GCC (requires installation of Xcode or command-line tools):

```console
$ gcc -o foo foo.c

$ file foo
foo: Mach-O 64-bit executable x86_64

$ codesign -d foo
foo: code object is not signed at all
```

Run it:

```console
$ ./foo
Hello World
```

Toggle Santa into "Lockdown" mode, which only allows authorized binaries to run:

```console
$ sudo defaults write /var/db/santa/config.plist ClientMode -int 2
```

Try to run the unsigned binary:

```console
$ ./foo
bash: ./foo: Operation not permitted

Santa

The following application has been blocked from executing
because its trustworthiness cannot be determined.

Path:       /Users/demouser/foo
Identifier: 4e11da26feb48231d6e90b10c169b0f8ae1080f36c168ffe53b1616f7505baed
Parent:     bash (701)
```

To authorize a binary, determine its SHA-256 sum:

```console
$ santactl fileinfo /Users/demouser/foo
Path                 : /Users/demouser/foo
SHA-256              : 4e11da26feb48231d6e90b10c169b0f8ae1080f36c168ffe53b1616f7505baed
SHA-1                : 4506f3a8c0a5abe4cacb98e6267549a4d8734d82
Type                 : Executable (x86-64)
Code-signed          : No
Rule                 : Blacklisted (Unknown)
```

Add a new rule:

```console
$ sudo santactl rule --whitelist --sha256 4e11da26feb48231d6e90b10c169b0f8ae1080f36c168ffe53b1616f7505baed
Added rule for SHA-256: 4e11da26feb48231d6e90b10c169b0f8ae1080f36c168ffe53b1616f7505baed.
```

Run it:

```console
$ ./foo
Hello World
```

It's allowed and works!

Applications can also be allowed by developer certificate. For example, download and run Google Chrome - it will be blocked by Santa in "Lockdown" mode:

```console
$ curl -sO https://dl.google.com/chrome/mac/stable/GGRO/googlechrome.dmg

$ hdiutil mount googlechrome.dmg

$ cp -r /Volumes/Google\ Chrome/Google\ Chrome.app /Applications/

$ open /Applications/Google\ Chrome.app/
LSOpenURLsWithRole() failed with error -10810 for the file /Applications/Google Chrome.app.
```

Authorize the application by the developer certificate (first item in the Signing Chain):

```console
$ santactl fileinfo /Applications/Google\ Chrome.app/
Path                 : /Applications/Google Chrome.app/Contents/MacOS/Google Chrome
SHA-256              : 0eb08224d427fb1d87d2276d911bbb6c4326ec9f74448a4d9a3cfce0c3413810
SHA-1                : 9213cbc7dfaaf7580f3936a915faa56d40479f6a
Bundle Name          : Google Chrome
Bundle Version       : 2883.87
Bundle Version Str   : 55.0.2883.87
Type                 : Executable (x86-64)
Code-signed          : Yes
Rule                 : Blacklisted (Unknown)
Signing Chain:
     1. SHA-256             : 15b8ce88e10f04c88a5542234fbdfc1487e9c2f64058a05027c7c34fc4201153
        SHA-1               : 85cee8254216185620ddc8851c7a9fc4dfe120ef
        Common Name         : Developer ID Application: Google Inc.
        Organization        : Google Inc.
        Organizational Unit : EQHXZ8M8AV
        Valid From          : 2012/04/26 07:10:10 -0700
        Valid Until         : 2017/04/27 07:10:10 -0700

     2. SHA-256             : 7afc9d01a62f03a2de9637936d4afe68090d2de18d03f29c88cfb0b1ba63587f
        SHA-1               : 3b166c3b7dc4b751c9fe2afab9135641e388e186
        Common Name         : Developer ID Certification Authority
        Organization        : Apple Inc.
        Organizational Unit : Apple Certification Authority
        Valid From          : 2012/02/01 14:12:15 -0800
        Valid Until         : 2027/02/01 14:12:15 -0800

     3. SHA-256             : b0b1730ecbc7ff4505142c49f1295e6eda6bcaed7e2c68c5be91b5a11001f024
        SHA-1               : 611e5b662c593a08ff58d14ae22452d198df6c60
        Common Name         : Apple Root CA
        Organization        : Apple Inc.
        Organizational Unit : Apple Certification Authority
        Valid From          : 2006/04/25 14:40:36 -0700
        Valid Until         : 2035/02/09 13:40:36 -0800
```

In this case, `15b8ce88e10f04c88a5542234fbdfc1487e9c2f64058a05027c7c34fc4201153` is the SHA-256 of Google’s Apple developer certificate (team ID EQHXZ8M8AV) - authorize it:

```console
$ sudo santactl rule --whitelist --certificate --sha256 15b8ce88e10f04c88a5542234fbdfc1487e9c2f64058a05027c7c34fc4201153
Added rule for SHA-256: 15b8ce88e10f04c88a5542234fbdfc1487e9c2f64058a05027c7c34fc4201153.
```

Google Chrome should now launch, and subsequent updates to the application will continue to work as long as the code signing certificate doesn’t change or expire.

To disable "Lockdown" mode:

```console
sudo defaults delete /var/db/santa/config.plist ClientMode
```

See `/var/log/santa.log` to monitor ALLOW and DENY execution decisions.

A log and configuration server for Santa is available in [Zentral](https://github.com/zentralopensource/zentral), an open source event monitoring solution and TLS server for osquery and Santa.

Zentral will support Santa in both MONITORING and LOCKDOWN operation mode. Clients need to be enrolled with a TLS connection to sync Santa Rules, all Santa events from endpoints are aggregated and logged back in Zentral. Santa events can trigger actions and notifications from within the Zentral Framework.

**Note** Python, Bash and other interpreters are authorized (since they are signed by Apple's developer certificate), so Santa will not be able to block such scripts from executing. Thus, a potential non-binary program which disables Santa is a weakness (not vulnerability, since it is so by design) to take note of.

# Miscellaneous

Disable [Diagnostics & Usage Data](https://support.apple.com/guide/mac-help/share-analytics-information-mac-apple-mh27990).

If you want to play **music** or watch **videos**, use QuickTime Player, the built-in media player in macOS. It uses the [App Sandbox](https://developer.apple.com/documentation/security/app_sandbox/protecting_user_data_with_app_sandbox), [Hardened Runtime](https://developer.apple.com/documentation/xcode/configuring-the-hardened-runtime), and benefits from the [Signed System Volume](https://support.apple.com/guide/security/signed-system-volume-security-secd698747c9/web) as part of the base system.

If you want to use **torrents**, use [Transmission](https://transmissionbt.com/download/) which is free and open source (note: like all software, even open source projects, [malware may still find its way in](http://researchcenter.paloaltonetworks.com/2016/03/new-os-x-ransomware-keranger-infected-transmission-bittorrent-client-installer/)). You may also wish to use a block list to avoid peering with known bad hosts - see [Which is the best blocklist for Transmission](https://giuliomac.wordpress.com/2014/02/19/best-blocklist-for-transmission/) and [johntyree/3331662](https://gist.github.com/johntyree/3331662).

Manage [default file handlers](https://support.apple.com/guide/mac-help/choose-an-app-to-open-a-file-on-mac-mh35597).

Monitor system logs with the **Console** application or `syslog -w` or `/usr/bin/log stream` commands.

Set your screen to lock as soon as the screensaver starts:

```console
defaults write com.apple.screensaver askForPassword -int 1

defaults write com.apple.screensaver askForPasswordDelay -int 0
```

Expose hidden files and Library folder in Finder:

```console
defaults write com.apple.finder AppleShowAllFiles -bool true

chflags nohidden ~/Library
```

Show all filename extensions (so that "Evil.jpg.app" cannot masquerade easily).

```console
defaults write NSGlobalDomain AppleShowAllExtensions -bool true
```

Don't default to saving documents to iCloud:

```console
defaults write NSGlobalDomain NSDocumentSaveNewDocumentsToCloud -bool false
```

Enable [Secure Keyboard Entry](https://support.apple.com/guide/terminal/use-secure-keyboard-entry-trml109) in Terminal (unless you use [YubiKey](https://mig5.net/content/secure-keyboard-entry-os-x-blocks-interaction-yubikeys) or applications such as [TextExpander](https://smilesoftware.com/textexpander/secure-input)).

Disable crash reporter (the dialog which appears after an application crashes and prompts to report the problem to Apple):

```console
defaults write com.apple.CrashReporter DialogType none
```

Disable Bonjour multicast advertisements:

**Warning:** This will cause problems with AirPlay and AirPrint!

```console
sudo defaults write /Library/Preferences/com.apple.mDNSResponder.plist NoMulticastAdvertisements -bool YES
```

[Disable Handoff](https://support.apple.com/guide/mac-help/change-airdrop-handoff-settings-mchl6a407f99) and [Bluetooth](https://support.apple.com/guide/mac-help/turn-bluetooth-on-or-off-blth1008) features, if they aren't necessary.

Check that your apps are sandboxed in [Activity Monitor](https://developer.apple.com/documentation/security/app_sandbox/protecting_user_data_with_app_sandbox#4098972).

macOS comes with this line in `/etc/sudoers`:

```console
Defaults env_keep += "HOME MAIL"
```

Which stops sudo from changing the HOME variable when you elevate privileges. This means it will execute as root the zsh dotfiles in the non-root user's home directory when you run "sudo zsh". It is advisable to comment this line out to avoid a potentially easy way for malware or a local attacker to escalate privileges to root.

If you want to retain the convenience of the root user having a non-root user's home directory, you can append an export line to /var/root/.zshrc, e.g.:

```console
export HOME=/Users/blah
```

Set a [custom umask](https://support.apple.com/101914):

```console
sudo launchctl config user umask 077
```

Reboot, create a file in Finder and verify its permissions (macOS default allows 'group/other' read access):

```console
$ ls -ld umask*
drwx------  2 kevin  staff       64 Dec  4 12:27 umask_testing_dir
-rw-------@ 1 kevin  staff  2026566 Dec  4 12:28 umask_testing_file
```

# Related software

* [CISOfy/lynis](https://github.com/CISOfy/lynis) - Cross-platform security auditing tool and assists with compliance testing and system hardening.
* [Zentral](https://github.com/zentralopensource/zentral) - A log and configuration server for santa and osquery. Run audit and probes on inventory, events, logfiles, combine with point-in-time alerting. A full Framework and Django web server build on top of the elastic stack (formerly known as ELK stack).
* [osquery](https://github.com/osquery/osquery) - Can be used to retrieve low level system information.  Users can write SQL queries to retrieve system information.

# Additional resources

* [Apple Open Source](https://opensource.apple.com/)
* [CIS Benchmarks](https://www.cisecurity.org/benchmark/apple_os/)
* [EFF Surveillance Self-Defense Guide](https://ssd.eff.org/)
* [iOS, The Future Of macOS, Freedom, Security And Privacy In An Increasingly Hostile Global Environment](https://gist.github.com/iosecure/357e724811fe04167332ef54e736670d)
* [Patrick Wardle's Objective-See blog](https://objective-see.com/blog.html)
* [Reverse Engineering macOS blog](https://reverse.put.as/)
* [Reverse Engineering Resources](http://samdmarshall.com/re.html)
* [The macOS Phishing Easy Button: AppleScript Dangers](https://duo.com/blog/the-macos-phishing-easy-button-applescript-dangers)
* [iCloud security and privacy overview](https://support.apple.com/102651)
