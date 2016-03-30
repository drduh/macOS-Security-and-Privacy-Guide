This is a collection of thoughts on securing a modern Apple Mac computer using OS X 10.11 "El Capitan", as well as steps to improving online privacy.

This guide is targeted to “power users” who wish to adopt enterprise-standard security, but is also suitable for novice users with an interest in improving their privacy and security on a Mac.

There is no security silver bullet. A system is only as secure as its administrator is capable of making it.

I am **not** responsible if you break a Mac by following any of these steps.

If you wish to make a correction or improvement, please send a pull request or [open an issue](https://github.com/drduh/OS-X-Security-and-Privacy-Guide/issues).

- [Basics](#basics)
- [Preparing OS X](#preparing-os-x)
- [Installing OS X](#installing-os-x)
    - [Recovery partition](#recovery-partition)
- [First boot](#first-boot)
- [Full disk encryption](#full-disk-encryption)
- [Firmware password](#firmware-password)
- [Firewall](#firewall)
    - [Application layer firewall](#application-layer-firewall)
    - [Third party firewalls](#third-party-firewalls)
    - [Kernel level packet filtering](#kernel-level-packet-filtering)
- [Services](#services)
- [Spotlight Suggestions](#spotlight-suggestions)
- [Homebrew](#homebrew)
- [DNS](#dns)
    - [Hosts file](#hosts-file)
    - [dnsmasq](#dnsmasq)
      - [Test DNSSEC validation](#test-dnssec-validation)
    - [dnscrypt](#dnscrypt)
- [Captive portal](#captive-portal)
- [Certificate authorities](#certificate-authorities)
- [OpenSSL](#openssl)
- [Curl](#curl)
- [HTTP](#http)
- [Web browsing](#web-browsing)
- [Plugins](#plugins)
- [PGP/GPG](#pgpgpg)
- [OTR](#otr)
- [Tor](#tor)
- [VPN](#vpn)
- [Viruses and malware](#viruses-and-malware)
- [System Integrity Protection](#system-integrity-protection)
- [Gatekeeper and XProtect](#gatekeeper-and-xprotect)
- [Passwords](#passwords)
- [Backup](#backup)
- [Wi-Fi](#wi-fi)
- [SSH](#ssh)
- [Physical access](#physical-access)
- [System monitoring](#system-monitoring)
    - [Open source monitoring tools](#open-source-monitoring-tools)
    - [OpenBSM audit](#openbsm-audit)
    - [DTrace](#dtrace)
    - [Execution](#execution)
    - [Network](#network)
- [Miscellaneous](#miscellaneous)
- [Additional resources](#additional-resources)

## Basics
The standard best security practices apply.

* Create a threat model
	* What are you trying to protect and from whom? Is your adversary a [three letter agency](https://theintercept.com/document/2015/03/10/strawhorse-attacking-macos-ios-software-development-kit/) (if so, you may want to consider using [OpenBSD](http://www.openbsd.org/) instead), a nosy eavesdropper on the network, or determined [apt](https://en.wikipedia.org/wiki/Advanced_persistent_threat) orchestrating a campaign against you?
	* Study and recognize threats and how to reduce attack surface.

* Keep the system up to date
	* Patch, patch, patch your system and software.
	* Subscribe to announcement mailing lists (e.g., [Apple security-announce](https://lists.apple.com/mailman/listinfo/security-announce)) for programs you use often.

* Encrypt sensitive data
	* In addition to full disk encryption, create one or many encrypted containers to store passwords, keys and personal documents.
	* This will mitigate damage in case of compromise and data exfiltration.

* Frequent backups
	* Create regular backups of your data and be ready to reimage in case of compromise.
	* Always encrypt before copying backups to external media or the "cloud".

* Click carefully
	* Ultimately, the security of a system can be reduced to its administrator.
	* Care should be taken when installing new software. Always prefer [free](https://www.gnu.org/philosophy/free-sw.en.html) and open source software ([which OS X is not](https://superuser.com/questions/19492/is-mac-os-x-open-source)).

## Preparing OS X
There are several ways to install a fresh copy of OS X.

The simplest way is to boot into [Recovery Mode](https://support.apple.com/en-us/HT201314) by holding `Command` and `R` keys at boot. A system image can be downloaded and applied directly from Apple. However, this way exposes the computer's serial number and other identifying information to Apple over plain **HTTP**.

Another way is to download **OS X El Capitan 10.11.4** from the [App Store](https://itunes.apple.com/us/app/os-x-el-capitan/id1018109117) or some other place and create a custom, installable system image.

The application is [code signed](https://developer.apple.com/library/mac/documentation/Security/Conceptual/CodeSigningGuide/Procedures/Procedures.html#//apple_ref/doc/uid/TP40005929-CH4-SW6), which should be verified to make sure you received a legitimate copy.

    $ codesign -dvv /Applications/Install\ OS\ X\ El\ Capitan.app
	Executable=/Applications/Install OS X El Capitan.app/Contents/MacOS/InstallAssistant
	Identifier=com.apple.InstallAssistant.ElCapitan
	Format=app bundle with Mach-O thin (x86_64)
	CodeDirectory v=20200 size=280 flags=0x200(kill) hashes=4+5 location=embedded
	Signature size=4167
	Authority=Apple Mac OS Application Signing
	Authority=Apple Worldwide Developer Relations Certification Authority
	Authority=Apple Root CA
	Info.plist entries=31
	TeamIdentifier=K36BKF7T3D
	Sealed Resources version=2 rules=7 files=152
	Internal requirements count=1 size=124

OS X installers can be made with the `createinstallmedia` utility included in `Install OS X El Capitan.app/Contents/Resources/`. See [Create a bootable installer for OS X Yosemite](https://support.apple.com/en-us/HT201372), or run the utility without arguments to see how it works.

If you'd like to do it the **manual** way, you will need to find the file `InstallESD.dmg`, which is inside `Install OS X El Capitan.app`.

Right click, select **Show Package Contents** and navigate to **Contents > SharedSupport** to find `InstallESD.DMG`.

You can verify the following cryptographic hashes to ensure you have the same, authentic copy by using a command like `shasum -a256 InstallESD.dmg` and so on.

You can also Google these hashes to ensure your copy is genuine and has not been tampered with. See `InstallESD_Hashes.csv` in this repository for previous versions.

    InstallESD.dmg (Build 15E65)

    SHA-256:   532830b2a04b6f496b1cc1b18cc1645d1cda34151c212b68133f41c19d1431ed
    SHA-1:     f6292573395b46e8110be6077fd4827409bc948b

Mount and install the operating system to a **temporary image**, or use the GUI app [MagerValp/AutoDMG](https://github.com/MagerValp/AutoDMG).

    hdiutil attach -noverify -mountpoint /tmp/installesd ./InstallESD.dmg

    hdiutil create -size 32g -type SPARSE -fs HFS+J -volname "OS X" -uid 0 -gid 80 -mode 1775 /tmp/output.sparseimage

    hdiutil attach -noverify -mountpoint /tmp/os -owners on /tmp/output.sparseimage

    sudo installer -pkg /tmp/installesd/Packages/OSInstall.mpkg -tgt /tmp/os

This part will take a while, so just be patient. You can `tail -F /var/log/install.log` to check progress.

Optionally, install any other packages to the image, such as [Wireshark](https://www.wireshark.org/download.html).

    hdiutil mount Wireshark\ 2.0.1\ Intel\ 64.dmg

    sudo installer -pkg /Volumes/Wireshark/Wireshark\ 2.0.1\ Intel\ 64.pkg -tgt /tmp/os

    hdiutil unmount /Volumes/Wireshark

See [MagerValp/AutoDMG/wiki/Packages-Suitable-for-Deployment](https://github.com/MagerValp/AutoDMG/wiki/Packages-Suitable-for-Deployment) for caveats and check out [chilcote/outset](https://github.com/chilcote/outset) to instead processes packages and scripts at first boot.

When you're done, detach, convert and verify the image.

    hdiutil detach /tmp/os

    hdiutil detach /tmp/installesd

    hdiutil convert -format UDZO /tmp/output.sparseimage -o elcap.dmg

    asr imagescan --source elcap.dmg

Now, `elcap.dmg` is ready to be applied to one or multiple Macs. You can further customize the image to include premade users, applications and preferences to your liking.

## Installing OS X

One way to install the OS X image is using another Mac in [Target Disk Mode](https://support.apple.com/en-us/HT201462).

If you don't have another Mac, create a bootable USB drive from the El Capitan application bundle, and boot the Mac you wish to image to it by holding the *Option* key at boot.

Alternatively, you could also create a second partition on your existing Mac and use that.

If you don't have an external drive or USB stick to use, it's possible to create a small partition with **Disk Utility** and use that. There are several guides online on how to do this.

To use **Target Disk Mode**, boot up the Mac you wish to image while holding `T` and connect it to another using Firewire, Thunderbolt or USB-C.

Run `diskutil list` to identify the connected disk, usually `/dev/disk2`

**Erase** the disk to Journaled HFS+

    diskutil unmountDisk /dev/disk2
    diskutil partitionDisk /dev/disk2 1 JHFS+ OSX 100%

**Restore** the image to the new volume

    sudo asr restore \
      --source elcap.dmg \
      --target /Volumes/OSX \
      --erase --noverify \
      --buffersize 4m

Alternatively, open the **Disk Utility** application, erase the connected Mac's disk, then drag `elcap.dmg` in to restore it to the new partition.

If you've followed these steps correctly, the target Mac should now have a new install of OS X.

If you want to transfer any files, copy them to a folder like `/Users/Shared` on the mounted disk image, e.g. `cp Xcode_7.0.dmg /Volumes/OS\ X/Users/Shared`

#### Recovery partition

We're not done yet! Unless you have built the image with [AutoDMG](https://github.com/MagerValp/AutoDMG), or installed OS X to a second partition on your Mac, you will need to create a recovery partition in order to use Filevault full disk encryption. You can do so using [MagerValp/Create-Recovery-Partition-Installer](https://github.com/MagerValp/Create-Recovery-Partition-Installer) or by following these steps.

Download [RecoveryHDUpdate.dmg](https://support.apple.com/downloads/DL1464/en_US/RecoveryHDUpdate.dmg)

    RecoveryHDUpdate.dmg

    SHA-256: f6a4f8ac25eaa6163aa33ac46d40f223f40e58ec0b6b9bf6ad96bdbfc771e12c
    SHA-1:   1ac3b7059ae0fcb2877d22375121d4e6920ae5ba

Attach and expand the installation, then run it

    hdiutil attach RecoveryHDUpdate.dmg

    pkgutil --expand /Volumes/Mac\ OS\ X\ Lion\ Recovery\ HD\ Update/RecoveryHDUpdate.pkg /tmp/recovery

    hdiutil attach /tmp/recovery/RecoveryHDUpdate.pkg/RecoveryHDMeta.dmg

    /tmp/recovery/RecoveryHDUpdate.pkg/Scripts/Tools/dmtest ensureRecoveryPartition /Volumes/OS\ X/ /Volumes/Recovery\ HD\ Update/BaseSystem.dmg 0 0 /Volumes/Recovery\ HD\ Update/BaseSystem.chunklist

Where `/Volumes/OS\ X` is the path to the target disk mode booted Mac.

This will take several minutes.

Run `diskutil list` again to make sure **Recovery HD** now exists.

Once you're done, eject the disk with `hdiutil unmount /Volumes/OS\ X` and power down the connected Mac.

## First boot
On first boot, hold `Command` `Option` `P` and `R` keys to [clear NVRAM](https://support.apple.com/en-us/HT204063).

Wait for the loud, obnoxious gong and keep holding while the Mac reboots once.

When OS X first starts, you'll be greeted by **Setup Assistant**.

Do not connect to networking yet; skip that part of the setup for now.

When creating your account, use a [strong password](http://www.explainxkcd.com/wiki/index.php/936:_Password_Strength) without a hint.

Don't use your real name for your account as it'll show up as *So-and-so's Macbook* through sharing services to local networks.

## Full disk encryption
[Filevault](https://en.wikipedia.org/wiki/FileVault) provides full disk (technically, full _volume_) encryption on OS X.

Filevault encryption will protect data at rest and prevent someone with physical access from stealing data or tampering with your Mac.

With much crypto [happening in hardware](https://software.intel.com/en-us/articles/intel-advanced-encryption-standard-aes-instructions-set/), the performance penalty for Filevault is not noticeable.

The security of Filevault 2 greatly depends on the pseudo random number generator (**PRNG**).

> The random device implements the Yarrow pseudo random number generator algorithm and maintains its entropy pool.  Additional entropy is fed to the generator regularly by the SecurityServer daemon from random jitter measurements of the kernel.
>
> SecurityServer is also responsible for periodically saving some entropy to disk and reloading it during startup to provide entropy in early system operation.

See `man 4 random` for more information.

The PRNG can be manually seeded with entropy by writing to /dev/random **before** enabling Filevault 2. This can be done by simply using the Mac for a little while before activating Filevault 2.

Enable Filevault with `sudo fdesetup enable` or using **System Preferences** and reboot.

If you can remember your password, there's no reason to save the **recovery key**. However, your encrypted data will be lost forever if you can't remember the password or recovery key.

If you want to know more about how Filevault 2 works, see the paper [Infiltrate the Vault: Security Analysis and Decryption of Lion Full Disk Encryption](https://eprint.iacr.org/2012/374.pdf) [pdf]

and [IEEE Std 1619-2007 “The XTS-AES Tweakable Block Cipher”](http://libeccio.di.unisa.it/Crypto14/Lab/p1619.pdf) [pdf]

You may wish to enforce **hibernation** and evict Filevault keys from memory instead of traditional sleep to memory.

    sudo pmset -a destroyfvkeyonstandby 1
    sudo pmset -a hibernatemode 25

> All computers have firmware of some type—EFI, BIOS—to help in the discovery of hardware components and ultimately to properly bootstrap the computer using the desired OS instance. In the case of Apple hardware and the use of EFI, Apple stores relevant information within EFI to aid in the functionality of OS X. For example, the FileVault key is stored in EFI to transparently come out of standby mode.

> Organizations especially sensitive to a high-attack environment, or potentially exposed to full device access when the device is in standby mode, should mitigate this risk by destroying the FileVault key in firmware. Doing so doesn’t destroy the use of FileVault, but simply requires the user to enter the password in order for the system to come out of standby mode.

For more information, see [Best Practices for
Deploying FileVault 2](http://training.apple.com/pdf/WP_FileVault2.pdf) [pdf]

and paper [Lest We Remember: Cold Boot Attacks on Encryption Keys](https://www.usenix.org/legacy/event/sec08/tech/full_papers/halderman/halderman.pdf) [pdf]

## Firmware password

Setting a firmware password in OS X prevents your Mac from starting up from any device other than your startup disk. [It can also be helpful if your laptop is stolen](https://www.ftc.gov/news-events/blogs/techftc/2015/08/virtues-strong-enduser-device-controls), as the only way to reset the firmware password is through an Apple Store ([or is it?](https://reverse.put.as/2015/05/29/the-empire-strikes-back-apple-how-your-mac-firmware-security-is-completely-broken/)).

1. Start up holding the `Command` and `R` keys to boot from **OS X Recovery** mode.

3. When the Recovery window appears, choose **Firmware Password Utility** from the Utilities menu.

4. In the Firmware Utility window that appears, select **Turn On Firmware Password**.

5. Enter a new password, then enter the same password in the Verify field.

6. Select Set Password.

7. Select Quit Firmware Utility to close the Firmware Password Utility.

8. Select the Apple menu and choose Restart or Shutdown.

The firmware password will activate at next boot. To validate the password, hold `alt` during boot - you should be prompted to enter the password.

## Firewall
Before connecting to the Internet, it's a good idea to first configure a firewall.

There are several types of firewall for OS X.

#### Application layer firewall
Built-in, basic firewall which blocks **incoming** connections only.

Note, this firewall does not have the ability to monitor, nor block **outgoing** connections.

It can be controlled by the **Firewall** tab of **Security & Privacy** in **System Preferences**, or with the following commands.

Enable the firewall:

    sudo defaults write /Library/Preferences/com.apple.alf globalstate -bool true

Enable logging:

    sudo defaults write /Library/Preferences/com.apple.alf loggingenabled -bool true

You may also wish to enable stealth mode:

    sudo defaults write /Library/Preferences/com.apple.alf stealthenabled -bool true

> Computer hackers scan networks so they can attempt to identify computers to attack. You can prevent your computer from responding to some of these scans by using **stealth mode**. When stealth mode is enabled, your computer does not respond to ICMP ping requests, and does not answer to connection attempts from a closed TCP or UDP port. This makes it more difficult for attackers to find your computer.

Finally, you may wish to disable feature, *Automatically allow signed software to receive incoming connections*.

    sudo defaults write /Library/Preferences/com.apple.alf allowsignedenabled -bool false

> Applications that are signed by a valid certificate authority are automatically added to the list of allowed apps, rather than prompting the user to authorize them. Apps included in OS X are signed by Apple and are allowed to receive incoming connections when this setting is enabled. For example, since iTunes is already signed by Apple, it is automatically allowed to receive incoming connections through the firewall.
>
> If you run an unsigned app that is not listed in the firewall list, a dialog appears with options to Allow or Deny connections for the app. If you choose Allow, OS X signs the application and automatically adds it to the firewall list. If you choose Deny, OS X adds it to the list but denies incoming connections intended for this app.

#### Third party firewalls
Programs such as [Little Snitch](https://www.obdev.at/products/littlesnitch/index.html), [Hands Off](https://www.oneperiodic.com/products/handsoff/) and [Radio Silence](http://radiosilenceapp.com/) provide a good balance of usability and security.

<img width="349" alt="Example of Little Snitch monitored session" src="https://cloud.githubusercontent.com/assets/12475110/10596588/c0eed3c0-76b3-11e5-95b8-9ce7d51b3d82.png">

*Example of Little Snitch-monitored session*

These programs are capable of monitoring and blocking **incoming** and **outgoing** network connections. However, they may require the use of a closed source [kernel extension](https://developer.apple.com/library/mac/documentation/Darwin/Conceptual/KernelProgramming/Extend/Extend.html).

If the number of choices of allowing/blocking network connections is overwhelming, use **Silent Mode** with connections allowed, then periodically check your settings to gain understanding of what various applications are doing.

It is worth noting that these firewalls can be bypassed by programs running as **root** or through [OS vulnerabilities](https://www.blackhat.com/docs/us-15/materials/us-15-Wardle-Writing-Bad-A-Malware-For-OS-X.pdf) [pdf], but they are still worth having - just don't expect absolute protection.

#### Kernel level packet filtering
A highly customizable, powerful, but also most complicated firewall exists in the kernel. It can be controlled with `pfctl` and various configuration files.

pf also be controlled with a GUI application such as [IceFloor](http://www.hanynet.com/icefloor/) or [Murus](http://www.murusfirewall.com/).

There are many books and articles on the subject of pf firewall. Here's is just one example of blocking traffic by IP address.

Put the following into a file called `pf.rules`

    set block-policy drop
    set fingerprints "/etc/pf.os"
    set ruleset-optimization basic
    set skip on lo0
    scrub in all no-df
    table <blocklist> persist
    block in log
    block in log quick from no-route to any
    pass out proto tcp from any to any keep state
    pass out proto udp from any to any keep state
    block log on en0 from {<blocklist>} to any

Use the following commands

* `sudo pfctl -e -f pf.rules` to enable the firewall
* `sudo pfctl -d` to disable the firewall
* `sudo pfctl -t blocklist -T add 1.2.3.4` to add hosts to a blocklist
* `sudo pfctl -t blocklist -T show` to view the blocklist
* `sudo ifconfig pflog0 create` to create an interface for logging
* `sudo tcpdump -ni pflog0` to dump the packets

Unless you're already familiar with packet filtering, spending too much time configuring pf is not recommended. It is also probably unnecessary if your Mac is behind a [NAT](https://www.grc.com/nat/nat.htm) on a secured home network, for example.

For an example of using pf to audit "phone home" behavior of user and system-level processes, see [fix-macosx/net-monitor](https://github.com/fix-macosx/net-monitor).

## Services
Before you connect to the Internet, you may wish to disable some system services, which use up resources or phone home to Apple.

See [fix-macosx/yosemite-phone-home](https://github.com/fix-macosx/yosemite-phone-home) and [l1k/osxparanoia](https://github.com/l1k/osxparanoia)

Services on OS X are managed by **launchd**. See <http://launchd.info/>, as well as [Apple's Daemons and Services Programming Guide](https://developer.apple.com/library/mac/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html) and [Technical Note TN2083](https://developer.apple.com/library/mac/technotes/tn2083/_index.html)

You can also run [KnockKnock](https://github.com/synack/knockknock) that shows more information about startup items.

* Use `launchctl list` to view running user agents
* Use `sudo launchctl list` to view running system daemons
* Specify the service name to examine it, e.g. `launchctl list com.apple.Maps.mapspushd`
* Use `defaults read` to examine job plists in `/System/Library/LaunchDaemons` and `/System/Library/LaunchAgents`
* Use `man`, `strings` and Google to learn about what the agent/daemon runs

For example, to learn what a system launch daemon or agent does, start with

	defaults read /System/Library/LaunchDaemons/com.apple.apsd.plist

Look at the `Program` or `ProgramArguments` section to see which binary is run, in this case `apsd`. To find more information about that, look at the man page with `man apsd`

If you're not interested in Apple Push Notifications, disable the service

	sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.apsd.plist

**Note** Unloading services may break usability of some applications. Read the manual pages and use Google to make sure you understand what you're doing first.

Be careful about disabling any system daemons you don't understand, as it may render your system unbootable. If you break your Mac, use [single user mode](https://support.apple.com/en-us/HT201573) to fix it.

Use [Console](https://en.wikipedia.org/wiki/Console_(OS_X)) and [Activity Monitor](https://support.apple.com/en-us/HT201464) applications if you notice your Mac heating up, feeling slugging, or generally misbehaving, as it may have resulted from your tinkering.

To view currently disabled services,

    find /var/db/com.apple.xpc.launchd/ -type f -print -exec defaults read {} \; 2>/dev/null

Annotated lists of launch daemons and agents, the respective program executed, and the programs' hash sums are included in this repository.

You may run the `read_launch_plists.py` script and `diff` output to check for any discrepancies on your system, e.g.:

    diff <(python read_launch_plists.py) <(cat 14F27_launchd.csv)

See also [cirrusj.github.io/Yosemite-Stop-Launch](http://cirrusj.github.io/Yosemite-Stop-Launch/) for descriptions of services.

## Spotlight Suggestions
Disable “Spotlight Suggestions” in both the Spotlight preferences and Safari's Search preferences to avoid your search queries being sent to Apple.

Also disable "Bing Web Searches" in the Spotlight preferences to avoid your search queries being sent to Microsoft.

See <https://fix-macosx.com/> for detailed instructions.

> If you've upgraded to Mac OS X Yosemite (10.10) and you're using the default settings, each time you start typing in Spotlight (to open an application or search for a file on your computer), your local search terms and location are sent to Apple and third parties (including Microsoft).

Speaking of Microsoft, you may want to see <https://fix10.isleaked.com/> just for fun.

## Homebrew
Consider using [Homebrew](http://brew.sh/) to make software installations easier and to update userland tools (see [Apple’s great GPL purge](http://meta.ath0.com/2012/02/05/apples-great-gpl-purge/)).

If you have not already installed Xcode or Command Line Tools, run `xcode-select --install` and a prompt should appear to download and install CLI Tools.

Homebrew can be easily installed with

    ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"

or have a look at [homebrew/Installation.md](https://github.com/Homebrew/homebrew/blob/master/share/doc/homebrew/Installation.md#installation) for other installation options.

Homebrew uses SSL/TLS to talk with github and verifies checksums of downloaded packages, so it's [fairly secure](https://github.com/Homebrew/homebrew/issues/18036).

Alternatively, you could download, compile and install software directly from their respective open source repositories.

Remember to periodically run `brew update` and `brew upgrade` on trusted, secure networks to install software updates.

## DNS

#### Hosts file
Use the [hosts file](https://en.wikipedia.org/wiki/Hosts_(file)) to block known malware, advertising or otherwise unwanted domains.

Edit the hosts file as root, for example with `sudo vi /etc/hosts`. The hosts file can also be managed with the GUI app [2ndalpha/gasmask](https://github.com/2ndalpha/gasmask).

To block a domain, just add `0 facebook.com` (`0` means `0.0.0.0`, a null route)

There are many lists of domains available online which you can paste in, just make sure each line starts with `0` or `127.0.0.1`, and the line `127.0.0.1 localhost` is included.

For hosts lists, see [someonewhocares.org](http://someonewhocares.org/hosts/zero/hosts), [l1k/osxparanoia/blob/master/hosts](https://github.com/l1k/osxparanoia/blob/master/hosts), [StevenBlack/hosts](https://github.com/StevenBlack/hosts) and [gorhill/uMatrix/hosts-files.json](https://github.com/gorhill/uMatrix/blob/master/assets/umatrix/hosts-files.json).

#### dnsmasq

Among other features, [dnsmasq](http://www.thekelleys.org.uk/dnsmasq/doc.html) is able to cache replies, prevent upstreaming queries for unqualified names, and block entire TLDs.

Use in combination with `dnscrypt` to additionally encrypt outgoing DNS traffic.

If you don't wish to use `dnscrypt`, you should at least use DNS [not provided](http://bcn.boulder.co.us/~neal/ietf/verisign-abuse.html) [by your ISP](http://hackercodex.com/guide/how-to-stop-isp-dns-server-hijacking/). Two popular alternatives are [Google DNS](https://developers.google.com/speed/public-dns/) and [OpenDNS](https://www.opendns.com/home-internet-security/).

[DNSSEC](https://en.wikipedia.org/wiki/Domain_Name_System_Security_Extensions) is a set of extensions to DNS which provide to DNS clients (resolvers) origin authentication of DNS data, authenticated denial of existence, and data integrity. All answers from DNSSEC protected zones are digitally signed. The signed records are authenticated via a chain of trust, starting with a set of verified public keys for the DNS root-zone. The current root-zone trust anchors may be downloaded [from IANA website](https://www.iana.org/dnssec/files). There are a number of resources on DNSSEC, but probably the best one is [dnssec.net website](http://www.dnssec.net).

Install dnsmasq:

    brew install dnsmasq --with-dnssec

    mkdir -p /usr/local/etc

    cp /usr/local/opt/dnsmasq/dnsmasq.conf.example /usr/local/etc/dnsmasq.conf
    
Edit the configuration:

    vim /usr/local/etc/dnsmasq.conf

Have a look through the commented-out options. Here are a few recommended settings to enable:

    # Forward queries to dnscrypt on localhost
    server=127.0.0.1#5355

    # Never forward plain names
    domain-needed

    # Examples of blocking TLDs or subdomains
    address=/.onion/0.0.0.0
    address=/.local/0.0.0.0
    address=/.mycoolnetwork/0.0.0.0
    address=/.facebook.com/0.0.0.0

    # Never forward addresses in the non-routed address spaces
    bogus-priv

    # Reject private addresses from upstream nameservers
    stop-dns-rebind

    # Query servers in order
    strict-order

    # Set the size of the cache
    # The default is to keep 150 hostnames
    cache-size=8192

    # Optional logging directives
    log-async
    log-dhcp
    log-queries
    log-facility=/var/log/dnsmasq.log

    # DNSSEC options
    dnssec
    trust-anchor=.,19036,8,2,49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5
    dnssec-check-unsigned

Install and start the program:

    sudo cp -fv /usr/local/opt/dnsmasq/*.plist /Library/LaunchDaemons

    sudo chown root /Library/LaunchDaemons/homebrew.mxcl.dnsmasq.plist

    sudo launchctl load /Library/LaunchDaemons/homebrew.mxcl.dnsmasq.plist

Open **System Preferences** > **Network** and select the active interface, then the **DNS** tab, select **+** and add `127.0.0.1` as a DNS server, or use the command:

    sudo networksetup -setdnsservers "Wi-Fi" 127.0.0.1

Make sure `dnsmasq` is running with `sudo lsof -ni UDP:53` and is correctly configured with `scutil` or `networksetup`:

    $ scutil --dns
    DNS configuration

    resolver #1
      search domain[0] : mycoolnetwork
      nameserver[0] : 127.0.0.1
      flags    : Request A records, Request AAAA records
      reach    : Reachable,Local Address

    $ networksetup -getdnsservers "Wi-Fi"
    127.0.0.1

**Note** Some VPN software overrides DNS settings on connect. See [issue #24](https://github.com/drduh/OS-X-Security-and-Privacy-Guide/issues/24) for more information.

##### Test DNSSEC validation

Test DNSSEC validation succeeds for signed zones:

    $ dig +dnssec icann.org

Reply should have `NOERROR` status and contain `ad` flag. For instance,

    ;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 47039
    ;; flags: qr rd ra ad; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 1

Test DNSSEC validation fails for zones that are signed improperly:

    $ dig www.dnssec-failed.org

Reply should have `SERVFAIL` status. For instance,

    ;; ->>HEADER<<- opcode: QUERY, status: SERVFAIL, id: 15190
    ;; flags: qr rd ra; QUERY: 1, ANSWER: 0, AUTHORITY: 0, ADDITIONAL: 1

#### dnscrypt

Use [dnscrypt](https://dnscrypt.org/) to encrypt DNS traffic to the provider of choice.

If you prefer a GUI application, see [alterstep/dnscrypt-osxclient](https://github.com/alterstep/dnscrypt-osxclient).

Install the program:

    brew install dnscrypt-proxy

    sudo cp -fv /usr/local/opt/dnscrypt-proxy/*.plist /Library/LaunchDaemons

    sudo chown root /Library/LaunchDaemons/homebrew.mxcl.dnscrypt-proxy.plist

If using in combination with `dnsmasq`, edit `/Library/LaunchDaemons/homebrew.mxcl.dnscrypt-proxy.plist` to have this line:

    <string>--local-address=127.0.0.1:5355</string>

Below the line:

    <string>/usr/local/opt/dnscrypt-proxy/sbin/dnscrypt-proxy</string>

<img width="916" alt="dnscrypt" src="https://cloud.githubusercontent.com/assets/12475110/10596750/94644540-76b5-11e5-8ddb-15c0130f7827.png">

*Append a local-address line to use dnscrypt on a port other than 53, like 5355.*

By default, the `resolvers-list` will point to the dnscrypt version specific resolvers file. When dnscrypt is updated, this version may no longer exist, and if it does, may point to an outdated file. This can be fixed by changing the resolvers file in `/Library/LaunchDaemons/homebrew.mxcl.dnscrypt-proxy.plist` to the symlinked version in `/usr/local/share`:

    <string>--resolvers-list=/usr/local/share/dnscrypt-proxy/dnscrypt-resolvers.csv</string>

Start the program:

    sudo launchctl load /Library/LaunchDaemons/homebrew.mxcl.dnscrypt-proxy.plist

Make sure `dnscrypt` is running with `sudo lsof -ni UDP:5355` or `ps -ef | grep '[d]nscrypt'`

> By default, dnscrypt-proxy runs on localhost (127.0.0.1), port 53,
and under the "nobody" user using the dnscrypt.eu-dk DNSCrypt-enabled
resolver. If you would like to change these settings, you will have to edit the plist file (e.g., --resolver-address, --provider-name, --provider-key, etc.)

This can be accomplished by editing `/Library/LaunchDaemons/homebrew.mxcl.dnscrypt-proxy.plist`.

You can run your own [dnscrypt server](https://github.com/Cofyc/dnscrypt-wrapper) from a trusted location or use one of many [public servers](https://github.com/jedisct1/dnscrypt-proxy/blob/master/dnscrypt-resolvers.csv) instead.

Confirm outgoing dns traffic is encrypted:

    $ sudo tcpdump -qtni en0
    IP 10.8.8.8.59636 > 77.66.84.233.443: UDP, length 512
    IP 77.66.84.233.443 > 10.8.8.8.59636: UDP, length 368

    $ dig +short -x 77.66.84.233
    resolver2.dnscrypt.eu

See also [What is a DNS leak and why should I care?](https://dnsleaktest.com/what-is-a-dns-leak.html) and the [mDNSResponder manual page](https://developer.apple.com/library/mac/documentation/Darwin/Reference/ManPages/man8/mDNSResponder.8.html). Precise test: [ipv6-test.com](http://ipv6-test.com/).

## Captive portal

When OS X connects to new networks, it **probes** the network and launches a Captive Portal assistant utility if connectivity can't be determined.

An attacker could trigger the utility and direct a Mac to a site with malware without user interaction, so it's best to disable this feature and log in to captive portals using your regular Web browser, provided you have first disable any custom dns and/or proxy settings.

    sudo defaults write /Library/Preferences/SystemConfiguration/com.apple.captive.control Active -bool false

See also [Apple OS X Lion Security: Captive Portal Hijacking Attack](https://www.securestate.com/blog/2011/10/07/apple-os-x-lion-captive-portal-hijacking-attack), [Apple's secret "wispr" request](http://blog.erratasec.com/2010/09/apples-secret-wispr-request.html), [How to disable the captive portal window in Mac OS Lion](https://web.archive.org/web/20130407200745/http://www.divertednetworks.net/apple-captiveportal.html), and [An undocumented change to Captive Network Assistant settings in OS X 10.10 Yosemite](https://grpugh.wordpress.com/2014/10/29/an-undocumented-change-to-captive-network-assistant-settings-in-os-x-10-10-yosemite/).

## Certificate authorities
OS X El Capitan comes with [over 200 root certificate authorities](https://support.apple.com/en-us/HT205204) from for-profit corporations like Apple, Verisign, Thawte, Digicert and government agencies from China, Japan, Netherlands, U.S., and more! These CAs are capable of issuing SSL certificates for any domain or code signing certificates as well.

For more information, see [Certification Authority Trust Tracker](https://github.com/kirei/catt), [Analysis of the HTTPS certificate ecosystem](http://conferences.sigcomm.org/imc/2013/papers/imc257-durumericAemb.pdf) [pdf], and [You Won’t Be Needing These Any More: On Removing Unused Certificates From Trust Stores](http://www.ifca.ai/fc14/papers/fc14_submission_100.pdf) [pdf].

You can inspect system root certificates in **Keychain Access**, under the **System Roots** tab or by using the `security` command line tool and `/System/Library/Keychains/SystemRootCertificates.keychain` file.

You can disable certificate authorities through Keychain Access by marking them as **Never Trust**.

The risk of a [man in the middle](https://en.wikipedia.org/wiki/Man-in-the-middle_attack) attack in which a coerced or compromised certificate authority trusted by your system issues a fake/rogue SSL certificate is quite low, but still [possible](https://en.wikipedia.org/wiki/DigiNotar#Issuance_of_fraudulent_certificates).

## OpenSSL

The version of `openssl` in El Capitan is `0.9.8zg` which is [not current](https://apple.stackexchange.com/questions/200582/why-is-apple-using-an-older-version-of-openssl). It doesn't support TLS 1.1 or newer, elliptic curve ciphers, and [more](https://stackoverflow.com/questions/27502215/difference-between-openssl-09-8z-and-1-0-1).

Apple claims OpenSSL is **deprecated** in their [Cryptographic Services Guide](https://developer.apple.com/library/mac/documentation/Security/Conceptual/cryptoservices/GeneralPurposeCrypto/GeneralPurposeCrypto.html) document. Their version also has patches which may [surprise you](https://hynek.me/articles/apple-openssl-verification-surprises/).

Grab a recent version of OpenSSL with `brew install openssl`. Note, linking brew to be used in favor of `/usr/bin/openssl` may interfere with building software. See [issue #39](https://github.com/drduh/OS-X-Security-and-Privacy-Guide/issues/39).

For example, compare the TLS protocol and cipher between the homebrew version and the system version of OpenSSL,

    $ openssl version; echo | openssl s_client -connect github.com:443 2>&1 | grep -A2 SSL-Session
    OpenSSL 1.0.2d 9 Jul 2015
    SSL-Session:
        Protocol  : TLSv1.2
        Cipher    : ECDHE-RSA-AES128-GCM-SHA256

    $ ^openssl^/usr/bin/openssl
    OpenSSL 0.9.8zg 14 July 2015
    SSL-Session:
        Protocol  : TLSv1
        Cipher    : AES128-SHA

Also see [Comparison of TLS implementations](https://en.wikipedia.org/wiki/Comparison_of_TLS_implementations), [How's My SSL](https://www.howsmyssl.com/), as well as [Qualys SSL Labs Tools](https://www.ssllabs.com/projects/).

## Curl

The version of `curl` which comes with OS X uses [Secure Transport](https://developer.apple.com/library/mac/documentation/Security/Reference/secureTransportRef/) for SSL/TLS validation.

If you prefer to use OpenSSL, install with `brew install curl --with-openssl` and ensure it's the default with `brew link --force curl`

Here are several recommended [options](http://curl.haxx.se/docs/manpage.html) to add to `~/.curlrc` (see `man curl` for more):

    user-agent = "Mozilla/5.0 (Windows NT 6.1; rv:31.0) Gecko/20100101 Firefox/31.0"
    referer = ";auto"
    connect-timeout = 10
    progress-bar
    max-time = 90
    verbose
    show-error
    remote-time
    ipv4

## HTTP
Consider using [privoxy](http://www.privoxy.org/) as a local proxy to sanitize and customize web browsing traffic.

A signed installation package for privoxy can be downloaded from [Sourceforge](http://sourceforge.net/projects/ijbswa/files/Macintosh%20%28OS%20X%29/) or [silvester.org.uk](http://silvester.org.uk/privoxy/OSX/). The signed package is [more secure](https://github.com/drduh/OS-X-Security-and-Privacy-Guide/issues/65) than the Homebrew version, and attracts full support from the Privoxy project.

Alternatively, install and start privoxy using Homebrew:

    brew install privoxy

    ln -sfv /usr/local/opt/privoxy/*.plist ~/Library/LaunchAgents

    launchctl load ~/Library/LaunchAgents/homebrew.mxcl.privoxy.plist

By default, privoxy listens on local TCP port 8118.

Set the system **http** proxy for your active network interface `127.0.0.1` and `8118`. This can be done through **System Preferences > Network > Advanced > Proxies**, or

    sudo networksetup -setwebproxy "Wi-Fi" 127.0.0.1 8118

Optionally, you can set the system **https** proxy, which allows for domain name filtering, with

    sudo networksetup -setsecurewebproxy "Wi-Fi" 127.0.0.1 8118

Confirm the proxy is set with the command `scutil --proxy`. You can also visit <http://p.p/> in a web browser, or use

    ALL_PROXY=127.0.0.1:8118 curl -I http://p.p/

Privoxy already comes with many good rules, however you can also write your own.

Edit `/usr/local/etc/privoxy/user.action` to filter elements by domain or with regular expressions, e.g.:

    { +block{unwanted stuff} }
    www.facebook.com/(extern|plugins)/(login_status|like(box)?|activity|fan)\.php
    .foxnews.com
    /cleardot.gif
    /.*linkedin.*

    { +block{ad images} +handle-as-image }
    /.*1x1.gif
    /.*fb-icon.*
    /assets/social-.*
    /img/social.*

    { +redirect{s@http://@https://@} }
    .google.com
    code.jquery.com
    imgur.com
    .wikipedia.org

You can even replace ad images with pictures of kittens by starting the a local web server and redirecting blocked privoxy requests to `127.0.0.1`.

Consider logging and monitoring privoxy requests so you can be inspired to write custom rules.

## Web browsing
The web browser poses the largest security and privacy risk, as its fundamental job is to download and execute untrusted code from the Internet.

Use [Google Chrome](https://www.google.com/chrome/browser/desktop/) for most of your browsing. It offers [separate profiles](https://www.chromium.org/user-experience/multi-profiles), [good sandboxing](https://www.chromium.org/developers/design-documents/sandbox), [frequent updates](http://googlechromereleases.blogspot.com/) (including Flash, although you should disable it - see below), and carries [impressive credentials](https://www.chromium.org/Home/chromium-security/brag-sheet).

Chrome also comes with a great [PDF viewer](http://0xdabbad00.com/2013/01/13/most-secure-pdf-viewer-chrome-pdf-viewer/).

If you don't want to use Chrome, [Firefox](https://www.mozilla.org/en-US/firefox/new/) is an excellent browser as well. Or simply use both. See discussion in issues [#2](https://github.com/drduh/OS-X-Security-and-Privacy-Guide/issues/2), [#90](https://github.com/drduh/OS-X-Security-and-Privacy-Guide/issues/90).

If using Firefox, see [TheCreeper/PrivacyFox](https://github.com/TheCreeper/PrivacyFox) for recommended privacy preferences. Also be sure to check out [NoScript](https://noscript.net/) for Mozilla-based browsers, which allows whitelist-based, pre-emptive script blocking.

Create at least three profiles, one for browsing **trusted** web sites (email, banking), another for **untrusted** (link aggregators, news sites), and a third for a completely **cookie-less** and **script-less** experience.

* One profile **without cookies or Javascript** enabled (e.g., turned off in `chrome://settings/content`) which should be the preferred profile to visiting untrusted web sites. However, many pages will not load at all without Javascript enabled.

* One profile with [uMatrix](https://github.com/gorhill/uMatrix) (or [uBlock](https://github.com/chrisaljoudi/uBlock), a simpler version). Use this profile for visiting **mostly trusted** web sites. Take time to learn how these firewall extensions work. Other frequently recommended extensions are [Privacy Badger](https://www.eff.org/privacybadger), [HTTPSEverywhere](https://www.eff.org/https-everywhere) and [CertPatrol](http://patrol.psyced.org/) (Firefox only).

* One (or more) profile(s) for your "real name", signed-in browsing needs such as banking and email (however, don't open email links from this profile).

The idea is to separate and compartmentalize your data, so that an exploit or privacy violation in one session does not necessarily affect data in another.

In each profile, visit `chrome://plugins/` and disable **Adobe Flash Player**. If you must use Flash, visit `chrome://settings/contents` to enable **Let me choose when to run plugin content**, under the Plugins section (also known as *click-to-play*).

Take some time to read through [Chromium Security](https://www.chromium.org/Home/chromium-security) and [Chromium Privacy](https://www.chromium.org/Home/chromium-privacy).

For example you may wish to disable [DNS prefetching](https://www.chromium.org/developers/design-documents/dns-prefetching) (see also [DNS Prefetching and Its Privacy Implications](https://www.usenix.org/legacy/event/leet10/tech/full_papers/Krishnan.pdf) [pdf]).

Also be aware of [WebRTC](https://en.wikipedia.org/wiki/WebRTC#Concerns), which may reveal your local or public (if connected to VPN) IP address(es). This can be disabled with extensions such as [uBlock Origin](https://github.com/gorhill/uBlock/wiki/Prevent-WebRTC-from-leaking-local-IP-address) and [rentamob/WebRTC-Leak-Prevent](https://github.com/rentamob/WebRTC-Leak-Prevent).

Chromium-derived browsers are not recommended. They are usually [closed source](http://yro.slashdot.org/comments.pl?sid=4176879&cid=44774943), [poorly maintained](https://plus.google.com/+JustinSchuh/posts/69qw9wZVH8z), [have bugs](https://code.google.com/p/google-security-research/issues/detail?id=679), and make dubious claims to protect privacy. See [The Private Life of Chromium Browsers](http://thesimplecomputer.info/the-private-life-of-chromium-browsers).

Safari is not recommended. The code is a mess and [security](https://nakedsecurity.sophos.com/2014/02/24/anatomy-of-a-goto-fail-apples-ssl-bug-explained-plus-an-unofficial-patch/) [vulnerabilities](https://vimeo.com/144872861) are frequent, and slower to patch (see [discussion on Hacker News](https://news.ycombinator.com/item?id=10150038)). Security does [not appear](https://discussions.apple.com/thread/5128209) to be a priority for Safari. If you do use it, at least [disable](https://thoughtsviewsopinions.wordpress.com/2013/04/26/how-to-stop-downloaded-files-opening-automatically/) the **Open "safe" files after downloading** option in Preferences, and be aware of other [privacy nuances](https://github.com/drduh/OS-X-Security-and-Privacy-Guide/issues/93).

For more information about security conscious browsing, see [HowTo: Privacy & Security Conscious Browsing](https://gist.github.com/atcuno/3425484ac5cce5298932), [browserleaks.com](https://www.browserleaks.com/) and [EFF Panopticlick](https://panopticlick.eff.org/).

## Plugins
**Adobe Flash**, **Oracle Java**, **Adobe Reader**, **Microsoft Silverlight** (Netflix now works with [HTML5](https://help.netflix.com/en/node/23742)) and other plugins are [security risks](https://news.ycombinator.com/item?id=9901480) and should not be installed.

If they are necessary, only use them in a disposable virtual machine and subscribe to security announcements to make sure you're always patched.

See [Hacking Team Flash Zero-Day](http://blog.trendmicro.com/trendlabs-security-intelligence/hacking-team-flash-zero-day-integrated-into-exploit-kits/), [Java Trojan BackDoor.Flashback](https://en.wikipedia.org/wiki/Trojan_BackDoor.Flashback), [Acrobat Reader: Security Vulnerabilities](http://www.cvedetails.com/vulnerability-list/vendor_id-53/product_id-497/Adobe-Acrobat-Reader.html), and [Angling for Silverlight Exploits](https://blogs.cisco.com/security/angling-for-silverlight-exploits), for example.

## PGP/GPG
PGP is a standard for encrypting email end to end. That means only the chosen recipients can decrypt a message, unlike regular email which is read and forever archived by providers.

**GPG**, or **GNU Privacy Guard**, is a GPL licensed program compliant with the standard.

**GPG** is used to verify signatures of software you download and install, as well as [symmetrically](https://en.wikipedia.org/wiki/Symmetric-key_algorithm) or [asymmetrically](https://en.wikipedia.org/wiki/Public-key_cryptography) encrypt files and text.

Install with `brew install gnupg`, or if you prefer to install a newer, more feature-rich [stable version](https://www.gnupg.org/), use `brew install homebrew/versions/gnupg21`

If you prefer a GUI, check out [GPG Suite](https://gpgtools.org/)

Here are several recommended options to add to `~/.gnupg/gpg.conf`

    auto-key-locate keyserver
    keyserver hkps://hkps.pool.sks-keyservers.net
    keyserver-options no-honor-keyserver-url
    keyserver-options ca-cert-file=/etc/sks-keyservers.netCA.pem
    keyserver-options no-honor-keyserver-url
    keyserver-options debug
    keyserver-options verbose
    personal-cipher-preferences AES256 AES192 AES CAST5
    personal-digest-preferences SHA512 SHA384 SHA256 SHA224
    default-preference-list SHA512 SHA384 SHA256 SHA224 AES256 AES192 AES CAST5 ZLIB BZIP2 ZIP Uncompressed
    cert-digest-algo SHA512
    s2k-digest-algo SHA512
    charset utf-8
    fixed-list-mode
    no-comments
    no-emit-version
    keyid-format 0xlong
    list-options show-uid-validity
    verify-options show-uid-validity
    with-fingerprint

Install the keyservers CA certificate

    curl -O https://sks-keyservers.net/sks-keyservers.netCA.pem

    sudo mv sks-keyservers.netCA.pem /etc

These settings will configure GnuPG to use SSL when fetching new keys and prefer strong cryptographic primitives.

See also [ioerror/duraconf/configs/gnupg/gpg.conf](https://github.com/ioerror/duraconf/blob/master/configs/gnupg/gpg.conf). You should also take some time to read [OpenPGP Best Practices](https://help.riseup.net/en/security/message-security/openpgp/best-practices).

If you don't already have a keypair, create one using `gpg --gen-key`. Also see [drduh/YubiKey-Guide](https://github.com/drduh/YubiKey-Guide).

Read [online](https://alexcabal.com/creating-the-perfect-gpg-keypair/) [guides](https://security.stackexchange.com/questions/31594/what-is-a-good-general-purpose-gnupg-key-setup) and practice encrypting and decrypting email to yourself and your friends. Get them interested in this stuff!

## OTR
OTR stands for **off-the-record** and is a cryptographic protocol for encrypting and authenticating conversations over instant messaging.

You can use OTR on top of any existing **XMPP** chat service, even Google Hangouts (which only encrypts conversations between users and the server).

The first time you start a conversation with someone new, you'll be asked to verify their public key fingerprint. Make sure to do this in person or by some other secure means (e.g. GPG encrypted mail).

A popular OS X GUI client for XMPP and other chat protocols is [Adium](https://adium.im/)

Consider downloading the [beta version](https://beta.adium.im/) which uses OAuth2, making logging in to Google Talk/Hangouts [more](https://adium.im/blog/2015/04/) [secure](https://trac.adium.im/ticket/16161).

    Adium_1.5.11b3.dmg

    SHA-256: 999e1931a52dc327b3a6e8492ffa9df724a837c88ad9637a501be2e3b6710078
    SHA-1:   ca804389412f9aeb7971ade6812f33ac739140e6

Remember to [disable logging](https://trac.adium.im/ticket/15722) for OTR chats with Adium.

A good console-based XMPP client is [profanity](http://www.profanity.im/)  which can be installed with `brew install profanity`

For improved anonymity, check out [Tor Messenger](https://blog.torproject.org/blog/tor-messenger-beta-chat-over-tor-easily), although it is still in beta, as well as [Ricochet](https://ricochet.im/) (which has recently received a thorough [security audit](https://ricochet.im/files/ricochet-ncc-audit-2016-01.pdf) [pdf]), which both use the Tor network rather than relying on messaging servers.

If you want to know how OTR works, read the paper [Off-the-Record Communication, or, Why Not To Use PGP](https://otr.cypherpunks.ca/otr-wpes.pdf) [pdf]

## Tor
Tor is an anonymizing proxy which can be used for browsing the web.

Download Tor Browser from <https://www.torproject.org/projects/torbrowser.html>.

Do **not** attempt to configure other browsers to use Tor as you are likely make a mistake which will compromise your anonymity.

After downloading the `dmg` and `asc` files, verify the disk image has been signed by Tor developers with `gpg TorBrowser*asc`

You may see a warning - the public key was not found. Fetch it from the keyserver with `gpg --recv-keys 0x2E1AC68ED40814E0` and verify again.

Make sure `Good signature from "Tor Browser Developers (signing key) <torbrowser@torproject.org>"` appears in the output. You may see a benign warning if the key has not been manually assigned trust.

<img width="872" alt="Example of valid signature output" src="https://cloud.githubusercontent.com/assets/12475110/10712417/e7485bb4-7a68-11e5-9bdb-e27bdd3742fd.png">

*Example of valid signature output*

See [How to verify signatures for packages](https://www.torproject.org/docs/verifying-signatures.html) for more information.

Tor traffic is **encrypted** to the [exit node](https://en.wikipedia.org/wiki/Tor_(anonymity_network)#Exit_node_eavesdropping) (i.e., cannot be read by a passive network eavesdropper), but **can** be identified.

Just one example way is by monitoring TLS handshakes:

    $ sudo tcpdump -Ani en0 "tcp" | grep "www"
    .............&.$..!www.ht50d2u6ky6y7kbcxhe5mjfdi.com.........
    .~7...~.|.Lp*e.....L._..........ug.......[.net0.brU.....fP...a&..'.]...r.....E*F....{...qjJ}....).$8....	....V.E..0
    ...................www.s4ku5skci.net.........
    l..5...R[i.0...A.$...l..Ly.....}..ZY..../.........LH.0..\...3.?.........*.N... ..._/G\...0*..?...`d.........0	...X..&.N0
    ^C

See [Tor Protocol Specification](https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt) and [Tor/TLSHistory](https://trac.torproject.org/projects/tor/wiki/org/projects/Tor/TLSHistory) for more information.

You may wish to additionally obfuscate Tor traffic using a [pluggable transport](https://www.torproject.org/docs/pluggable-transports.html), such as [Yawning/obfs4proxy](https://github.com/Yawning/obfs4) or [SRI-CSL/stegotorus](https://github.com/SRI-CSL/stegotorus).

This can be done by setting up your own [Tor relay](https://www.torproject.org/docs/tor-relay-debian.html) or finding an existing private or public [bridge](https://www.torproject.org/docs/bridges.html.en#RunningABridge) to serve as an obfuscating entry node.

For extra security, use Tor inside a [VirtualBox](https://www.virtualbox.org/wiki/Downloads) or [VMware](https://www.vmware.com/products/fusion) virtualized [GNU/Linux](http://www.brianlinkletter.com/installing-debian-linux-in-a-virtualbox-virtual-machine/) or [BSD](http://www.openbsd.org/faq/faq4.html) machine.

Finally, remember the Tor network provides [anonymity](https://www.privateinternetaccess.com/blog/2013/10/how-does-privacy-differ-from-anonymity-and-why-are-both-important/), which is not necessarily synonymous with privacy. The Tor network does not guarantee protection against a global observer capable of traffic analysis and [correlation](https://blog.torproject.org/category/tags/traffic-correlation). See also [Seeking Anonymity in an Internet Panopticon](http://bford.info/pub/net/panopticon-cacm.pdf) [pdf] and [Traffic Correlation on Tor by Realistic Adversaries](http://www.ohmygodel.com/publications/usersrouted-ccs13.pdf) [pdf].

## VPN
If you use your Mac on untrusted networks - airports, cafes, etc. - your network traffic is being monitored and possibly tampered with.

It is a good idea to use a VPN which encrypts **all** outgoing network traffic (i.e., not **split tunnel**) with a provider you trust. Ideally, that provider is a server in your house or a trustworthy "cloud".

Don't just blindly sign up for a VPN service without understanding the full implications and how your traffic will be routed. If you don't understand how the VPN works or are not familiar with the software used, you are probably better off without it.

When choosing a VPN service or setting up your own, be sure to research the protocols, key exchange algorithms, authentication mechanisms, and type of encryption being used. Some protocols, such as [PPTP](https://en.wikipedia.org/wiki/Point-to-Point_Tunneling_Protocol#Security), should be avoided in favor of [OpenVPN](https://en.wikipedia.org/wiki/OpenVPN), for example.

Some clients may send traffic over the next available interface when VPN is interrupted or disconnected. See [scy/8122924](https://gist.github.com/scy/8122924) for an example on how to allow traffic only over VPN.

## Viruses and malware
There is an ever-increasing amount of Mac malware in the wild. Macs aren't immune from viruses and malicious software!

Some malware comes bundled with both legitimate software, such as the [Java bundling Ask Toolbar](http://www.zdnet.com/article/oracle-extends-its-adware-bundling-to-include-java-for-macs/), and some with illegitimate software, such as [Mac.BackDoor.iWorm](https://docs.google.com/document/d/1YOfXRUQJgMjJSLBSoLiUaSZfiaS_vU3aG4Bvjmz6Dxs/edit?pli=1) bundled with pirated programs.

See [Methods of malware persistence on Mac OS X](https://www.virusbtn.com/pdf/conference/vb2014/VB2014-Wardle.pdf) [pdf] and [Malware Persistence on OS X Yosemite](https://www.rsaconference.com/events/us15/agenda/sessions/1591/malware-persistence-on-os-x-yosemite) to learn about how garden-variety malware functions.

You could periodically run a tool like [Knock Knock](https://github.com/synack/knockknock) to examine persistent applications (e.g. scripts, binaries). But by then, it is probably too late. Maybe applications such as [Block Block](https://objective-see.com/products/blockblock.html) and [Ostiarius](https://objective-see.com/products/ostiarius.html) will help. See warnings and caveats in [issue #90](https://github.com/drduh/OS-X-Security-and-Privacy-Guide/issues/90) first, however.

**Anti-virus** programs are a double-edged sword -- not useful for **advanced** users and will likely increase attack surface against sophisticated threats, however possibly useful for catching "garden variety" malware on **novice** users' Macs. There is also the additional processing overhead to consider.

See [Sophail: Applied attacks against  Antivirus](https://lock.cmpxchg8b.com/sophailv2.pdf) [pdf], [Analysis and Exploitation of an ESET Vulnerability](http://googleprojectzero.blogspot.ro/2015/06/analysis-and-exploitation-of-eset.html), [a trivial Avast RCE](https://code.google.com/p/google-security-research/issues/detail?id=546), [Popular Security Software Came Under Relentless NSA and GCHQ Attacks](https://theintercept.com/2015/06/22/nsa-gchq-targeted-kaspersky/), and [AVG: "Web TuneUP" extension multiple critical vulnerabilities](https://code.google.com/p/google-security-research/issues/detail?id=675).

Therefore, the best anti-virus is **Common Sense 2016**. See more discussion in [issue #44](https://github.com/drduh/OS-X-Security-and-Privacy-Guide/issues/44).

Local privilege escalation bugs are plenty on OS X, so always be careful when downloading and running untrusted programs or trusted programs from third party websites or downloaded over HTTP ([example](http://arstechnica.com/security/2015/08/0-day-bug-in-fully-patched-os-x-comes-under-active-exploit-to-hijack-macs/)).

Have a look at [The Safe Mac](http://www.thesafemac.com/) for past and current Mac security news.

Also check out [Hacking Team](https://www.schneier.com/blog/archives/2015/07/hacking_team_is.html) malware for Mac OS: [root installation for MacOS](https://github.com/hackedteam/vector-macos-root), [Support driver for Mac Agent](https://github.com/hackedteam/driver-macos) and [RCS Agent for Mac](https://github.com/hackedteam/core-macos), which is a good example of advanced malware with capabilities to hide from **userland** (e.g., `ps`, `ls`), for example. For more, see [A Brief Analysis of an RCS Implant Installer](https://objective-see.com/blog/blog_0x0D.html) and [reverse.put.as](https://reverse.put.as/2016/02/29/the-italian-morons-are-back-what-are-they-up-to-this-time/)

## System Integrity Protection

[System Integrity Protection](https://support.apple.com/en-us/HT204899) (SIP) is a new security feature of OS X 10.11. It is enabled by default, but [can be disabled](https://derflounder.wordpress.com/2015/10/01/system-integrity-protection-adding-another-layer-to-apples-security-model/), which may be necessary to change some system settings, such as deleting root certificate authorities or unloading certain launch daemons.

From [What's New in OS X 10.11](https://developer.apple.com/library/prerelease/mac/releasenotes/MacOSX/WhatsNewInOSX/Articles/MacOSX10_11.html):

> A new security policy that applies to every running process, including privileged code and code that runs out of the sandbox. The policy extends additional protections to components on disk and at run-time, only allowing system binaries to be modified by the system installer and software updates. Code injection and runtime attachments to system binaries are no longer permitted.

Also see [What is the “rootless” feature in El Capitan, really?](https://apple.stackexchange.com/questions/193368/what-is-the-rootless-feature-in-el-capitan-really)

## Gatekeeper and XProtect

**Gatekeeper** and the **quarantine** system try to prevent unsigned or "bad" programs and files from running and opening.

**XProtect** prevents the execution of known bad files and outdated plugin versions, but does nothing to cleanup or stop existing malware.

Both offer trivial protection against common risks and are fine at default settings.

See also [Mac Malware Guide : How does Mac OS X protect me?](http://www.thesafemac.com/mmg-builtin/) and [Gatekeeper, XProtect and the Quarantine attribute](http://ilostmynotes.blogspot.com/2012/06/gatekeeper-xprotect-and-quarantine.html).

**Note** Quarantine stores information about downloaded files in `~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`, which may pose a privacy risk. To examine the file, use `strings` or,

    echo 'SELECT datetime(LSQuarantineTimeStamp + 978307200, "unixepoch") as LSQuarantineTimeStamp, LSQuarantineAgentName, LSQuarantineOriginURLString, LSQuarantineDataURLString from LSQuarantineEvent;' | sqlite3 /Users/$USER/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2


See [here](http://www.zoharbabin.com/hey-mac-i-dont-appreciate-you-spying-on-me-hidden-downloads-log-in-os-x/) for more information.

Furthermore, OS X attaches metadata ([HFS+ extended attributes](https://en.wikipedia.org/wiki/Extended_file_attributes#OS_X)) to downloaded files, e.g.

    $ ls -l@ adobe_flashplayer_setup.dmg
    -rw-r-----@ 1 drduh  staff  1000000 Sep  1 12:00 adobe_flashplayer_setup.dmg
	com.apple.diskimages.fsck	     20
	com.apple.diskimages.recentcksum	     79
	com.apple.metadata:kMDItemWhereFroms	   2737
	com.apple.quarantine	     68

	$ xattr -l com.apple.metadata:kMDItemWhereFroms adobe_flashplayer_setup.dmg
	[output omitted]

## Passwords
You can generate strong passwords with `gpg`, `openssl` or just get creative with `/dev/urandom` output.

    $ openssl rand -base64 30
    LK9xkjUEAemc1gV2Ux5xqku+PDmMmCbSTmwfiMRI

    $ gpg --gen-random -a 0 30
    4/bGZL+yUEe8fOqQhF5V01HpGwFSpUPwFcU3aOWQ

    $ dd if=/dev/urandom bs=1 count=30 2>/dev/null | base64
    CbRGKASFI4eTa96NMrgyamj8dLZdFYBaqtWUSxKe

You can also generate passwords, even memorable ones, using **Keychain Access** password assistant, or a command line equivalent like [anders/pwgen](https://github.com/anders/pwgen).

**Keychains** are encrypted with a [PBKDF2 derived key](https://en.wikipedia.org/wiki/PBKDF2) and are a _pretty safe_ place to store credentials. See also [Breaking into the OS X keychain](http://juusosalonen.com/post/30923743427/breaking-into-the-os-x-keychain).

Alternatively, you can manage an encrypted passwords file yourself with `gpg` (shameless plug for my [drduh/pwd.sh](https://github.com/drduh/pwd.sh) script).

In addition to passwords, ensure eligible online accounts, such as Github, Google accounts, banking, have [two factor authentication](https://en.wikipedia.org/wiki/Two-factor_authentication) enabled.

Look to [Yubikey](https://www.yubico.com/products/yubikey-hardware/yubikey-neo/) for a two factor and private key (e.g., ssh, gpg) hardware token. See [drduh/YubiKey-Guide](https://github.com/drduh/YubiKey-Guide) and [trmm.net/Yubikey](https://trmm.net/Yubikey). One of two Yubikey's slots can also be programmed to emit a long, static password (which can be used in combination with a short, memorized password, for example).

## Backup
Always encrypt files locally before backing them up to external media or online services. One way is to use a symmetric cipher with **gpg** and a password of your choosing.

To encrypt, use

    tar zcvf - ~/Downloads | gpg -c > ~/Desktop/backup-$(date +%F-%H%M).tar.gz.gpg

To decrypt, use

    gpg -o ~/Desktop/decrypted-backup.tar.gz \
      -d ~/Desktop/backup-2015-01-01-0000.tar.gz.gpg && \
      tar zxvf ~/Desktop/decrypted-backup.tar.gz

You may also create encrypted volumes using **Disk Utility**, or `hdiutil`, e.g.:

    hdiutil create ~/Desktop/encrypted.dmg -encryption -size 1g -volname "Name" -fs JHFS+

Also see the following applications and services: [SpiderOak](https://spideroak.com/), [Arq](https://www.arqbackup.com/), [Espionage](https://www.espionageapp.com/), and [restic](https://restic.github.io/).

## Wi-Fi
OS X remembers access points it has connected to. Like all wireless devices, the Mac will broadcast all access point names it remembers (e.g., *MyHomeNetwork*) each time it looks for a network, such as when waking from sleep.

This is a privacy risk, so remove networks from the list in **System Preferences** > **Network** > **Advanced** when they're no longer needed.

Also see [Signals from the Crowd: Uncovering Social Relationships through Smartphone Probes](http://conferences.sigcomm.org/imc/2013/papers/imc148-barberaSP106.pdf) [pdf] and [Wi-Fi told me everything about you](http://confiance-numerique.clermont-universite.fr/Slides/M-Cunche-2014.pdf) [pdf].

Saved Wi-Fi information (SSID, last connection, etc.) can be found in `/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`

You may wish to [spoof the MAC address](https://en.wikipedia.org/wiki/MAC_spoofing) of your network card before connecting to new and untrusted wireless networks to mitigate passive fingerprinting, e.g.:

    sudo ifconfig en0 ether $(openssl rand -hex 6 | sed 's%\(..\)%\1:%g; s%.$%%')

**Note** MAC addresses will reset to their hardware defaults on each boot.

Also see [feross/SpoofMAC](https://github.com/feross/SpoofMAC).

Finally, WEP protection on wireless networks is [not secure](http://www.howtogeek.com/167783/htg-explains-the-difference-between-wep-wpa-and-wpa2-wireless-encryption-and-why-it-matters/) and you should favor connecting to **WPA2** protected networks only to mitigate the risk of passive eavesdroppers.

## SSH
For outgoing ssh connections, use hardware- or password-protected ssh keys, [set up](http://nerderati.com/2011/03/17/simplify-your-life-with-an-ssh-config-file/) remote hosts and consider [hashing](http://nms.csail.mit.edu/projects/ssh/) them.

Here are several recommended [options](https://www.freebsd.org/cgi/man.cgi?query=ssh_config&sektion=5) to add to  `~/.ssh/ssh_config`

    Host *
      PasswordAuthentication no
      ChallengeResponseAuthentication no
      HashKnownHosts yes
      UseRoaming no

UseRoaming is an undocumented option in OpenSSH that is enabled by default and is vulnerable in OpenSSH versions 5.4 through 7.1. The vulnerabilities are detailed in [CVE-2016-0777 and CVE-2016-0778](http://undeadly.org/cgi?action=article&sid=20160114142733).

You can also use ssh to create an [encrypted tunnel](http://blog.trackets.com/2014/05/17/ssh-tunnel-local-and-remote-port-forwarding-explained-with-examples.html) to send your traffic through, which is similar to a VPN.

For example, to use privoxy on a remote host:

    ssh -C -L 5555:127.0.0.1:8118 you@remote-host.tld

    sudo networksetup -setwebproxy "Wi-Fi" 127.0.0.1 5555

    sudo networksetup -setsecurewebproxy "Wi-Fi" 127.0.0.1 5555

By default, OS X does **not** have sshd or *Remote Login* enabled.

To enable sshd and allow incoming ssh connections:

    sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist

Or use the **System Preferences** > **Sharing** menu.

If you are going to enable sshd, at least disable password authentication and consider further [hardening](https://stribika.github.io/2015/01/04/secure-secure-shell.html) your configuration.

To `/etc/sshd_config`, add

    PasswordAuthentication no
    ChallengeResponseAuthentication no
    UsePAM no

 Confirm sshd is enabled or disabled with:

    sudo lsof -ni TCP:22

## Physical access
Keep your Mac physically secure at all times. Don't leave it unattended in hotels and such.

For example, a skilled attacker with unsupervised physical access to your computer can infect the boot ROM to install a keylogger and steal your password - see [Thunderstrike](https://trmm.net/Thunderstrike), for example.

A helpful tool is [usbkill](https://github.com/hephaest0s/usbkill), which is *"an anti-forensic kill-switch that waits for a change on your USB ports and then immediately shuts down your computer"*.

Consider purchasing a [privacy filter](https://www.amazon.com/s/ref=nb_sb_noss_2?url=node%3D15782001&field-keywords=macbook) for your screen to thwart shoulder surfers.

## System monitoring

#### Open source monitoring tools

[facebook/osquery](https://github.com/facebook/osquery) can be used to retrieve low level system information.  Users can write SQL queries to retrieve system information.  More information can be found at <https://osquery.io/>.

[google/grr](https://github.com/google/grr) is an incident response framework focused on remote live forensics.

[jipegit/OSXAuditor](https://github.com/jipegit/OSXAuditor) analyzes artifacts on a running system, such as quarantined files, Safari, Chrome and Firefox history, downloads, HTML5 databases and localstore, social media and email accounts, and Wi-Fi access point names.

#### OpenBSM audit
OS X has a powerful OpenBSM auditing capability. You can use it to monitor process execution, network activity, and much more.

Use `sudo praudit -l /dev/auditpipe` to tail audit logs, e.g.:

    header,201,11,execve(2),0,Thu Sep  1 12:00:00 2015, + 195 msec,exec arg,/Applications/.evilapp/rootkit,path,/Applications/.evilapp/rootkit,path,/Applications/.evilapp/rootkit,attribute,100755,root,wheel,16777220,986535,0,subject,drduh,root,wheel,root,wheel,412,100005,50511731,0.0.0.0,return,success,0,trailer,201,

	header,88,11,connect(2),0,Thu Sep  1 12:00:00 2015, + 238 msec,argument,1,0x5,fd,socket-inet,2,443,173.194.74.104,subject,drduh,root,wheel,root,wheel,326,100005,50331650,0.0.0.0,return,failure : Operation now in progress,4354967105,trailer,88

	header,111,11,OpenSSH login,0,Thu Sep  1 12:00:00 2015, + 16 msec,subject_ex,drduh,drduh,staff,drduh,staff,404,404,49271,::1,text,successful login drduh,return,success,0,trailer,111,

See the manual pages for `audit`, `praudit`, `audit_control` and other files in `/etc/security`

**Note** although `man audit` says the `-s` flag will synchronize the audit configuration, it appears necessary to reboot for changes to take effect.

See articles on [ilostmynotes.blogspot.com](http://ilostmynotes.blogspot.com/2013/10/openbsm-auditd-on-os-x-these-are-logs.html) and [derflounder.wordpress.com](https://derflounder.wordpress.com/2012/01/30/openbsm-auditing-on-mac-os-x/) for more information.

#### DTrace

`iosnoop` monitors disk I/O

`opensnoop` monitors file opens

`execsnoop` monitors execution of processes

`errinfo` monitors failed system calls

`dtruss` monitors all system calls

See `man -k dtrace` for more

#### Execution

`ps -ef` lists information about all running processes.

You can also view processes with **Activity Monitor**.

`launchctl list` and `sudo launchctl list` lists loaded and running user and system launch daemons and agents.

#### Network

`sudo lsof -ni -P` lists all open Internet and network "files"

`sudo netstat -atln` lists contents of various network-related data structures

You can also use [Wireshark](https://www.wireshark.org/) from the command line.

Monitor DNS queries and replies

    tshark -Y "dns.flags.response == 1" -Tfields \
      -e frame.time_delta \
      -e dns.qry.name \
      -e dns.a \
      -Eseparator=,

Monitor HTTP requests and responses

    tshark -Y "http.request or http.response" -Tfields \
      -e ip.dst \
      -e http.request.full_uri \
      -e http.request.method \
      -e http.response.code \
      -e http.response.phrase \
      -Eseparator=/s

Monitor x509 certificates on the wire

    tshark -Y "ssl.handshake.certificate" -Tfields \
      -e ip.src \
      -e x509sat.uTF8String \
      -e x509sat.printableString \
      -e x509sat.universalString \
      -e x509sat.IA5String \
      -e x509sat.teletexString \
      -Eseparator=/s -Equote=d

Also check out the GUI "simple network activity monitor" [BonzaiThePenguin/Loading](https://github.com/BonzaiThePenguin/Loading)

## Miscellaneous

If you wish, disable [Diagnostics & Usage Data](https://github.com/fix-macosx/fix-macosx/wiki/Diagnostics-&-Usage-Data).

Consider creating a second, non-administrator account for web browsing and general use which doesn't require elevated privileges. See [issue #9](https://github.com/drduh/OS-X-Security-and-Privacy-Guide/issues/9).

If you want to play **music** or watch **videos**, use [VLC media player](https://www.videolan.org/vlc/index.html) which is free and open source.

If you want to **torrent**, use [Transmission](http://www.transmissionbt.com/download/) which is free and open source (note: like all software, even open source projects, [malware may still find its way in](http://researchcenter.paloaltonetworks.com/2016/03/new-os-x-ransomware-keranger-infected-transmission-bittorrent-client-installer/)). You may also wish to use a block list to avoid peering with known bad hosts - see [Which is the best blocklist for Transmission](https://giuliomac.wordpress.com/2014/02/19/best-blocklist-for-transmission/) and [johntyree/3331662](https://gist.github.com/johntyree/3331662).

Manage default file handlers with [duti](http://duti.org/), which can be installed with `brew install duti`. One reason to manage extensions is to prevent auto-mounting of remote filesystems in Finder (see [Protecting Yourself From Sparklegate](https://www.taoeffect.com/blog/2016/02/apologies-sky-kinda-falling-protecting-yourself-from-sparklegate/)).

Watch the system log with **Console** or the `syslog -w` command.

Enable [tty_tickets](http://blog.rongarret.info/2015/08/psa-beware-of-sudo-on-os-x.html) in the sudoers file.

Set your screen to lock as soon as the screensaver starts

    defaults write com.apple.screensaver askForPassword -int 1
    defaults write com.apple.screensaver askForPasswordDelay -int 0

Expose hidden files and Library folder in Finder

    defaults write com.apple.finder AppleShowAllFiles -bool true
    chflags nohidden ~/Library

Don't default to saving documents to iCloud

    defaults write NSGlobalDomain NSDocumentSaveNewDocumentsToCloud -bool false

[Disable Handoff](https://apple.stackexchange.com/questions/151481/why-is-my-macbook-visibile-on-bluetooth-after-yosemite-install) and Bluetooth features, if they aren't necessary.

Consider [sandboxing](https://developer.apple.com/library/mac/documentation/Darwin/Reference/ManPages/man1/sandbox-exec.1.html) your applications. See [fG! Sandbox Guide](https://reverse.put.as/wp-content/uploads/2011/09/Apple-Sandbox-Guide-v0.1.pdf) [pdf] and [s7ephen/OSX-Sandbox--Seatbelt--Profiles](https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles).

Did you know Apple has not shipped a computer with TPM since [2006](http://osxbook.com/book/bonus/chapter10/tpm/)?

## Additional resources

*In no particular order*

[OS X Core Technologies Overview White Paper](https://www.apple.com/osx/all-features/pdf/osx_elcapitan_core_technologies_overview.pdf)

[Reverse Engineering Mac OS X blog](https://reverse.put.as/)

[Reverse Engineering Resources](http://samdmarshall.com/re.html)

[Patrick Wardle's Objective-See blog](https://objective-see.com/blog.html)

[Dylib Hijack Scanner](https://objective-see.com/products/dhs.html)

[Managing Macs at Google Scale (LISA '13)](https://www.usenix.org/conference/lisa13/managing-macs-google-scale)

[OS X Hardening: Securing a Large Global Mac Fleet (LISA '13)](https://www.usenix.org/conference/lisa13/os-x-hardening-securing-large-global-mac-fleet)

[Yelp's forensic evidence collection & analysis toolkit for OS X](https://github.com/yelp/osxcollector)

[DoD Security Technical Implementation Guides for Mac OS](http://iase.disa.mil/stigs/os/mac/Pages/mac-os.aspx)

[The EFI boot process](http://homepage.ntlworld.com/jonathan.deboynepollard/FGA/efi-boot-process.html)

[The Intel Mac boot process](http://refit.sourceforge.net/info/boot_process.html)

[Userland Persistence on Mac OS X](https://archive.org/details/joshpitts_shmoocon2015)

[Developing Mac OSX kernel rootkits](http://phrack.org/issues/66/16.html#article)

[IOKit kernel code execution exploit](https://code.google.com/p/google-security-research/issues/detail?id=135)

[Hidden backdoor API to root privileges in Apple OS X](https://truesecdev.wordpress.com/2015/04/09/hidden-backdoor-api-to-root-privileges-in-apple-os-x/)

[Santa: A binary whitelisting/blacklisting system for Mac OS X](https://github.com/google/santa/)

[IPv6 Hardening Guide for OS X](http://www.insinuator.net/2015/02/ipv6-hardening-guide-for-os-x/)

[Hacker News discussion](https://news.ycombinator.com/item?id=10148077)

[Apple Open Source](https://opensource.apple.com/)

[OS X 10.10 Yosemite: The Ars Technica Review](http://arstechnica.com/apple/2014/10/os-x-10-10/)

[CIS Apple OSX 10.10 Benchmark](https://benchmarks.cisecurity.org/tools2/osx/CIS_Apple_OSX_10.10_Benchmark_v1.1.0.pdf) [pdf]

[How to Switch to the Mac](https://taoofmac.com/space/HOWTO/Switch)

[Security Configuration For Mac OS X Version 10.6 Snow Leopard](http://www.apple.com/support/security/guides/docs/SnowLeopard_Security_Config_v10.6.pdf) [pdf]

[EFF Surveillance Self-Defense](https://ssd.eff.org/)

[MacAdmins on Slack](https://macadmins.herokuapp.com/)

[SummitRoute/osxlockdown](https://github.com/SummitRoute/osxlockdown)

[iCloud security and privacy overview](http://support.apple.com/kb/HT4865)

[Demystifying the DMG File Format](http://newosxbook.com/DMG.html)

[libyal/libfvde](https://github.com/libyal/libfvde)

[There's a lot of vulnerable OS X applications out there (Sparkle Framework RCE)](https://vulnsec.com/2016/osx-apps-vulnerabilities/)

[iSeeYou: Disabling the MacBook Webcam Indicator LED](https://jscholarship.library.jhu.edu/handle/1774.2/36569)

[Mac OS X Forensics - Technical Report](https://www.ma.rhul.ac.uk/static/techrep/2015/RHUL-MA-2015-8.pdf) [pdf]

[Mac Forensics: Mac OS X and the HFS+ File System](https://cet4861.pbworks.com/w/file/fetch/71245694/mac.forensics.craiger-burke.IFIP.06.pdf) [pdf]

[Extracting FileVault 2 Keys with Volatility](https://tribalchicken.com.au/security/extracting-filevault-2-keys-with-volatility/)
