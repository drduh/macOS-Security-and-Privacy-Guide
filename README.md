This is a collection of thoughts on securing a modern Mac running OS X Yosemite and some steps on how to improve privacy.

It is targeted to “power users” who wish to adopt enterprise-standard security, but is also suitable for novice users with an interest in improving their privacy and security on a Mac.

There is no security silver bullet. A system is only as secure as its administrator is capable of making it.

I am **not** responsible if you break a Mac by following any of these steps.

If you wish to make a correction or improvement, please send a pull request or [open an issue](https://github.com/drduh/OS-X-Yosemite-Security-and-Privacy-Guide/issues).

- [Basics](#basics)
- [Preparing Yosemite](#preparing-yosemite)
- [Installing Yosemite](#installing-yosemite)
    - [Recovery partition](#recovery-partition)
- [First boot](#first-boot)
- [Full disk encryption](#full-disk-encryption)
- [Firmware password](#firmware-password)
- [Firewall](#firewall)
    - [Application layer firewall](#application-layer-firewall)
    - [Third party solutions](#third-party-solutions)
    - [Kernel level packet filtering](#kernel-level-packet-filtering)
- [Services](#services)
- [Spotlight Suggestions](#spotlight-suggestions)
- [Homebrew](#homebrew)
- [DNS](#dns)
    - [Hosts file](#hosts-file)
    - [dnsmasq](#dnsmasq)
    - [dnscrypt](#dnscrypt)
    - [Multicast advertisement](#multicast-advertisement)
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
- [Gatekeeper and Xprotect](#gatekeeper-and-xprotect)
- [Passwords](#passwords)
- [Wi-Fi](#wi-fi)
- [Physical access](#physical-access)
- [System monitoring](#system-monitoring)
    - [Open Source Monitoring Tools](#open-source-monitoring-tools)
    - [OpenBSM Audit](#openbsm-audit)
    - [DTrace](#dtrace)
    - [Network](#network)
- [Miscellaneous](#miscellaneous)
- [Additional resources](#additional-resources)

## Basics
The standard best security practices apply.

* Create a threat model
	* What are you trying to protect and from whom? Is your adversary a [three letter agency](https://theintercept.com/document/2015/03/10/strawhorse-attacking-macos-ios-software-development-kit/) (if so, you may want to consider using [OpenBSD](http://www.openbsd.org/) instead), a nosy eavesdropper on the network, or determined [apt](https://en.wikipedia.org/wiki/Advanced_persistent_threat) orchestrating a campaign against you?
	* Study and recognize the threat and your attack surface.

* Keep the system up to date
	* Patch, patch, patch.
	* Subscribe to announcement mailing lists (e.g., [Apple security-announce](https://lists.apple.com/mailman/listinfo/security-announce)) for software you use often.

* Encrypt sensitive data
	* In addition to full disk encryption, create one or many encrypted containers to store passwords, keys and personal documents.
	* This will mitigate damage in case of compromise and data exfiltration.

* Frequent backups
	* Create regular backups of your data and be ready to reimage in case of compromise.
	* Always encrypt before copying backups to external media or the "cloud".

* Click carefully
	* Ultimately, the security of the system can be reduced to its administrator.
	* Care should be taken when installing new software. Always prefer [free](https://www.gnu.org/philosophy/free-sw.en.html) and open source software ([which OS X is not](https://superuser.com/questions/19492/is-mac-os-x-open-source)).

## Preparing Yosemite
There are several ways to install a fresh copy of OS X Yosemite.

The simplest way is to boot into [Recovery Mode](https://support.apple.com/en-us/HT201314) by holding `Command` and `R` keys at boot. A system image can be downloaded and applied directly from Apple. However, this way exposes the computer's serial number and other identifying information to Apple over plain **HTTP**.

Another way is to download Yosemite build version `14F27` from the [App Store](https://itunes.apple.com/us/app/os-x-yosemite/id915041082) or some other place and create a custom, installable system image.

The application is [code signed](https://developer.apple.com/library/mac/documentation/Security/Conceptual/CodeSigningGuide/Procedures/Procedures.html#//apple_ref/doc/uid/TP40005929-CH4-SW6), which should be verified to make sure you received a legitimate copy.

    $ codesign -dvv Install\ OS\ X\ Yosemite.app
    Executable=/Users/drduh/Install OS X Yosemite.app/Contents/MacOS/InstallAssistant
    Identifier=com.apple.InstallAssistant.Yosemite
    Format=bundle with Mach-O thin (x86_64)
    CodeDirectory v=20200 size=239 flags=0x200(kill) hashes=4+3 location=embedded
    Signature size=4169
    Authority=Apple Mac OS Application Signing
    Authority=Apple Worldwide Developer Relations Certification Authority
    Authority=Apple Root CA
    Info.plist entries=30
    TeamIdentifier=K36BKF7T3D

OS X installers can be made with the `createinstallmedia` utility included in `Install OS X Yosemite.app/Contents/Resources/`. See [Create a bootable installer for OS X Yosemite](https://support.apple.com/en-us/HT201372), or run the utility without arguments to see how it works.

If you'd like to do it the **manual** way, you will need to find the file `InstallESD.dmg`, which is inside `Install OS X Yosemite.app`.

Right click, select **Show Package Contents** and navigate to **Contents > SharedSupport** to find `Install.DMG`.

You can verify the following cryptographic hashes to ensure you have the same, authentic copy by using a command like `shasum -a256 InstallESD.dmg` and so on.

You can also Google these hashes to ensure your copy is genuine and has not been tampered with.

    InstallESD.dmg (Build 14F27)

    SHA-256: 24c4934d91401dd2f738c7811d35ae16d3d7993586592a64b9baf625fe0427db
    SHA-1:   ef5cc8851b893dbe4bc9a5cf5c648c10450af6bc
    MD5:     ff4850735fa0a0a1d706edd21f133ef2

Mount and install the operating system to a **temporary image**, or use the GUI app [MagerValp/AutoDMG](https://github.com/MagerValp/AutoDMG).

    hdiutil attach -noverify -mountpoint /tmp/installesd /Applications/Install\ OS\ X\ Yosemite.app/Contents/SharedSupport/InstallESD.dmg

    hdiutil create -size 32g -type SPARSE -fs HFS+J -volname "OS X" -uid 0 -gid 80 -mode 1775 /tmp/output.sparseimage

    hdiutil attach -noverify -mountpoint /tmp/os -owners on /tmp/output.sparseimage

    sudo installer -pkg /tmp/installesd/Packages/OSInstall.mpkg -tgt /tmp/os

This part will take a while, so just be patient. You can `tail -F /var/log/install.log` to check progress.

Optionally, install any other packages to the image, such as [Wireshark](https://www.wireshark.org/download.html).

    hdiutil mount Wireshark\ 1.99.5\ Intel\ 64.dmg

    sudo installer -pkg /Volumes/Wireshark/Wireshark\ 1.99.5\ Intel\ 64.pkg -tgt /tmp/os

    hdiutil unmount /Volumes/Wireshark

See [MagerValp/AutoDMG/wiki/Packages-Suitable-for-Deployment](https://github.com/MagerValp/AutoDMG/wiki/Packages-Suitable-for-Deployment) for caveats and check out [chilcote/outset](https://github.com/chilcote/outset) to instead processes packages and scripts at first boot.

When you're done, detach, convert and verify the image.

    hdiutil detach /tmp/os

    hdiutil detach /tmp/installesd

    hdiutil convert -format UDZO /tmp/output.sparseimage -o yosemite.dmg

    asr imagescan --source yosemite.dmg

Now, `yosemite.dmg` is ready to be applied to one or multiple Macs. You can further customize the image to have premade users, applications and preferences to your liking.

## Installing Yosemite

I prefer to install this image using another Mac and [Target Disk Mode](https://support.apple.com/en-us/HT201462).

If you don't have another Mac, create a bootable USB drive from the Yosemite app bundle you already have, and boot the Mac you wish to image to it by holding the *Option* key at boot.

If you don't have an external drive or USB stick to use, it's possible to create a small partition with **Disk Utility** and use that. There are several guides online on how to do this.

To use **Target Disk Mode**, boot up the Mac you wish to image while holding `T` and connect it to another using Firewire, Thunderbolt or USB-C.

Run `diskutil list` to identify the connected disk, usually `/dev/disk2`

**Erase** the disk to Journaled HFS+

    diskutil unmountDisk /dev/disk2
    diskutil partitionDisk /dev/disk2 1 JHFS+ OSX 100%

**Restore** the image to the new volume

    sudo asr restore \
      --source yosemite.dmg \
      --target /Volumes/OSX \
      --erase --noverify \
      --buffersize 4m

Alternatively, open the **Disk Utility** application, erase the connected Mac's disk, then drag `yosemite.dmg` in to restore it to the new partition.

If you've followed these steps correctly, the target Mac should now have a fresh install of OS X Yosemite.

If you want to transfer any files, copy them to a folder like `/Users/Shared` on the mounted disk image, e.g. `cp xcode_6.1.1.dmg /Volumes/OS\ X/Users/Shared`

#### Recovery partition

We're not done yet! Unless you have built the image with [AutoDMG](https://github.com/MagerValp/AutoDMG), you will need to create a recovery partition in order to use Filevault full disk encryption. You can do so using [MagerValp/Create-Recovery-Partition-Installer](https://github.com/MagerValp/Create-Recovery-Partition-Installer) or with the following manual steps.

Download [RecoveryHDUpdate.dmg](https://support.apple.com/downloads/DL1464/en_US/RecoveryHDUpdate.dmg)

    RecoveryHDUpdate.dmg

    SHA-256: f6a4f8ac25eaa6163aa33ac46d40f223f40e58ec0b6b9bf6ad96bdbfc771e12c
    SHA-1:   1ac3b7059ae0fcb2877d22375121d4e6920ae5ba
    MD5:     b669cdb341b2253a843bf0d402b9675a

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

The PRNG can be manually seeded with entropy by writing to /dev/random **before** enabling Filevault 2. This can be done by simply using the Mac for a little while before activate Filevault 2.

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

1. Shutdown your Mac.

2. Start up your Mac again and immediately hold the `Command` and `R` keys after you hear the startup sound to start from **OS X Recovery**.

3. When the Recovery window appears, choose **Firmware Password Utility** from the Utilities menu.

4. In the Firmware Utility window that appears, select **Turn On Firmware Password**.

5. Enter a new password, then enter the same password in the Verify field.

6. Select Set Password.

7. Select Quit Firmware Utility to close the Firmware Password Utility.

8. Select the Apple menu and choose Restart or Shutdown.

The firmware password will activate at next boot. To validate the password hold `alt` pressed while booting, you should be prompted to enter the password. After that select the partition you want to boot from.

## Firewall
Before connecting to the Internet, it's a good idea to first configure a firewall.

There are three basic types of firewall for OS X.

#### Application layer firewall
Built-in, basic firewall which blocks **incoming** connections only.

Controlled by the **Firewall** tab of **Security & Privacy** in **System Preferences**.

Enable ALF, logging and "stealth mode" with the following commands, or through System Preferences:

    sudo defaults write /Library/Preferences/com.apple.alf globalstate -int 1
    sudo defaults write /Library/Preferences/com.apple.alf allowsignedenabled -bool false
    sudo defaults write /Library/Preferences/com.apple.alf loggingenabled -bool true
    sudo defaults write /Library/Preferences/com.apple.alf stealthenabled -bool true

> Computer hackers scan networks so they can attempt to identify computers to attack. You can prevent your computer from responding to some of these scans by using **stealth mode**. When stealth mode is enabled, your computer does not respond to ICMP ping requests, and does not answer to connection attempts from a closed TCP or UDP port. This makes it more difficult for attackers to find your computer.

Note, ALF does not offer the ability to monitor or block **outgoing** connections.

#### Third party solutions
Programs such as [Little Snitch](https://www.obdev.at/products/littlesnitch/index.html), [Hands Off](https://www.oneperiodic.com/products/handsoff/) and [Radio Silence](http://radiosilenceapp.com/) provide a good balance of usability and security.

They are capable of monitoring and blocking **incoming** and **outgoing** network connections. However, they may require the use of a closed source [kernel extension](https://developer.apple.com/library/mac/documentation/Darwin/Conceptual/KernelProgramming/Extend/Extend.html).

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

Unless you're already familiar with pf, I don't suggest worrying too much about configuring it on OS X.

## Services
Before you connect to the Internet, you may wish to disable some Apple services which phone home to Apple.

Also see [fix-macosx/yosemite-phone-home](https://github.com/fix-macosx/yosemite-phone-home) and [l1k/osxparanoia](https://github.com/l1k/osxparanoia)

Services on OS X are managed by **launchd**. See <http://launchd.info/>, as well as [Apple's Daemons and Services Programming Guide](https://developer.apple.com/library/mac/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html) and [Technical Note TN2083](https://developer.apple.com/library/mac/technotes/tn2083/_index.html)

You can also run [KnockKnock](https://github.com/synack/knockknock) that shows more information about startup items.

Here are the basics:

* Use `launchctl list` to view loaded user agents
* Use `sudo launchctl list` to view loaded system daemons
* Specify the service name to examine it, e.g. `launchctl list com.apple.Maps.mapspushd`
* Use `defaults read` to examine job plists in `/System/Library/LaunchDaemons` and `/System/Library/LaunchAgents`
* Use `man`, `strings` and Google to learn about what the agent/daemon runs

For example, to learn what a system launch daemon or agent does, start with

	defaults read /System/Library/LaunchDaemons/com.apple.apsd.plist

Look at the `ProgramArguments` section to see which binary is run, in this case **apsd**. To find more information about that, look at the man page with `man apsd`

If you're not interested in Apple Push Notifications, disable the service

	sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.apsd.plist

**Note** Unloading services may break usability of some applications. Read the manual pages and use Google to make sure you understand what you're doing first.

That said, here's an example of disabling some **user launch agents** I don't care for,

	function disable_agent {
      echo "Disabling ${1}"
      launchctl unload -w /System/Library/LaunchAgents/${1}.plist
	}

	disable_agent com.apple.AddressBook.SourceSync
	disable_agent com.apple.AirPlayUIAgent
	disable_agent com.apple.AOSHeartbeat
	disable_agent com.apple.AOSPushRelay
	disable_agent com.apple.bird
	disable_agent com.apple.CalendarAgent
	disable_agent com.apple.CallHistoryPluginHelper
	disable_agent com.apple.CallHistorySyncHelper
	disable_agent com.apple.cloudd
	disable_agent com.apple.cloudfamilyrestrictionsd-mac
	disable_agent com.apple.cloudpaird
	disable_agent com.apple.cloudphotosd
	disable_agent com.apple.CoreLocationAgent
	disable_agent com.apple.coreservices.appleid.authentication
	disable_agent com.apple.EscrowSecurityAlert
	disable_agent com.apple.findmymacmessenger
	disable_agent com.apple.gamed
	disable_agent com.apple.helpd
	disable_agent com.apple.icloud.fmfd
	disable_agent com.apple.idsremoteurlconnectionagent
	disable_agent com.apple.imagent
	disable_agent com.apple.IMLoggingAgent
	disable_agent com.apple.locationmenu
	disable_agent com.apple.notificationcenterui
	disable_agent com.apple.pbs
	disable_agent com.apple.rtcreportingd
	disable_agent com.apple.SafariCloudHistoryPushAgent
	disable_agent com.apple.safaridavclient
	disable_agent com.apple.SafariNotificationAgent
	disable_agent com.apple.security.cloudkeychainproxy
	disable_agent com.apple.SocialPushAgent
	disable_agent com.apple.syncdefaultsd
	disable_agent com.apple.telephonyutilities.callservicesd

And the same for **system launch daemons**,

	function disable_daemon {
      echo "Disabling ${1}"
      sudo launchctl unload -w /System/Library/LaunchDaemons/${1}.plist
	}

	disable_daemon com.apple.apsd
	disable_daemon com.apple.AssetCacheLocatorService
	disable_daemon com.apple.awacsd
	disable_daemon com.apple.awdd
	disable_daemon com.apple.CrashReporterSupportHelper
	disable_daemon com.apple.GameController.gamecontrollerd
	disable_daemon com.apple.SubmitDiagInfo
	disable_daemon com.apple.TMCacheDelete

Be careful about disabling any system daemons you don't understand, as it may render your system unbootable. If you break your Mac, use [single user mode](https://support.apple.com/en-us/HT201573) to fix it.

## Spotlight Suggestions
Disable “Spotlight Suggestions” in both the Spotlight preferences and Safari's Search preferences to avoid your search queries being sent to Apple.

Also disable "Bing Web Searches" in the Spotlight preferences to avoid your search queries being sent to Microsoft.

See <https://fix-macosx.com/>

> If you've upgraded to Mac OS X Yosemite (10.10) and you're using the default settings, each time you start typing in Spotlight (to open an application or search for a file on your computer), your local search terms and location are sent to Apple and third parties (including Microsoft).

Speaking of Microsoft, you may want to see <https://fix10.isleaked.com/> just for fun.

## Homebrew
Consider installing [Homebrew](http://brew.sh/) to make installing software easier.

If you have not already installed Xcode or Command Line Tools, run `xcode-select --install` and a prompt should appear to download and install CLI Tools.

Homebrew can be easily installed with

    ruby -e "$(curl -fsSL https://raw.githubusercontent.com/Homebrew/install/master/install)"

or have a look at [homebrew/Installation.md](https://github.com/Homebrew/homebrew/blob/master/share/doc/homebrew/Installation.md#installation) for other installation options.

Homebrew uses SSL/TLS to talk with github and verifies checksums of downloaded packages, so it's [fairly secure](https://github.com/Homebrew/homebrew/issues/18036).

Or, just download, compile and install software directly from their respective open source repositories.

## DNS
Here are a few ways to improve your security and privacy with DNS.

#### Hosts file
Use the [hosts file](https://en.wikipedia.org/wiki/Hosts_(file)) to block known malware, advertising or otherwise unwanted domains.

Edit the hosts file as root with `sudo vi /etc/hosts`. The hosts file can also be managed with the GUI app [2ndalpha/gasmask](https://github.com/2ndalpha/gasmask).

To block a domain, just add `0 facebook.com` (`0` means `0.0.0.0`, a null route)

There are many lists of domains available online which you can paste in, just make sure each line starts with `0` or `127.0.0.1`, and the line `127.0.0.1 localhost` is included.

For examples, see [someonewhocares.org](http://someonewhocares.org/hosts/zero/hosts), [l1k/osxparanoia/blob/master/hosts](https://github.com/l1k/osxparanoia/blob/master/hosts), [StevenBlack/hosts](https://github.com/StevenBlack/hosts) and [gorhill/uMatrix/hosts-files.json](https://github.com/gorhill/uMatrix/blob/master/assets/umatrix/hosts-files.json).

#### dnsmasq

Install and use [dnsmasq](http://www.thekelleys.org.uk/dnsmasq/doc.html) to cache replies, prevent upstreaming queries for unqualified names, and even block entire TLDs.

Use it in combination with `dnscrypt` to also encrypt outgoing DNS traffic.

If you don't wish to use `dnscrypt`, you should at least use DNS [not provided](http://bcn.boulder.co.us/~neal/ietf/verisign-abuse.html) [by your ISP](http://hackercodex.com/guide/how-to-stop-isp-dns-server-hijacking/). Two popular alternatives are [Google DNS](https://developers.google.com/speed/public-dns/) and [OpenDNS](https://www.opendns.com/home-internet-security/).

Install `dnsmasq` and edit the configuration

    brew install dnsmasq

    mkdir -p /usr/local/etc

    cp /usr/local/opt/dnsmasq/dnsmasq.conf.example /usr/local/etc/dnsmasq.conf

    vim /usr/local/etc/dnsmasq.conf

Have a look through the commented-out options. Here are a few recommended settings to enable,

    # Forward queries to dnscrypt on localhost
    server=127.0.0.1#5355
      
    # Never forward plain names
    domain-needed

    # Never forward addresses in the non-routed address spaces
    bogus-priv

    # Optional logging directives
    log-async
    log-dhcp
    log-queries
    log-facility=/var/log/dnsmasq.log

Install and start the program

    sudo cp -fv /usr/local/opt/dnsmasq/*.plist /Library/LaunchDaemons
    
    sudo chown root /Library/LaunchDaemons/homebrew.mxcl.dnsmasq.plist
    
    sudo launchctl load /Library/LaunchDaemons/homebrew.mxcl.dnsmasq.plist

Open **System Preferences** > **Network** and select your interface, then the **DNS** tab.

Select the **+** and add `127.0.0.1` as a DNS server.

Make sure `dnsmasq` is running with `sudo lsof -ni UDP:53` or `ps -ef | grep '[d]nsmasq'` or with `scutil`

    $ scutil --dns
    DNS configuration

    resolver #1
      search domain[0] : mycoolnetwork
      nameserver[0] : 127.0.0.1
      flags    : Request A records, Request AAAA records
      reach    : Reachable,Local Address

**Note** Some VPN software overrides DNS settings on connect. See [issue #24](https://github.com/drduh/OS-X-Yosemite-Security-and-Privacy-Guide/issues/24) for more information.

#### dnscrypt

Use [dnscrypt](https://dnscrypt.org/) to encrypt DNS traffic to the provider of choice.

If you prefer a GUI application, see [alterstep/dnscrypt-osxclient](https://github.com/alterstep/dnscrypt-osxclient).

Install the program

    brew install dnscrypt-proxy

    sudo cp -fv /usr/local/opt/dnscrypt-proxy/*.plist /Library/LaunchDaemons

    sudo chown root /Library/LaunchDaemons/homebrew.mxcl.dnscrypt-proxy.plist

If using in combination with `dnsmasq`, edit `/Library/LaunchDaemons/homebrew.mxcl.dnscrypt-proxy.plist` to have this line

    <string>--local-address=127.0.0.1:5355</string>

Below the line

    <string>/usr/local/opt/dnscrypt-proxy/sbin/dnscrypt-proxy</string>

Finally, start the program

    sudo launchctl load /Library/LaunchDaemons/homebrew.mxcl.dnscrypt-proxy.plist

Make sure `dnscrypt` is running with `sudo lsof -ni UDP:5355` or `ps -ef | grep '[d]nscrypt'`

> By default, dnscrypt-proxy runs on localhost (127.0.0.1), port 53,
and under the "nobody" user using the dnscrypt.eu-dk DNSCrypt-enabled
resolver. If you would like to change these settings, you will have to edit
the plist file (e.g., --resolver-address, --provider-name, --provider-key, etc.)

This can be accomplished by editing `/Library/LaunchDaemons/homebrew.mxcl.dnscrypt-proxy.plist`.

You can run your own [dnscrypt server](https://github.com/Cofyc/dnscrypt-wrapper) from a trusted location or use one of many [public servers](https://github.com/jedisct1/dnscrypt-proxy/blob/master/dnscrypt-resolvers.csv) instead.

Make sure it's working with `tcpdump` or Wireshark

    $ sudo tcpdump -qtni en0
    IP 10.8.8.8.59636 > 77.66.84.233.443: UDP, length 512
    IP 77.66.84.233.443 > 10.8.8.8.59636: UDP, length 368

    $ dig +short -x 77.66.84.233
    resolver2.dnscrypt.eu

Also see [What is a DNS leak and why should I care?](https://dnsleaktest.com/what-is-a-dns-leak.html)

#### Multicast advertisement
Turn off multicast DNS if you don't need it. It spams information about your machine and its services to the local network.

Edit `com.apple.mDNSResponder.plist`

    sudo -E vim /System/Library/LaunchDaemons/com.apple.mDNSResponder.plist

Copy the line `<string>/usr/sbin/mDNSResponder</string>` and paste it twice (`yy` and `pp` in vim)

Replace the argument with `-launchd` and `-NoMulticastAdvertisements`

`sudo killall -9 mDNSResponder` to restart **mDNSResponder**

You can also use [MacMiniVault/Mac-Scripts/disablebonjour.sh](https://github.com/MacMiniVault/Mac-Scripts/blob/master/disablebonjour/disablebonjour.sh) to accomplish this.

## Captive portal

When OS X connects to new networks, it **probes** the network and launches a Captive Portal assistant utility if connectivity can't be determined.

An attacker could trigger the utility and direct a Mac to a site with malware without user interaction, so it's best to disable this feature.

See <https://web.archive.org/web/20130407200745/http://www.divertednetworks.net/apple-captiveportal.html>

and <https://grpugh.wordpress.com/2014/10/29/an-undocumented-change-to-captive-network-assistant-settings-in-os-x-10-10-yosemite/>

## Certificate authorities
Yosemite comes with [over 200 root certificate authorities](https://support.apple.com/en-us/HT202858) from for-profit corporations like Apple, Verisign, Thawte, Digicert and government agencies from China, Japan, Netherlands, U.S., and more! These CAs are capable of issuing SSL certificates for any domain or code signing certificates as well.

For more information, see [Certification Authority Trust Tracker](https://github.com/kirei/catt),

and papers
[Analysis of the HTTPS certificate ecosystem](http://conferences.sigcomm.org/imc/2013/papers/imc257-durumericAemb.pdf) [pdf]

and [You Won’t Be Needing These Any More: On Removing Unused Certificates From Trust Stores](http://www.ifca.ai/fc14/papers/fc14_submission_100.pdf) [pdf]

You can inspect system root certificates in **Keychain Access**, under the **System Roots** tab or by using the `security` command line tool and `/System/Library/Keychains/SystemRootCertificates.keychain` file.

The risk of a [man in the middle](https://en.wikipedia.org/wiki/Man-in-the-middle_attack) attack in which a coerced or compromised certificate authority trusted by your system issues a fake/rogue SSL certificate is quite low, but still [possible](https://en.wikipedia.org/wiki/DigiNotar#Issuance_of_fraudulent_certificates).

To remove an unwanted certificate, copy its **SHA1** sum, then delete it

    echo "4F 99 AA 93 FB 2B D1 37 26 A1 99 4A CE 7F F0 05 F2 93 5D 1E" | tr -d ' '
    4F99AA93FB2BD13726A1994ACE7FF005F2935D1E

    sudo security delete-certificate -t -Z 4F99AA93FB2BD13726A1994ACE7FF005F2935D1E /System/Library/Keychains/SystemRootCertificates.keychain

Here's an example of removing a list of roots

	function remove {
    echo "Removing ${2}"
    sudo /usr/bin/security delete-certificate \
      -t -Z $1 \
      /System/Library/Keychains/SystemRootCertificates.keychain
	}

	remove "D1EB23A46D17D68FD92564C2F1F1601764D8E349" "AAA Certificate Services"
	remove "4F99AA93FB2BD13726A1994ACE7FF005F2935D1E" "China Internet Network Information Center Root CA"
	remove "8BAF4C9B1DF02A92F7DA128EB91BACF498604B6F" "CNNIC"
	remove "8C941B34EA1EA6ED9AE2BC54CF687252B4C9B561" "DoD Root CA 2"
	remove "10F193F340AC91D6DE5F1EDC006247C4F25D9671" "DoD CLASS 3 Root CA"
	remove "8C96BAEBDD2B070748EE303266A0F3986E7CAE58" "EBG"
	remove "51C6E70849066EF392D45CA00D6DA3628FC35239" "E-Tugra Certification Authority"
	remove "905F942FD9F28F679B378180FD4F846347F645C1" "Federal Common Policy CA"
	remove "FE45659B79035B98A161B5512EACDA580948224D" "Hellenic Academic and Research Institutions RootCA 2011"
	remove "D6DAA8208D09D2154D24B52FCB346EB258B28A58" "Hongkong Post Root CA 1"
	remove "D2441AA8C203AECAA96E501F124D52B68FE4C375" "I.CA"
	remove "270C500CC6C86ECB1980BC1305439ED282480BE3" "MPHPT Certification Authority"
	remove "06083F593F15A104A069A46BA903D006B7970991" "NetLock Arany"
	remove "E392512F0ACFF505DFF6DE067F7537E165EA574B" "NetLock Expressz"
	remove "016897E1A0B8F2C3B134665C20A727B7A158E28F" "NetLock Minositett Kozjegyzoi"
	remove "ACED5F6553FD25CE015F1F7A483B6A749F6178C6" "NetLock Kozjegyzoi"
	remove "2DFF6336E33A4829AA009F01A1801EE7EBA582BB" "Prefectural Association For JPKI"
	remove "8782C6C304353BCFD29692D2593E7D44D934FF11" "SecureTrust CA"
	remove "E19FE30E8B84609E809B170D72A8C5BA6E1409BD" "Trusted Certificate Services"
	remove "3BC0380B33C3F6A60C86152293D9DFF54B81C005" "Trustis FPS Root CA"
	remove "B091AA913847F313D727BCEFC8179F086F3A8C0F" "TW Government Root Certification Authority"
	remove "1B4B396126276B6491A2686DD70243212D1F1D96" "TurkTrust 1"
	remove "7998A308E14D6585E6C21E153A719FBA5AD34AD9" "TurkTrust 2"
	remove "B435D4E1119D1C6690A749EBB394BD637BA782B7" "TurkTrust 3"
	remove "F17F6FB631DC99E3A3C87FFE1CF1811088D96033" "TurkTrust 4"
	remove "0B972C9EA6E7CC58D93B20BF71EC412E7209FABF" "UCA Global Root"
	remove "8250BED5A214433A66377CBC10EF83F669DA3A67" "UCA Root"
	remove "CB44A097857C45FA187ED952086CB9841F2D51B5" "US Govt Common Policy"
	remove "FAA7D9FB31B746F200A85E65797613D816E063B5" "VRK Gov. Root CA"
	remove "E7B4F69D61EC9069DB7E90A7401A3CF47D4FE8EE" "WellsSecure Public Root Certificate Authority"

These may be updated or re-added during system updates, though.

A cool idea is to write a custom proxy which monitors and logs certificate chains seen on the wire.

## OpenSSL

The version of `openssl` in Yosemite is `0.9.8` which is [not current](https://apple.stackexchange.com/questions/200582/why-is-apple-using-an-older-version-of-openssl). It doesn't support TLS 1.1 or newer, elliptic curve ciphers, and [more](https://stackoverflow.com/questions/27502215/difference-between-openssl-09-8z-and-1-0-1).

Apple claims OpenSSL is **deprecated** in their [Cryptographic Services Guide
](https://developer.apple.com/library/mac/documentation/Security/Conceptual/cryptoservices/GeneralPurposeCrypto/GeneralPurposeCrypto.html) document. Their version also has patches which may [surprise you](https://hynek.me/articles/apple-openssl-verification-surprises/).

Grab a recent version of OpenSSL with `brew install openssl` and ensure it's the default with `brew link --force openssl`

Compare the new version with the system one

    $ echo | openssl s_client -connect github.com:443 2>&1 | grep -A2 SSL-Session
    SSL-Session:
        Protocol  : TLSv1.2
        Cipher    : ECDHE-RSA-AES128-GCM-SHA256

    $ ^openssl^/usr/bin/openssl
    echo | /usr/bin/openssl s_client -connect github.com:443 2>&1 | grep -A2 SSL-Session
    SSL-Session:
        Protocol  : TLSv1
        Cipher    : AES128-SHA

Also see [Comparison of TLS implementations
](https://en.wikipedia.org/wiki/Comparison_of_TLS_implementations) and [How's My SSL](https://www.howsmyssl.com/).

## Curl

The version of `curl` which comes with OS X uses [Secure Transport](https://developer.apple.com/library/mac/documentation/Security/Reference/secureTransportRef/) for SSL/TLS validation.

If you prefer to use OpenSSL, install with `brew install curl --with-openssl` and ensure it's the default with `brew link --force curl`

Here are a few recommended self explanatory options to add to `~/.curlrc`

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

Install and start privoxy

    brew install privoxy
    
    ln -sfv /usr/local/opt/privoxy/*.plist ~/Library/LaunchAgents
    
    launchctl load ~/Library/LaunchAgents/homebrew.mxcl.privoxy.plist

By default, privoxy listens on local TCP port 8118.

Set the **HTTP** proxy for your active network interface in **System Preferences** to `127.0.0.1` and port `8118`.

Confirm it's working by visiting <http://p.p/> and with the command `scutil --proxy`

Privoxy already comes with many good rules, however you can also write your own.

For example, edit `/usr/local/etc/privoxy/user.action` to block elements by domain or with regular expressions,

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

Write simple or complex rules for redirection, such as to HTTPS,

    { +redirect{s@http://@https://@} }
    code.jquery.com

    { +redirect{s@http://imgur.com/@https://imgur.com/@}}
    imgur.com

You can even replace all ad images with pictures of kittens by running a local web server.

Consider logging all privoxy requests so you can be inspired to write custom rules.

## Web browsing
The web browser is poses the largest security and privacy risk, as its fundamental job is to download and execute untrusted code from the Internet.

Use [Google Chrome](https://www.google.com/chrome/browser/desktop/) for most of your browsing. It offers [separate profiles](https://www.chromium.org/user-experience/multi-profiles), [good sandboxing](https://www.chromium.org/developers/design-documents/sandbox) and [frequent updates](http://googlechromereleases.blogspot.com/) (including Flash, although you should disable it - see below).

Chrome also comes with a great [PDF viewer](http://0xdabbad00.com/2013/01/13/most-secure-pdf-viewer-chrome-pdf-viewer/).

If you don't want to use Chrome, [Firefox](https://www.mozilla.org/en-US/firefox/new/) is an excellent browser as well. Or simply use both. See discussion in [issue #2](https://github.com/drduh/OS-X-Yosemite-Security-and-Privacy-Guide/issues/2).

Create at least three profiles, one for browsing **trusted** web sites (email, banking), another for **untrusted** (link aggregators, news sites), and a third for a completely **cookie-less** and **script-less** experience.

* One profile **without cookies or Javascript** (turned off in `chrome://settings/content`) which should be the **preferred** profile to visiting new web sites. However, many pages will not load at all without Javascript enabled.

* One profile with [uMatrix](https://github.com/gorhill/uMatrix) (or [uBlock](https://github.com/chrisaljoudi/uBlock), a simpler version). Use this profile for visiting **mostly trusted** web sites. Take time to learn how these **firewall** extensions work. Other frequently recommended extensions are [Privacy Badger](https://www.eff.org/privacybadger) and [HTTPSEverywhere](https://www.eff.org/https-everywhere).

* One (or more) profile for your "real name", signed-in browsing needs such as banking and email (however, don't open email links from this profile)

The idea is to separate and compartmentalize your data.

In each profile, visit `chrome://plugins/` and **disable Adobe Flash** plugin. If you **must** use Flash, create a separate profile, and make sure the content is hosted over **HTTPS**.

Also visit `chrome://settings/contents` and select **Let me choose when to run plugin content** under the Plugins section.

Take some time to read through [Chromium Security](https://www.chromium.org/Home/chromium-security) and [Chromium Privacy](https://www.chromium.org/Home/chromium-privacy).

For example you may wish to disable [DNS prefetching](https://www.chromium.org/developers/design-documents/dns-prefetching) (see also [DNS Prefetching and Its Privacy Implications](https://www.usenix.org/legacy/event/leet10/tech/full_papers/Krishnan.pdf) [pdf].

Do **not** use other Chromium-derived browsers. They are usually [closed source](http://yro.slashdot.org/comments.pl?sid=4176879&cid=44774943), [poorly maintained](https://plus.google.com/+JustinSchuh/posts/69qw9wZVH8z), or make dubious claims to protect privacy. See [The Private Life of Chromium Browsers](http://thesimplecomputer.info/the-private-life-of-chromium-browsers).

Do **not** use Safari. The code is a mess and security vulnerabilities are frequent, but slower to patch ([discussion on HN](https://news.ycombinator.com/item?id=10150038)). If you have to use Safari, disable the **Open "safe" files after downloading** option in Preferences.

For more information about security conscious browsing [HowTo: Privacy & Security Conscious Browsing](https://gist.github.com/atcuno/3425484ac5cce5298932) is a great addition.

## Plugins
Don't download or install Internet plugins like **Silverlight** unless you really need them. Netflix works with HTML5 on Yosemite.

**Java**, **Flash**, **Adobe Reader** and others plugins are a big security risk because they are poorly written, and should not be installed.

Really, only use them in a disposable VM.

See <https://en.wikipedia.org/wiki/Trojan_BackDoor.Flashback>,

<http://www.cvedetails.com/vulnerability-list/vendor_id-53/product_id-497/Adobe-Acrobat-Reader.html>, and

<https://blogs.cisco.com/security/angling-for-silverlight-exploits>

## PGP/GPG
PGP is a standard for encrypting email end to end. That means only the chosen recipients can decrypt a message, unlike regular email which is read and forever archived by providers.

**GPG**, or **GNU Privacy Guard**, is a GPL licensed program compliant with the standard.

**GPG** is used to verify signatures of software you download and install, as well as [symmetrically](https://en.wikipedia.org/wiki/Symmetric-key_algorithm) or [asymmetrically](https://en.wikipedia.org/wiki/Public-key_cryptography) encrypt files and text.

Install with `brew install gnupg`, or if you prefer to install a newer, more feature-rich [stable version](https://www.gnupg.org/), use `brew install homebrew/versions/gnupg21`

If you prefer a GUI, check out [GPG Suite](https://gpgtools.org/)

Here are recommended options to add to `~/.gnupg/gpg.conf`

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

See also [ioerror/duraconf/configs/gnupg/gpg.conf](https://github.com/ioerror/duraconf/blob/master/configs/gnupg/gpg.conf)

You should also read [OpenPGP Best Practices
](https://help.riseup.net/en/security/message-security/openpgp/best-practices)

If you don't already have a gpg keypair, create one with `gpg --gen-key`

Read [online](https://alexcabal.com/creating-the-perfect-gpg-keypair/) [guides](https://security.stackexchange.com/questions/31594/what-is-a-good-general-purpose-gnupg-key-setup) and practice encrypting and decrypting email to yourself and your friends. Get them interested in this stuff!

## OTR
OTR stands for **Off-the-Record** and is a cryptographic protocol for encrypting and authenticating conversations over instant messaging.

You can use OTR on top of any existing **XMPP** chat service, even Google Hangouts (which only encrypts conversations between users and the server).

The first time you start a conversation with someone new, you'll be asked to verify their public key fingerprint. Make sure to do this in person or by some other secure means (e.g. GPG encrypted mail).

A popular OS X GUI client for XMPP and other chat protocol is [Adium](https://adium.im/)

Consider downloading the [beta version](https://beta.adium.im/) which uses OAuth2, making logging in to Google Talk/Hangouts [more secure](https://trac.adium.im/ticket/16161).

    Adium_1.5.11b2.dmg

    SHA-256: e7690718f14defa3bc08cd3949a4eab52e942abd47f7ac2ce7157ed7295658c6
    SHA-1:   7f0271d4fe9835b4554225510e758a3c46c10b6a
    MD5:     db27cb75caffdb147db915369ae46b4c

Remember to [disable logging](https://trac.adium.im/ticket/15722) for OTR chats with Adium.

A good console-based XMPP client is [profanity](http://www.profanity.im/)  which can be installed with `brew install profanity`

If you want to know how OTR works, read the paper [Off-the-Record Communication, or, Why Not To Use PGP](https://otr.cypherpunks.ca/otr-wpes.pdf) [pdf]

## Tor
Tor is an anonymizing proxy which can be used for browsing the web.

Download Tor Browser from <https://www.torproject.org/projects/torbrowser.html.en>. Do **not** attempt to configure other browsers to use Tor as you are likely make a mistake which will compromise your anonymity.

After downloading the `dmg` and `asc` files, verify the disk image has been signed by Tor developers with `gpg TorBrowser*asc`

You may see a warning - the public key was not found. Fetch it from the keyserver with `gpg --recv-keys 0x2E1AC68ED40814E0` and verify again.

Make sure `Good signature from "Tor Browser Developers (signing key) <torbrowser@torproject.org>"` appears in the output.

See [How to verify signatures for packages](https://www.torproject.org/docs/verifying-signatures.html) for more information.

Tor traffic is **encrypted** (i.e., cannot be read by a passive network eavesdropper), but **can** be identified.

Just one example way is by monitoring TLS handshakes:

    $ sudo tcpdump -Ani en0 "tcp" | grep "www"
    .............&.$..!www.ht50d2u6ky6y7kbcxhe5mjfdi.com.........
    .~7...~.|.Lp*e.....L._..........ug.......[.net0.brU.....fP...a&..'.]...r.....E*F....{...qjJ}....).$8....	....V.E..0
    ...................www.s4ku5skci.net.........
    l..5...R[i.0...A.$...l..Ly.....}..ZY..../.........LH.0..\...3.?.........*.N... ..._/G\...0*..?...`d.........0	...X..&.N0
    ^C

See [Tor Protocol Specification](https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt) and [Tor/TLSHistory](https://trac.torproject.org/projects/tor/wiki/org/projects/Tor/TLSHistory) for more information.

It is recommended to additionally obfuscate it using a [pluggable transport](https://www.torproject.org/docs/pluggable-transports.html) such as [Yawning/obfs4proxy](https://github.com/Yawning/obfs4) or [SRI-CSL/stegotorus](https://github.com/SRI-CSL/stegotorus).

This can be done by [running a Tor relay](https://www.torproject.org/docs/tor-relay-debian.html) or a private or public [bridge](https://www.torproject.org/docs/bridges.html.en#RunningABridge) which will serve as your obfuscating guard node. Set one up and share it with your friends!

For extra security, use [VirtualBox](https://www.virtualbox.org/wiki/Downloads) or VMware to run a virtualized [GNU/Linux](http://www.brianlinkletter.com/installing-debian-linux-in-a-virtualbox-virtual-machine/) or [BSD](http://www.openbsd.org/faq/faq4.html) machine to do your private browsing on.

For more on browser privacy, see <https://www.browserleaks.com/> and <https://panopticlick.eff.org/>.

## VPN
If you use your Mac on untrusted networks - airports, cafes, etc. - your network traffic is being monitored and possibly tampered with.

It is a good idea to use a VPN which encrypts **all** outgoing network traffic (i.e., not **split tunnel**) with a provider you trust. Ideally, that provider is a server in your house or a trustworthy "cloud".

Don't just blindly sign up for a VPN service without understanding the full implications and how your traffic will be routed. If you don't understand how the VPN works or are not familiar with the software used, you are probably better off without it.

## Viruses and malware
There is an increasing amount of Mac malware in the wild; Macs aren't immune from viruses and malicious software.

Some of the malware comes bundled with both legitimate software, such as the [Java bundling Ask Toolbar](http://www.zdnet.com/article/oracle-extends-its-adware-bundling-to-include-java-for-macs/), and some with illegitimate software, such as [Mac.BackDoor.iWorm](https://docs.google.com/document/d/1YOfXRUQJgMjJSLBSoLiUaSZfiaS_vU3aG4Bvjmz6Dxs/edit?pli=1) bundled with pirated programs.

See [Methods of malware persistence on Mac OS X](https://www.virusbtn.com/pdf/conference/vb2014/VB2014-Wardle.pdf) [pdf] and [Malware Persistence on OS X Yosemite](https://www.rsaconference.com/events/us15/agenda/sessions/1591/malware-persistence-on-os-x-yosemite) to learn about how garden-variety malware functions.

You can periodically run a tool like [Knock Knock](https://github.com/synack/knockknock) to examine persistent binaries (e.g. scripts, binaries). But by then, it is probably too late. Maybe [Block Block](https://objective-see.com/products/blockblock.html) will help.

**Anti-virus** programs are not useful for advanced users and **will** increase your attack surface against sophisticated threats. See [Sophail: Applied attacks against Sophos Antivirus](https://lock.cmpxchg8b.com/sophailv2.pdf) [pdf] and [Analysis and Exploitation of an ESET Vulnerability](http://googleprojectzero.blogspot.ro/2015/06/analysis-and-exploitation-of-eset.html). The best anti-virus is **Common Sense 2015**.

Local **privilege escalation** bugs are plenty on OS X, so always be careful when downloading and running untrusted programs or trusted programs from third party websites or downloaded over HTTP ([example](http://arstechnica.com/security/2015/08/0-day-bug-in-fully-patched-os-x-comes-under-active-exploit-to-hijack-macs/)).

Have a look at [The Safe Mac](http://www.thesafemac.com/) for past and current Mac security news.

Check out [Hacking Team](https://www.schneier.com/blog/archives/2015/07/hacking_team_is.html) malware for Mac OS: [root installation for MacOS](https://github.com/hackedteam/vector-macos-root), [Support driver for Mac Agent](https://github.com/hackedteam/driver-macos) and [RCS Agent for Mac](https://github.com/hackedteam/core-macos). Good example of malware which hides from **userland** (`ps`, `ls`, etc). and is very difficult to detect.

## Gatekeeper and Xprotect

**Gatekeeper** and the **quarantine** system try to prevent unsigned or "bad" programs and files from running and opening.

**Xprotect** prevents the execution of known bad files and outdated plugin versions, but does nothing to cleanup or stop existing malware.

Both offer trivial protection against common risks and are fine at default settings.

See <http://www.thesafemac.com/mmg-builtin/>

and <http://ilostmynotes.blogspot.com/2012/06/gatekeeper-xprotect-and-quarantine.html>

**Note** Quarantine stores information about downloaded files in `~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`. See [here](http://www.zoharbabin.com/hey-mac-i-dont-appreciate-you-spying-on-me-hidden-downloads-log-in-os-x/) for more information.

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
You can generate passwords with `gpg`, `openssl` or just get creative with `/dev/urandom` output.

    openssl rand -base64 30

    gpg --gen-random -a 0 30

    dd if=/dev/urandom bs=1 count=30 2>/dev/null | base64

You can also generate passwords from **Keychain Access** password assistant, or a command line equivalent like [anders/pwgen](https://github.com/anders/pwgen).

**Keychains** are encrypted with a [PBKDF2 derived key](https://en.wikipedia.org/wiki/PBKDF2) and are a _pretty safe_ place to store credentials. See also [Breaking into the OS X keychain](http://juusosalonen.com/post/30923743427/breaking-into-the-os-x-keychain).

Alternatively, you can manage an encrypted passwords file yourself with `gpg` (shameless plug for my [pwd.sh](https://github.com/drduh/pwd.sh) script).

In addition to passwords, ensure your online accounts (such as github, google accounts, etc.) have [two factor authentication](https://en.wikipedia.org/wiki/Two-factor_authentication) enabled.

Look to [Yubikey](https://www.yubico.com/products/yubikey-hardware/yubikey-neo/) for a two factor and private key (e.g., ssh, gpg) hardware token.

## Wi-Fi
OS X remembers access points it has connected to. Like all wireless devices, your Mac will broadcast all of these access point names it remembers (e.g. *So-and-so's Router*) each time it looks for a network (e.g. wake from sleep).

This is a privacy risk, so remove networks from the list in **System Preferences** when they're no longer needed.

## Physical access
Keep your Mac physically secure at all times. Don't leave it unattended in hotels and such.

For example, a skilled attacker with unsupervised physical access to your computer can infect the boot ROM to install a keylogger and steal your password - see <https://trmm.net/Thunderstrike>.

## System monitoring

#### Open Source Monitoring Tools

[etsy/MIDAS](https://github.com/etsy/MIDAS) is a framework for developing a Mac Intrusion Detection Analysis System.  Credits given to the security team at Facebook and Etsy in developing this framework.  This framework consists of utilities which help detect any modifications that have been made to common OS X persistence mechanisms.

[facebook/osquery](https://github.com/facebook/osquery) can be used to retrieve low level system information.  Users can write SQL queries to retrieve system information.  More information can be found at <https://osquery.io/>.

[google/grr](https://github.com/google/grr) is an incident response framework focused on remote live forensics.

[jipegit/OSXAuditor](https://github.com/jipegit/OSXAuditor) can be used to analyze artifacts on a running system, such as:

 - Quarantined files
 - Browser information
 	- Safari history, downloads, topsites, LastSession, HTML5 databases and localstore
 	- Firefox cookies, downloads, formhistory, permissions, places and signons
 	- Chrome history and archives history, cookies, login data, top sites, web data, HTML5
 - User social media and email accounts
 - WiFi access points

#### OpenBSM Audit
OS X has a powerful OpenBSM auditing capability. You can use it to monitor process execution, network activity, and much more.

Use `sudo praudit -l /dev/auditpipe` to tail audit logs.

Some example events,

    header,201,11,execve(2),0,Thu Sep  1 12:00:00 2015, + 195 msec,exec arg,/Applications/.evilapp/rootkit,path,/Applications/.evilapp/rootkit,path,/Applications/.evilapp/rootkit,attribute,100755,root,wheel,16777220,986535,0,subject,drduh,root,wheel,root,wheel,412,100005,50511731,0.0.0.0,return,success,0,trailer,201,

	header,88,11,connect(2),0,Thu Sep  1 12:00:00 2015, + 238 msec,argument,1,0x5,fd,socket-inet,2,443,173.194.74.104,subject,drduh,root,wheel,root,wheel,326,100005,50331650,0.0.0.0,return,failure : Operation now in progress,4354967105,trailer,88
	
	header,111,11,OpenSSH login,0,Thu Sep  1 12:00:00 2015, + 16 msec,subject_ex,drduh,drduh,staff,drduh,staff,404,404,49271,::1,text,successful login drduh,return,success,0,trailer,111,
	
See the manual pages for `audit`, `praudit`, `audit_control` and other files in `/etc/security`

**Note** although `man audit` says the `-s` flag will synchronize the audit configuration, it is actually necessary to reboot for changes to take effect.

See articles on [ilostmynotes.blogspot.com](http://ilostmynotes.blogspot.com/2013/10/openbsm-auditd-on-os-x-these-are-logs.html) and [derflounder.wordpress.com](https://derflounder.wordpress.com/2012/01/30/openbsm-auditing-on-mac-os-x/) for more information.

#### DTrace

`iosnoop` monitors disk I/O.

`opensnoop` monitors file opens.

`execsnoop` monitors execution of processes.

`errinfo` monitors failed system calls.

`dtruss` monitors all system calls.

See `man -k dtrace` for more.

#### Network

Here's a few examples of networking monitoring commands

    sudo lsof -ni -P
    
    sudo netstat -atln

You can also use Wireshark from the command line.

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

If you want to play **music** or watch **videos**, use [VLC media player](https://www.videolan.org/vlc/index.html) which is free and open source.

If you want to **torrent**, use [Transmission](http://www.transmissionbt.com/download/) which is free and open source.

Watch the system log with **Console** or the `syslog -w` command.

Enable [tty_tickets](http://blog.rongarret.info/2015/08/psa-beware-of-sudo-on-os-x.html) in the sudoers file.

Hash your known ssh hosts. To `ssh_config`, add

    Host *
      HashKnownHosts yes

Set your screen to lock as soon as the screensaver starts

    defaults write com.apple.screensaver askForPassword -int 1
    defaults write com.apple.screensaver askForPasswordDelay -int 0

Expose hidden files and Library folder in Finder

    defaults write com.apple.finder AppleShowAllFiles -bool true
    chflags nohidden ~/Library

Don't default to saving documents to iCloud

    defaults write NSGlobalDomain NSDocumentSaveNewDocumentsToCloud -bool false

Consider [sandboxing](https://developer.apple.com/library/mac/documentation/Darwin/Reference/ManPages/man1/sandbox-exec.1.html) your applications. See [fG! Sandbox Guide](https://reverse.put.as/wp-content/uploads/2011/09/Apple-Sandbox-Guide-v0.1.pdf) [pdf] and [s7ephen/OSX-Sandbox--Seatbelt--Profiles](https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles).

Did you know Apple has not shipped a computer with TPM since [2006](http://osxbook.com/book/bonus/chapter10/tpm/)?

## Additional resources

[OS X Yosemite Core Technologies Overview White Paper](https://www.apple.com/osx/pdf/OSXYosemite_TO_FF1.pdf)

[Reversing Engineering Mac OS X blog](https://reverse.put.as/)

[Reverse Engineering Resources](http://samdmarshall.com/re.html)

[Patrick Wardle's Objective-See blog](https://objective-see.com/blog.html)

[Dylib Hijack Scanner](https://objective-see.com/products/dhs.html)

[Managing Macs at Google Scale (LISA '13)](https://www.usenix.org/conference/lisa13/managing-macs-google-scale)

[OS X Hardening: Securing a Large Global Mac Fleet (LISA '13)](https://www.usenix.org/conference/lisa13/os-x-hardening-securing-large-global-mac-fleet)

[Yelp's forensic evidence collection & analysis toolkit for OS X](https://github.com/yelp/osxcollector)

[DoD Security Technical Implementation Guides for Mac OS](http://iase.disa.mil/stigs/os/mac/Pages/mac-os.aspx)

[The EFI boot process](http://homepage.ntlworld.com/jonathan.deboynepollard/FGA/efi-boot-process.html)

[Userland Persistence on Mac OS X](https://archive.org/details/joshpitts_shmoocon2015)

[Developing Mac OSX kernel rootkits](http://phrack.org/issues/66/16.html#article)

[IOKit kernel code execution exploit](https://code.google.com/p/google-security-research/issues/detail?id=135)

[Hidden backdoor API to root privileges in Apple OS X](https://truesecdev.wordpress.com/2015/04/09/hidden-backdoor-api-to-root-privileges-in-apple-os-x/)

[Santa: A binary whitelisting/blacklisting system for Mac OS X](https://github.com/google/santa/)

[IPv6 Hardening Guide for OS X](http://www.insinuator.net/2015/02/ipv6-hardening-guide-for-os-x/)

[Preventing OS X from phoning home to Cupertino](https://github.com/l1k/osxparanoia)

[Yosemite net-monitor](https://github.com/fix-macosx/net-monitor)

[Hacker News discussion](https://news.ycombinator.com/item?id=10148077)

[Apple Open Source](https://opensource.apple.com/)

[OS X 10.10 Yosemite: The Ars Technica Review](http://arstechnica.com/apple/2014/10/os-x-10-10/)

[CIS Apple OSX 10.10 Benchmark](https://benchmarks.cisecurity.org/tools2/osx/CIS_Apple_OSX_10.10_Benchmark_v1.0.0.pdf) [pdf]
