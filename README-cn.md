> * 原文地址：[macOS Security and Privacy Guide](https://github.com/drduh/macOS-Security-and-Privacy-Guide)
* 原文作者：[drduh](https://github.com/drduh)
* 译文出自：[掘金翻译计划](https://github.com/xitu/gold-miner)
* 译者：
* 校对者：

This is a collection of thoughts on securing a modern Apple Mac computer using macOS (formerly *"OS X"*) 10.12 "Sierra", as well as steps to improving online privacy.

This guide is targeted to “power users” who wish to adopt enterprise-standard security, but is also suitable for novice users with an interest in improving their privacy and security on a Mac.

A system is only as secure as its administrator is capable of making it. There is no one single technology, software, nor technique to guarantee perfect computer security; a modern operating system and computer is very complex, and requires numerous incremental changes to meaningfully improve one's security and privacy posture.

I am **not** responsible if you break a Mac by following any of these steps.

If you wish to make a correction or improvement, please send a pull request or [open an issue](https://github.com/drduh/OS-X-Security-and-Privacy-Guide/issues).

- [Basics](#basics)
- [Firmware](#firmware)
- [Preparing and Installing macOS](#preparing-and-installing-macos)
    - [Virtualization](#virtualization)
- [First boot](#first-boot)
- [Admin and standard user accounts](#admin-and-standard-user-accounts)
- [Full disk encryption](#full-disk-encryption)
- [Firewall](#firewall)
    - [Application layer firewall](#application-layer-firewall)
    - [Third party firewalls](#third-party-firewalls)
    - [Kernel level packet filtering](#kernel-level-packet-filtering)
- [Services](#services)
- [Spotlight Suggestions](#spotlight-suggestions)
- [Homebrew](#homebrew)
- [DNS](#dns)
    - [Hosts file](#hosts-file)
    - [Dnsmasq](#dnsmasq)
      - [Test DNSSEC validation](#test-dnssec-validation)
    - [DNSCrypt](#dnscrypt)
- [Captive portal](#captive-portal)
- [Certificate authorities](#certificate-authorities)
- [OpenSSL](#openssl)
- [Curl](#curl)
- [Web](#web)
    - [Privoxy](#privoxy)
    - [Browser](#browser)
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
    - [OpenBSM audit](#openbsm-audit)
    - [DTrace](#dtrace)
    - [Execution](#execution)
    - [Network](#network)
- [Miscellaneous](#miscellaneous)
- [Related software](#related-software)
- [Additional resources](#additional-resources)

## Basics

The standard best security practices apply:

* Create a threat model
    * What are you trying to protect and from whom? Is your adversary a [three letter agency](https://theintercept.com/document/2015/03/10/strawhorse-attacking-macos-ios-software-development-kit/) (if so, you may want to consider using [OpenBSD](http://www.openbsd.org/) instead), a nosy eavesdropper on the network, or determined [apt](https://en.wikipedia.org/wiki/Advanced_persistent_threat) orchestrating a campaign against you?
    * Study and recognize threats and how to reduce attack surface.

* Keep the system up to date
    * Patch, patch, patch your system and software.
    * macOS system updates can be completed using the App Store application, or the `softwareupdate` command-line utility - neither requires registering an Apple account.
    * Subscribe to announcement mailing lists (e.g., [Apple security-announce](https://lists.apple.com/mailman/listinfo/security-announce)) for programs you use often.

* Encrypt sensitive data
    * In addition to full disk encryption, create one or many encrypted containers to store passwords, keys and personal documents.
    * This will mitigate damage in case of compromise and data exfiltration.

* Frequent backups
    * Create regular backups of your data and be ready to reimage in case of compromise.
    * Always encrypt before copying backups to external media or the "cloud".

* Click carefully
    * Ultimately, the security of a system can be reduced to its administrator.
    * Care should be taken when installing new software. Always prefer [free](https://www.gnu.org/philosophy/free-sw.en.html) and open source software ([which macOS is not](https://superuser.com/questions/19492/is-mac-os-x-open-source)).

## Firmware

Setting a firmware password prevents your Mac from starting up from any device other than your startup disk. It may also be set to be required on each boot.

This feature [can be helpful if your laptop is stolen](https://www.ftc.gov/news-events/blogs/techftc/2015/08/virtues-strong-enduser-device-controls), as the only way to reset the firmware password is through an Apple Store, or by using an [SPI programmer](https://reverse.put.as/2016/06/25/apple-efi-firmware-passwords-and-the-scbo-myth/), such as [Bus Pirate](http://ho.ax/posts/2012/06/unbricking-a-macbook/) or other flash IC programmer.

1. Start up pressing `Command` `R` keys to boot to [Recovery Mode](https://support.apple.com/en-au/HT201314) mode.

3. When the Recovery window appears, choose **Firmware Password Utility** from the Utilities menu.

4. In the Firmware Utility window that appears, select **Turn On Firmware Password**.

5. Enter a new password, then enter the same password in the **Verify** field.

6. Select **Set Password**.

7. Select **Quit Firmware Utility** to close the Firmware Password Utility.

8. Select the Apple menu and choose Restart or Shutdown.

The firmware password will activate at next boot. To validate the password, hold `Alt` during boot - you should be prompted to enter the password.

The firmware password can also be managed with the `firmwarepasswd` utility while booted into the OS.

<img width="750" alt="Using a Dediprog SF600 to dump and flash a 2013 MacBook SPI Flash chip to remove a firmware password, sans Apple" src="https://cloud.githubusercontent.com/assets/12475110/17075918/0f851c0c-50e7-11e6-904d-0b56cf0080c1.png">

*Using a [Dediprog SF600](http://www.dediprog.com/pd/spi-flash-solution/sf600) to dump and flash a 2013 MacBook SPI Flash chip to remove a firmware password, sans Apple*

See [HT204455](https://support.apple.com/en-au/HT204455), [LongSoft/UEFITool](https://github.com/LongSoft/UEFITool) and [chipsec/chipsec](https://github.com/chipsec/chipsec) for more information.

## Preparing and Installing macOS

There are several ways to install a fresh copy of macOS.

The simplest way is to boot into [Recovery Mode](https://support.apple.com/en-us/HT201314) by holding `Command` `R` keys at boot. A system image can be downloaded and applied directly from Apple. However, this way exposes the serial number and other identifying information over the network in plaintext.

<img width="500" alt="PII is transmitted to Apple in plaintext when using macOS Recovery" src="https://cloud.githubusercontent.com/assets/12475110/20312189/8987c958-ab20-11e6-90fa-7fd7c8c1169e.png">

*Packet capture of an unencrypted HTTP conversation during macOS recovery*

Another way is to download **macOS Sierra** from the [App Store](https://itunes.apple.com/us/app/macos-sierra/id1127487414) or some other place and create a custom, installable system image.

The macOS Sierra installer application is [code signed](https://developer.apple.com/library/mac/documentation/Security/Conceptual/CodeSigningGuide/Procedures/Procedures.html#//apple_ref/doc/uid/TP40005929-CH4-SW6), which should be verified to make sure you received a legitimate copy, using the `codesign` command:

```
$ codesign -dvv /Applications/Install\ macOS\ Sierra.app
Executable=/Applications/Install macOS Sierra.app/Contents/MacOS/InstallAssistant
Identifier=com.apple.InstallAssistant.Sierra
Format=app bundle with Mach-O thin (x86_64)
CodeDirectory v=20200 size=297 flags=0x200(kill) hashes=5+5 location=embedded
Signature size=4167
Authority=Apple Mac OS Application Signing
Authority=Apple Worldwide Developer Relations Certification Authority
Authority=Apple Root CA
Info.plist entries=30
TeamIdentifier=K36BKF7T3D
Sealed Resources version=2 rules=7 files=137
Internal requirements count=1 size=124
```

macOS installers can be made with the `createinstallmedia` utility included in `Install macOS Sierra.app/Contents/Resources/`. See [Create a bootable installer for OS X Yosemite](https://support.apple.com/en-us/HT201372), or run the utility without arguments to see how it works.

**Note** Apple's installer [does not appear to work](https://github.com/drduh/OS-X-Security-and-Privacy-Guide/issues/120) across OS versions. If you want to build a 10.12 image, for example, the following steps must be run on a 10.12 machine!

To create a **bootable USB macOS installer**, mount a USB drive, and erase and partition it, then use the `createinstallmedia` utility:

```
$ diskutil list
[Find disk matching correct size, usually "disk2"]

$ diskutil unmountDisk /dev/disk2

$ diskutil partitionDisk /dev/disk2 1 JHFS+ Installer 100%

$ cd /Applications/Install\ macOS\ Sierra.app

$ sudo ./Contents/Resources/createinstallmedia --volume /Volumes/Installer --applicationpath /Applications/Install\ macOS\ Sierra.app --nointeraction
Erasing Disk: 0%... 10%... 20%... 30%... 100%...
Copying installer files to disk...
Copy complete.
Making disk bootable...
Copying boot files...
Copy complete.
Done.
```

To create a custom, installable image which can be [restored](https://en.wikipedia.org/wiki/Apple_Software_Restore) to a Mac, you will need to find the file `InstallESD.dmg`, which is also inside `Install macOS Sierra.app`.

With Finder, right click on the app, select **Show Package Contents** and navigate to **Contents** > **SharedSupport** to find the file `InstallESD.dmg`.

You can [verify](https://support.apple.com/en-us/HT201259) the following cryptographic hashes to ensure you have the same copy with `openssl sha1 InstallESD.dmg` or `shasum -a 1 InstallESD.dmg` or `shasum -a 256 InstallESD.dmg` (in Finder, you can drag the file into a Terminal window to provide the full path).

See [InstallESD_Hashes.csv](https://github.com/drduh/OS-X-Security-and-Privacy-Guide/blob/master/InstallESD_Hashes.csv) in this repository for a list of current and previous file hashes. You can also Google the cryptographic hashes to ensure the file is genuine and has not been tampered with.

To create the image, use [MagerValp/AutoDMG](https://github.com/MagerValp/AutoDMG), or to create it manually, mount and install the operating system to a temporary image:

    $ hdiutil attach -mountpoint /tmp/install_esd ./InstallESD.dmg

    $ hdiutil create -size 32g -type SPARSE -fs HFS+J -volname "macOS" -uid 0 -gid 80 -mode 1775 /tmp/output.sparseimage

    $ hdiutil attach -mountpoint /tmp/os -owners on /tmp/output.sparseimage

    $ sudo installer -pkg /tmp/install_esd/Packages/OSInstall.mpkg -tgt /tmp/os -verbose

This part will take a while, so be patient. You can `tail -F /var/log/install.log` in another Terminal window to check progress.

**(Optional)** Install additional software, such as [Wireshark](https://www.wireshark.org/download.html):

    $ hdiutil attach Wireshark\ 2.2.0\ Intel\ 64.dmg

    $ sudo installer -pkg /Volumes/Wireshark/Wireshark\ 2.2.0\ Intel\ 64.pkg -tgt /tmp/os

    $ hdiutil unmount /Volumes/Wireshark

See [MagerValp/AutoDMG/wiki/Packages-Suitable-for-Deployment](https://github.com/MagerValp/AutoDMG/wiki/Packages-Suitable-for-Deployment) for caveats and [chilcote/outset](https://github.com/chilcote/outset) to instead processes packages and scripts at first boot.

When you're done, detach, convert and verify the image:

    $ hdiutil detach /tmp/os

    $ hdiutil detach /tmp/install_esd

    $ hdiutil convert -format UDZO /tmp/output.sparseimage -o ~/sierra.dmg

    $ asr imagescan --source ~/sierra.dmg

Now `sierra.dmg` is ready to be applied to one or multiple Macs. One could futher customize the image to include premade users, applications, preferences, etc.

This image can be installed using another Mac in [Target Disk Mode](https://support.apple.com/en-us/HT201462) or from a bootable USB installer.

To use **Target Disk Mode**, boot up the Mac you wish to image while holding the `T` key and connect it to another Mac using a Firewire, Thunderbolt or USB-C cable.

If you don't have another Mac, boot to a USB installer, with `sierra.dmg` and other required files copied to it, by holding the *Option* key at boot.

Run `diskutil list` to identify the connected Mac's disk, usually `/dev/disk2`

**(Optional)** [Securely erase](https://www.backblaze.com/blog/securely-erase-mac-ssd/) the disk with a single pass (if previously FileVault-encrypted, the disk must first be unlocked and mounted as `/dev/disk3s2`):

    $ sudo diskutil secureErase freespace 1 /dev/disk3s2

Partition the disk to Journaled HFS+:

    $ sudo diskutil unmountDisk /dev/disk2

    $ sudo diskutil partitionDisk /dev/disk2 1 JHFS+ macOS 100%

Restore the image to the new volume:

    $ sudo asr restore --source ~/sierra.dmg --target /Volumes/macOS --erase --buffersize 4m

You can also use the **Disk Utility** application to erase the connected Mac's disk, then restore `sierra.dmg` to the newly created partition.

If you've followed these steps correctly, the target Mac should now have a new install of macOS Sierra.

If you want to transfer any files, copy them to a shared folder like `/Users/Shared` on the mounted disk image, e.g. `cp Xcode_8.0.dmg /Volumes/macOS/Users/Shared`

<img width="1280" alt="Finished restore install from USB recovery boot" src="https://cloud.githubusercontent.com/assets/12475110/14804078/f27293c8-0b2d-11e6-8e1f-0fb0ac2f1a4d.png">

*Finished restore install from USB recovery boot*

We're not done yet! Unless you have built the image with [AutoDMG](https://github.com/MagerValp/AutoDMG), or installed macOS to a second partition on your Mac, you will need to create a recovery partition (in order to use full disk encryption). You can do so using [MagerValp/Create-Recovery-Partition-Installer](https://github.com/MagerValp/Create-Recovery-Partition-Installer) or using the following manual steps:

Download the file [RecoveryHDUpdate.dmg](https://support.apple.com/downloads/DL1464/en_US/RecoveryHDUpdate.dmg).

```
RecoveryHDUpdate.dmg
SHA-256: f6a4f8ac25eaa6163aa33ac46d40f223f40e58ec0b6b9bf6ad96bdbfc771e12c
SHA-1:   1ac3b7059ae0fcb2877d22375121d4e6920ae5ba
```

Attach and expand the installer, then run it:

```
$ hdiutil attach RecoveryHDUpdate.dmg

$ pkgutil --expand /Volumes/Mac\ OS\ X\ Lion\ Recovery\ HD\ Update/RecoveryHDUpdate.pkg /tmp/recovery

$ hdiutil attach /tmp/recovery/RecoveryHDUpdate.pkg/RecoveryHDMeta.dmg

$ /tmp/recovery/RecoveryHDUpdate.pkg/Scripts/Tools/dmtest ensureRecoveryPartition /Volumes/macOS/ /Volumes/Recovery\ HD\ Update/BaseSystem.dmg 0 0 /Volumes/Recovery\ HD\ Update/BaseSystem.chunklist
```

Replace `/Volumes/macOS` with the path to the target disk mode-booted Mac as necessary.

This step will take several minutes. Run `diskutil list` again to make sure **Recovery HD** now exists on `/dev/disk2` or equivalent identifier.

Once you're done, eject the disk with `hdiutil unmount /Volumes/macOS` and power down the target disk mode-booted Mac.

### Virtualization

To install macOS as a virtual machine (vm) using [VMware Fusion](https://www.vmware.com/products/fusion.html), follow the instructions above to create an image. You will **not** need to download and create a recovery partition manually.

```
VMware-Fusion-8.5.2-4635224.dmg
SHA-256: f6c54b98c9788d1df94d470661eedff3e5d24ca4fb8962fac5eb5dc56de63b77
SHA-1:   37ec465673ab802a3f62388d119399cb94b05408
```

For the Installation Method, select *Install OS X from the recovery partition*. Customize any memory or CPU requirements and complete setup. The guest vm should boot into [Recovery Mode](https://support.apple.com/en-us/HT201314) by default.

In Recovery Mode, select a language, then Utilities > Terminal from the menubar.

In the guest vm, type `ifconfig | grep inet` - you should see a private address like `172.16.34.129`

On the host Mac, type `ifconfig | grep inet` - you should see a private gateway address like `172.16.34.1`

From the host Mac, serve the installable image to the guest vm by editing `/etc/apache2/httpd.conf` and adding the following line to the top (using the gateway address assigned to the host Mac and port 80):

    Listen 172.16.34.1:80

On the host Mac, link the image to the default Apache Web server directory:

    $ sudo ln ~/sierra.dmg /Library/WebServer/Documents

From the host Mac, start Apache in the foreground:

    $ sudo httpd -X

From the guest VM, install the disk image to the volume over the local network using `asr`:

```
-bash-3.2# asr restore --source http://172.16.34.1/sierra.dmg --target /Volumes/Macintosh\ HD/ --erase --buffersize 4m
    Validating target...done
    Validating source...done
    Erase contents of /dev/disk0s2 (/Volumes/Macintosh HD)? [ny]: y
    Retrieving scan information...done
    Validating sizes...done
    Restoring  ....10....20....30....40....50....60....70....80....90....100
    Verifying  ....10....20....30....40....50....60....70....80....90....100
    Remounting target volume...done
```

When it's finished, stop the Apache Web server on the host Mac by pressing `Control` `C` at the `sudo httpd -X` window and remove the image copy with `sudo rm /Library/WebServer/Documents/sierra.dmg`

In the guest vm, select *Startup Disk* from the top-left corner Apple menu, select the hard drive and restart. You may wish to disable the Network Adapter in VMware for the initial guest vm boot.

Take and Restore from saved guest vm snapshots before and after attempting risky browsing, for example, or use a guest vm to install and operate questionable software.

## First boot

**Note** Before setting up macOS, consider disconnecting networking and configuring a firewall(s) first.

On first boot, hold `Command` `Option` `P` `R` keys to [clear NVRAM](https://support.apple.com/en-us/HT204063).

When macOS first starts, you'll be greeted by **Setup Assistant**.

When creating your account, use a [strong password](http://www.explainxkcd.com/wiki/index.php/936:_Password_Strength) without a hint.

If you enter your real name at the account setup process, be aware that your [computer's name and local hostname](https://support.apple.com/kb/PH18720) will be comprised of that name (e.g., *John Appleseed's MacBook*) and thus will appear on local networks and in various preference files. You can change them both in **System Preferences > Sharing** or with the following commands:

    $ sudo scutil --set ComputerName your_computer_name

    $ sudo scutil --set LocalHostName your_hostname

## Admin and standard user accounts

The first user account is always an admin account. Admin accounts are members of the admin group and have access to `sudo`, which allows them to usurp other accounts, in particular root, and gives them effective control over the system. Any program that the admin executes can potentially obtain the same access, making this a security risk. Utilities like `sudo` have [weaknesses that can be exploited](https://bogner.sh/2014/03/another-mac-os-x-sudo-password-bypass/) by concurrently running programs and many panes in System Preferences are [unlocked by default](http://csrc.nist.gov/publications/drafts/800-179/sp800_179_draft.pdf) [p. 61–62] for admin accounts. It is considered a best practice by [Apple](https://help.apple.com/machelp/mac/10.12/index.html#/mh11389) and [others](http://csrc.nist.gov/publications/drafts/800-179/sp800_179_draft.pdf) [p. 41–42] to use a separate standard account for day-to-day work and use the admin account for installations and system configuration.

It is not strictly required to ever log into the admin account via the OS X login screen. The system will prompt for authentication when required and Terminal can do the rest. To that end, Apple provides some [recommendations](https://support.apple.com/HT203998) for hiding the admin account and its home directory. This can be an elegant solution to avoid having a visible 'ghost' account. The admin account can also be [removed from FileVault](http://apple.stackexchange.com/a/94373).

#### Caveats

1. Only administrators can install applications in `/Applications` (local directory). Finder and Installer will prompt a standard user with an authentication dialog. Many applications can be installed in `~/Applications` instead (the directory can be created manually). As a rule of thumb: applications that do not require admin access – or do not complain about not being installed in `/Applications` – should be installed in the user directory, the rest in the local directory. Mac App Store applications are still installed in `/Applications` and require no additional authentication.

2. `sudo` is not available in shells of the standard user, which requires using `su` or `login` to enter a shell of the admin account. This can make some maneuvers trickier and requires some basic experience with command-line interfaces.

3. System Preferences and several system utilities (e.g. Wi-Fi Diagnostics) will require root privileges for full functionality. Many panels in System Preferences are locked and need to be unlocked separately by clicking on the lock icon. Some applications will simply prompt for authentication upon opening, others must be opened by an admin account directly to get access to all functions (e.g. Console).

4. There are third-party applications that will not work correctly because they assume that the user account is an admin. These programs may have to be executed by logging into the admin account, or by using the `open` utility.

#### Setup

Accounts can be created and managed in System Preferences. On settled systems, it is generally easier to create a second admin account and then demote the first account. This avoids data migration. Newly installed systems can also just add a standard account. Demoting an account can be done either from the the new admin account in System Preferences – the other account must be logged out – or by executing this command:
```
sudo dscl . -delete /Groups/admin GroupMembership user_name
```

## Full disk encryption

[FileVault](https://en.wikipedia.org/wiki/FileVault) provides full disk (technically, full _volume_) encryption on macOS.

FileVault encryption will protect data at rest and prevent someone with physical access from stealing data or tampering with your Mac.

With much of the cryptographic operations happening [efficiently in hardware](https://software.intel.com/en-us/articles/intel-advanced-encryption-standard-aes-instructions-set/), the performance penalty for FileVault is not noticeable.

The security of FileVault greatly depends on the pseudo random number generator (PRNG).

> The random device implements the Yarrow pseudo random number generator algorithm and maintains its entropy pool.  Additional entropy is fed to the generator regularly by the SecurityServer daemon from random jitter measurements of the kernel.

> SecurityServer is also responsible for periodically saving some entropy to disk and reloading it during startup to provide entropy in early system operation.

See `man 4 random` for more information.

The PRNG can be manually seeded with entropy by writing to /dev/random **before** enabling FileVault. This can be done by simply using the Mac for a little while before activating FileVault.

To manually seed entropy *before* enabling FileVault:

    $ cat > /dev/random
    [Type random letters for a long while, then press Control-D]

Enable FileVault with `sudo fdesetup enable` or through **System Preferences** > **Security & Privacy** and reboot.

If you can remember your password, there's no reason to save the **recovery key**. However, your encrypted data will be lost forever if you can't remember the password or recovery key.

If you want to know more about how FileVault works, see the paper [Infiltrate the Vault: Security Analysis and Decryption of Lion Full Disk Encryption](https://eprint.iacr.org/2012/374.pdf) (pdf) and related [presentation](http://www.cl.cam.ac.uk/~osc22/docs/slides_fv2_ifip_2013.pdf) (pdf). Also see [IEEE Std 1619-2007 “The XTS-AES Tweakable Block Cipher”](http://libeccio.di.unisa.it/Crypto14/Lab/p1619.pdf) (pdf).

You may wish to enforce **hibernation** and evict FileVault keys from memory instead of traditional sleep to memory:

    $ sudo pmset -a destroyfvkeyonstandby 1
    $ sudo pmset -a hibernatemode 25

> All computers have firmware of some type—EFI, BIOS—to help in the discovery of hardware components and ultimately to properly bootstrap the computer using the desired OS instance. In the case of Apple hardware and the use of EFI, Apple stores relevant information within EFI to aid in the functionality of OS X. For example, the FileVault key is stored in EFI to transparently come out of standby mode.

> Organizations especially sensitive to a high-attack environment, or potentially exposed to full device access when the device is in standby mode, should mitigate this risk by destroying the FileVault key in firmware. Doing so doesn’t destroy the use of FileVault, but simply requires the user to enter the password in order for the system to come out of standby mode.

If you choose to evict FileVault keys in standby mode, you should also modify your standby and power nap settings. Otherwise, your machine may wake while in standby mode and then power off due to the absence of the FileVault key. See [issue #124](https://github.com/drduh/OS-X-Security-and-Privacy-Guide/issues/124) for more information. These settings can be changed with:

    $ sudo pmset -a powernap 0
    $ sudo pmset -a standby 0
    $ sudo pmset -a standbydelay 0
    $ sudo pmset -a autopoweroff 0

For more information, see [Best Practices for
Deploying FileVault 2](http://training.apple.com/pdf/WP_FileVault2.pdf) (pdf) and paper [Lest We Remember: Cold Boot Attacks on Encryption Keys](https://www.usenix.org/legacy/event/sec08/tech/full_papers/halderman/halderman.pdf) (pdf)

## Firewall

Before connecting to the Internet, it's a good idea to first configure a firewall.

There are several types of firewall available for macOS.

#### Application layer firewall

Built-in, basic firewall which blocks **incoming** connections only.

Note, this firewall does not have the ability to monitor, nor block **outgoing** connections.

It can be controlled by the **Firewall** tab of **Security & Privacy** in **System Preferences**, or with the following commands.

Enable the firewall:

    $ sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on

Enable logging:

    $ sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setloggingmode on

You may also wish to enable stealth mode:

    $ sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on

> Computer hackers scan networks so they can attempt to identify computers to attack. You can prevent your computer from responding to some of these scans by using **stealth mode**. When stealth mode is enabled, your computer does not respond to ICMP ping requests, and does not answer to connection attempts from a closed TCP or UDP port. This makes it more difficult for attackers to find your computer.

Finally, you may wish to prevent *built-in software* as well as *code-signed, downloaded software from being whitelisted automatically*:

    $ sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setallowsigned off

    $ sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setallowsignedapp off

> Applications that are signed by a valid certificate authority are automatically added to the list of allowed apps, rather than prompting the user to authorize them. Apps included in OS X are signed by Apple and are allowed to receive incoming connections when this setting is enabled. For example, since iTunes is already signed by Apple, it is automatically allowed to receive incoming connections through the firewall.

> If you run an unsigned app that is not listed in the firewall list, a dialog appears with options to Allow or Deny connections for the app. If you choose Allow, OS X signs the application and automatically adds it to the firewall list. If you choose Deny, OS X adds it to the list but denies incoming connections intended for this app.

After interacting with `socketfilterfw`, you may want to restart (or terminate) the process:

    $ sudo pkill -HUP socketfilterfw

#### Third party firewalls

Programs such as [Little Snitch](https://www.obdev.at/products/littlesnitch/index.html), [Hands Off](https://www.oneperiodic.com/products/handsoff/), [Radio Silence](http://radiosilenceapp.com/) and [Security Growler](https://pirate.github.io/security-growler/) provide a good balance of usability and security.

<img width="349" alt="Example of Little Snitch monitored session" src="https://cloud.githubusercontent.com/assets/12475110/10596588/c0eed3c0-76b3-11e5-95b8-9ce7d51b3d82.png">

*Example of Little Snitch-monitored session*

```
LittleSnitch-3.7.dmg
SHA-256: 5c44d853dc4178fb227abd3e8eee19ef1bf0d576f49b5b6a9a7eddf6ae7ea951
SHA-1:   1320ca9bcffb8ff8105b7365e792db6dc7b9f46a
```

These programs are capable of monitoring and blocking **incoming** and **outgoing** network connections. However, they may require the use of a closed source [kernel extension](https://developer.apple.com/library/mac/documentation/Darwin/Conceptual/KernelProgramming/Extend/Extend.html).

If the number of choices of allowing/blocking network connections is overwhelming, use **Silent Mode** with connections allowed, then periodically check your settings to gain understanding of what various applications are doing.

It is worth noting that these firewalls can be bypassed by programs running as **root** or through [OS vulnerabilities](https://www.blackhat.com/docs/us-15/materials/us-15-Wardle-Writing-Bad-A-Malware-For-OS-X.pdf) (pdf), but they are still worth having - just don't expect absolute protection.

For more on how Little Snitch works, see the [Network Kernel Extensions Programming Guide](https://developer.apple.com/library/mac/documentation/Darwin/Conceptual/NKEConceptual/socket_nke/socket_nke.html#//apple_ref/doc/uid/TP40001858-CH228-SW1) and [Shut up snitch! – reverse engineering and exploiting a critical Little Snitch vulnerability](https://reverse.put.as/2016/07/22/shut-up-snitch-reverse-engineering-and-exploiting-a-critical-little-snitch-vulnerability/).

#### Kernel level packet filtering

A highly customizable, powerful, but also most complicated firewall exists in the kernel. It can be controlled with `pfctl` and various configuration files.

pf can also be controlled with a GUI application such as [IceFloor](http://www.hanynet.com/icefloor/) or [Murus](http://www.murusfirewall.com/).

There are many books and articles on the subject of pf firewall. Here's is just one example of blocking traffic by IP address.

Add the following into a file called `pf.rules`:

```
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
```

Use the following commands:

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

See [fix-macosx/yosemite-phone-home](https://github.com/fix-macosx/yosemite-phone-home), [l1k/osxparanoia](https://github.com/l1k/osxparanoia) and [karek314/macOS-home-call-drop](https://github.com/karek314/macOS-home-call-drop) for further recommendations.

Services on macOS are managed by **launchd**. See (launchd.info)[http://launchd.info/], as well as [Apple's Daemons and Services Programming Guide](https://developer.apple.com/library/mac/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html) and [Technical Note TN2083](https://developer.apple.com/library/mac/technotes/tn2083/_index.html)

You can also run [KnockKnock](https://github.com/synack/knockknock) that shows more information about startup items.

* Use `launchctl list` to view running user agents
* Use `sudo launchctl list` to view running system daemons
* Specify the service name to examine it, e.g. `launchctl list com.apple.Maps.mapspushd`
* Use `defaults read` to examine job plists in `/System/Library/LaunchDaemons` and `/System/Library/LaunchAgents`
* Use `man`, `strings` and Google to learn about what the agent/daemon runs

For example, to learn what a system launch daemon or agent does, start with:

    $ defaults read /System/Library/LaunchDaemons/com.apple.apsd.plist

Look at the `Program` or `ProgramArguments` section to see which binary is run, in this case `apsd`. To find more information about that, look at the man page with `man apsd`

For example, if you're not interested in Apple Push Notifications, disable the service:

    $ sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.apsd.plist

**Note** Unloading services may break usability of some applications. Read the manual pages and use Google to make sure you understand what you're doing first.

Be careful about disabling any system daemons you don't understand, as it may render your system unbootable. If you break your Mac, use [single user mode](https://support.apple.com/en-us/HT201573) to fix it.

Use [Console](https://en.wikipedia.org/wiki/Console_(OS_X)) and [Activity Monitor](https://support.apple.com/en-us/HT201464) applications if you notice your Mac heating up, feeling sluggish, or generally misbehaving, as it may have resulted from your tinkering.

To view currently disabled services:

    $ find /var/db/com.apple.xpc.launchd/ -type f -print -exec defaults read {} \; 2>/dev/null

Annotated lists of launch daemons and agents, the respective program executed, and the programs' hash sums are included in this repository.

**(Optional)** Run the `read_launch_plists.py` script and `diff` output to check for any discrepancies on your system, e.g.:

    $ diff <(python read_launch_plists.py) <(cat 16A323_launchd.csv)

See also [cirrusj.github.io/Yosemite-Stop-Launch](http://cirrusj.github.io/Yosemite-Stop-Launch/) for descriptions of services and [Provisioning OS X and Disabling Unnecessary Services](https://vilimpoc.org/blog/2014/01/15/provisioning-os-x-and-disabling-unnecessary-services/) for another explanation.

## Spotlight Suggestions

Disable **Spotlight Suggestions** in both the Spotlight preferences and Safari's Search preferences to avoid your search queries being sent to Apple.

Also disable **Bing Web Searches** in the Spotlight preferences to avoid your search queries being sent to Microsoft.

See [fix-macosx.com](https://fix-macosx.com/) for detailed instructions.

> If you've upgraded to Mac OS X Yosemite (10.10) and you're using the default settings, each time you start typing in Spotlight (to open an application or search for a file on your computer), your local search terms and location are sent to Apple and third parties (including Microsoft).

To download, view and apply their suggested fixes:

```
$ curl -O https://fix-macosx.com/fix-macosx.py

$ less fix-macosx.py

$ python fix-macosx.py
All done. Make sure to log out (and back in) for the changes to take effect.
```

Speaking of Microsoft, you may want to see <https://fix10.isleaked.com/> just for fun.

## Homebrew

Consider using [Homebrew](http://brew.sh/) to make software installations easier and to update userland tools (see [Apple’s great GPL purge](http://meta.ath0.com/2012/02/05/apples-great-gpl-purge/)).

**Note** If you have not already installed Xcode or Command Line Tools, use `xcode-select --install` to download and install them from Apple.

To [install Homebrew](https://github.com/Homebrew/brew/blob/master/docs/Installation.md#installation):

    $ mkdir homebrew && curl -L https://github.com/Homebrew/brew/tarball/master | tar xz --strip 1 -C homebrew

Edit `PATH` in your shell or shell rc file to use `~/homebrew/bin` and `~/homebrew/sbin`. For example, `echo 'PATH=$PATH:~/homebrew/sbin:~/homebrew/bin' >> .zshrc`, then change your login shell to Z shell with `chsh -s /bin/zsh`, open a new Terminal window and run `brew update`.

Homebrew uses SSL/TLS to talk with GitHub and verifies checksums of downloaded packages, so it's [fairly secure](https://github.com/Homebrew/homebrew/issues/18036).

Remember to periodically run `brew update` and `brew upgrade` on trusted and secure networks to download and install software updates. To get information on a package before installation, run `brew info <package>` and check its recipe online.

According to [Homebrew's Anonymous Aggregate User Behaviour Analytics](https://github.com/Homebrew/brew/blob/master/docs/Analytics.md), Homebrew gathers anonymous aggregate user behaviour analytics and reporting these to Google Analytics.

To opt out of Homebrew's analytics, you can set `export HOMEBREW_NO_ANALYTICS=1` in your environment or shell rc file, or use `brew analytics off`.

You may also wish to enable [additional security options](https://github.com/drduh/macOS-Security-and-Privacy-Guide/issues/138), such as `HOMEBREW_NO_INSECURE_REDIRECT=1` and `HOMEBREW_CASK_OPTS=--require-sha`.

## DNS

#### Hosts file

Use the [hosts file](https://en.wikipedia.org/wiki/Hosts_(file)) to block known malware, advertising or otherwise unwanted domains.

Edit the hosts file as root, for example with `sudo vi /etc/hosts`. The hosts file can also be managed with the GUI app [2ndalpha/gasmask](https://github.com/2ndalpha/gasmask).

To block a domain, append `0 example.com` or `0.0.0.0 example.com` or `127.0.0.1 example.com` to `/etc/hosts`

There are many lists of domains available online which you can paste in, just make sure each line starts with `0`, `0.0.0.0`, `127.0.0.1`, and the line `127.0.0.1 localhost` is included.

For hosts lists, see [someonewhocares.org](http://someonewhocares.org/hosts/zero/hosts), [l1k/osxparanoia/blob/master/hosts](https://github.com/l1k/osxparanoia/blob/master/hosts), [StevenBlack/hosts](https://github.com/StevenBlack/hosts) and [gorhill/uMatrix/hosts-files.json](https://github.com/gorhill/uMatrix/blob/master/assets/umatrix/hosts-files.json).

To append a raw list:

```
$ curl "https://raw.githubusercontent.com/StevenBlack/hosts/master/hosts" | sudo tee -a /etc/hosts

$ wc -l /etc/hosts
31998

$ egrep -ve "^#|^255.255.255|^0.0.0.0|^127.0.0.0|^0 " /etc/hosts
::1 localhost
fe80::1%lo0 localhost
[should not return any other IP addresses]
```

See `man hosts` and [FreeBSD Configuration Files](https://www.freebsd.org/doc/handbook/configtuning-configfiles.html) for more information.

#### Dnsmasq

Among other features, [dnsmasq](http://www.thekelleys.org.uk/dnsmasq/doc.html) is able to cache replies, prevent upstreaming queries for unqualified names, and block entire TLDs.

Use in combination with DNSCrypt to additionally encrypt outgoing DNS traffic.

If you don't wish to use DNSCrypt, you should at least use DNS [not provided](http://bcn.boulder.co.us/~neal/ietf/verisign-abuse.html) [by your ISP](http://hackercodex.com/guide/how-to-stop-isp-dns-server-hijacking/). Two popular alternatives are [Google DNS](https://developers.google.com/speed/public-dns/) and [OpenDNS](https://www.opendns.com/home-internet-security/).

**(Optional)** [DNSSEC](https://en.wikipedia.org/wiki/Domain_Name_System_Security_Extensions) is a set of extensions to DNS which provide to DNS clients (resolvers) origin authentication of DNS data, authenticated denial of existence, and data integrity. All answers from DNSSEC protected zones are digitally signed. The signed records are authenticated via a chain of trust, starting with a set of verified public keys for the DNS root-zone. The current root-zone trust anchors may be downloaded [from IANA website](https://www.iana.org/dnssec/files). There are a number of resources on DNSSEC, but probably the best one is [dnssec.net website](http://www.dnssec.net).

Install Dnsmasq (DNSSEC is optional):

    $ brew install dnsmasq --with-dnssec

    $ cp ~/homebrew/opt/dnsmasq/dnsmasq.conf.example ~/homebrew/etc/dnsmasq.conf

Edit the configuration:

    $ vim ~/homebrew/etc/dnsmasq.conf

Examine all the options. Here are a few recommended settings to enable:

```
# Forward queries to DNSCrypt on localhost port 5355
server=127.0.0.1#5355

# Uncomment to forward queries to Google Public DNS
#server=8.8.8.8

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
log-facility=/var/log/dnsmasq.log

# Uncomment to log all queries
#log-queries

# Uncomment to enable DNSSEC
#dnssec
#trust-anchor=.,19036,8,2,49AAC11D7B6F6446702E54A1607371607A1A41855200FD2CE1CDDE32F24E8FB5
#dnssec-check-unsigned
```

Install and start the program:

    $ brew services start dnsmasq

To set Dnsmasq as your local DNS server, open **System Preferences** > **Network** and select the active interface, then the **DNS** tab, select **+** and add `127.0.0.1`, or use:

    $ sudo networksetup -setdnsservers "Wi-Fi" 127.0.0.1

Make sure Dnsmasq is correctly configured:

```
$ scutil --dns
DNS configuration

resolver #1
  search domain[0] : whatever
  nameserver[0] : 127.0.0.1
  flags    : Request A records, Request AAAA records
  reach    : Reachable, Local Address, Directly Reachable Address

$ networksetup -getdnsservers "Wi-Fi"
127.0.0.1
```

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

Install DNSCrypt from Homebrew:

    $ brew install dnscrypt-proxy

If using in combination with Dnsmasq, find the file `homebrew.mxcl.dnscrypt-proxy.plist`

```
$ find ~/homebrew -name homebrew.mxcl.dnscrypt-proxy.plist
/Users/drduh/homebrew/Cellar/dnscrypt-proxy/1.7.0/homebrew.mxcl.dnscrypt-proxy.plist
```

Edit it to have the line:

    <string>--local-address=127.0.0.1:5355</string>

Below the line:

    <string>/usr/local/opt/dnscrypt-proxy/sbin/dnscrypt-proxy</string>

<img width="1015" alt="dnscrypt" src="https://cloud.githubusercontent.com/assets/12475110/19222914/8e6f853e-8e31-11e6-8dd6-27c33cbfaea5.png">

*Append a local-address line to use DNScrypt on a port other than 53, like 5355*

This can also be done using Homebrew, by installing `gnu-sed` and using the `gsed` command:

    $ sudo gsed -i "/sbin\\/dnscrypt-proxy<\\/string>/a<string>--local-address=127.0.0.1:5355<\\/string>\n" $(find ~/homebrew -name homebrew.mxcl.dnscrypt-proxy.plist)

By default, the `resolvers-list` will point to the dnscrypt version specific resolvers file. When dnscrypt is updated, this version may no longer exist, and if it does, may point to an outdated file. This can be fixed by changing the resolvers file in `/Library/LaunchDaemons/homebrew.mxcl.dnscrypt-proxy.plist` to the symlinked version in `/usr/local/share`:

    <string>--resolvers-list=/usr/local/share/dnscrypt-proxy/dnscrypt-resolvers.csv</string>

Start DNSCrypt:

    $ brew services start dnscrypt-proxy

Make sure DNSCrypt is running:

```
$ sudo lsof -Pni UDP:5355
COMMAND   PID   USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
dnscrypt-  83 nobody    7u  IPv4 0x1773f85ff9f8bbef      0t0  UDP 127.0.0.1:5355

$ ps A | grep '[d]nscrypt'
   83   ??  Ss     0:00.27 /Users/drduh/homebrew/opt/dnscrypt-proxy/sbin/dnscrypt-proxy --local-address=127.0.0.1:5355 --ephemeral-keys --resolvers-list=/Users/drduh/homebrew/opt/dnscrypt-proxy/share/dnscrypt-proxy/dnscrypt-resolvers.csv --resolver-name=dnscrypt.eu-dk --user=nobody
```

> By default, dnscrypt-proxy runs on localhost (127.0.0.1), port 53,
and under the "nobody" user using the dnscrypt.eu-dk DNSCrypt-enabled
resolver. If you would like to change these settings, you will have to edit the plist file (e.g., --resolver-address, --provider-name, --provider-key, etc.)

This can be accomplished by editing `homebrew.mxcl.dnscrypt-proxy.plist`

You can run your own [dnscrypt server](https://github.com/Cofyc/dnscrypt-wrapper) (see also [drduh/Debian-Privacy-Server-Guide#dnscrypt](https://github.com/drduh/Debian-Privacy-Server-Guide#dnscrypt)) from a trusted location or use one of many [public servers](https://github.com/jedisct1/dnscrypt-proxy/blob/master/dnscrypt-resolvers.csv) instead.

Confirm outgoing DNS traffic is encrypted:

```
$ sudo tcpdump -qtni en0
IP 10.8.8.8.59636 > 77.66.84.233.443: UDP, length 512
IP 77.66.84.233.443 > 10.8.8.8.59636: UDP, length 368

$ dig +short -x 77.66.84.233
resolver2.dnscrypt.eu
```

See also [What is a DNS leak](https://dnsleaktest.com/what-is-a-dns-leak.html), the [mDNSResponder manual page](https://developer.apple.com/library/mac/documentation/Darwin/Reference/ManPages/man8/mDNSResponder.8.html) and [ipv6-test.com](http://ipv6-test.com/).

## Captive portal

When macOS connects to new networks, it **probes** the network and launches a Captive Portal assistant utility if connectivity can't be determined.

An attacker could trigger the utility and direct a Mac to a site with malware without user interaction, so it's best to disable this feature and log in to captive portals using your regular Web browser, provided you have first disable any custom dns and/or proxy settings.

    $ sudo defaults write /Library/Preferences/SystemConfiguration/com.apple.captive.control Active -bool false

See also [Apple OS X Lion Security: Captive Portal Hijacking Attack](https://www.securestate.com/blog/2011/10/07/apple-os-x-lion-captive-portal-hijacking-attack), [Apple's secret "wispr" request](http://blog.erratasec.com/2010/09/apples-secret-wispr-request.html), [How to disable the captive portal window in Mac OS Lion](https://web.archive.org/web/20130407200745/http://www.divertednetworks.net/apple-captiveportal.html), and [An undocumented change to Captive Network Assistant settings in OS X 10.10 Yosemite](https://grpugh.wordpress.com/2014/10/29/an-undocumented-change-to-captive-network-assistant-settings-in-os-x-10-10-yosemite/).

## Certificate authorities

macOS comes with [over 200](https://support.apple.com/en-us/HT202858) root authority certificates installed from for-profit corporations like Apple, Verisign, Thawte, Digicert and government agencies from China, Japan, Netherlands, U.S., and more! These Certificate Authorities (CAs) are capable of issuing SSL/TLS certificates for any domain, code signing certificates, etc.

For more information, see [Certification Authority Trust Tracker](https://github.com/kirei/catt), [Analysis of the HTTPS certificate ecosystem](http://conferences.sigcomm.org/imc/2013/papers/imc257-durumericAemb.pdf) (pdf), and [You Won’t Be Needing These Any More: On Removing Unused Certificates From Trust Stores](http://www.ifca.ai/fc14/papers/fc14_submission_100.pdf) (pdf).

You can inspect system root certificates in **Keychain Access**, under the **System Roots** tab or by using the `security` command line tool and `/System/Library/Keychains/SystemRootCertificates.keychain` file.

You can disable certificate authorities through Keychain Access by marking them as **Never Trust** and closing the window:

<img width="450" alt="A certificate authority certificate" src="https://cloud.githubusercontent.com/assets/12475110/19222972/6b7aabac-8e32-11e6-8efe-5d3219575a98.png">

The risk of a [man in the middle](https://en.wikipedia.org/wiki/Man-in-the-middle_attack) attack in which a coerced or compromised certificate authority trusted by your system issues a fake/rogue SSL certificate is quite low, but still [possible](https://en.wikipedia.org/wiki/DigiNotar#Issuance_of_fraudulent_certificates).

## OpenSSL

The version of OpenSSL in Sierra is `0.9.8zh` which is [not current](https://apple.stackexchange.com/questions/200582/why-is-apple-using-an-older-version-of-openssl). It doesn't support TLS 1.1 or newer, elliptic curve ciphers, and [more](https://stackoverflow.com/questions/27502215/difference-between-openssl-09-8z-and-1-0-1).

Apple declares OpenSSL **deprecated** in their [Cryptographic Services Guide](https://developer.apple.com/library/mac/documentation/Security/Conceptual/cryptoservices/GeneralPurposeCrypto/GeneralPurposeCrypto.html) document. Their version also has patches which may [surprise you](https://hynek.me/articles/apple-openssl-verification-surprises/).

If you're going to use OpenSSL on your Mac, download and install a recent version of OpenSSL with `brew install openssl`. Note, linking brew to be used in favor of `/usr/bin/openssl` may interfere with building software. See [issue #39](https://github.com/drduh/OS-X-Security-and-Privacy-Guide/issues/39).

Compare the TLS protocol and cipher between the homebrew version and the system version of OpenSSL:

```
$ ~/homebrew/bin/openssl version; echo | ~/homebrew/bin openssl s_client -connect github.com:443 2>&1 | grep -A2 SSL-Session
OpenSSL 1.0.2j  26 Sep 2016
SSL-Session:
    Protocol  : TLSv1.2
    Cipher    : ECDHE-RSA-AES128-GCM-SHA256

$ /usr/bin/openssl version; echo | /usr/bin/openssl s_client -connect github.com:443 2>&1 | grep -A2 SSL-Session
OpenSSL 0.9.8zh 14 Jan 2016
SSL-Session:
    Protocol  : TLSv1
    Cipher    : AES128-SHA
```

See also [Comparison of TLS implementations](https://en.wikipedia.org/wiki/Comparison_of_TLS_implementations), [How's My SSL](https://www.howsmyssl.com/), [Qualys SSL Labs Tools](https://www.ssllabs.com/projects/) and for detailed explanations and with latest vulnerabilities tests [ssl-checker.online-domain-tools.com](http://ssl-checker.online-domain-tools.com).

## Curl

The version of Curl which comes with macOS uses [Secure Transport](https://developer.apple.com/library/mac/documentation/Security/Reference/secureTransportRef/) for SSL/TLS validation.

If you prefer to use OpenSSL, install with `brew install curl --with-openssl` and ensure it's the default with `brew link --force curl`

Here are several recommended [options](http://curl.haxx.se/docs/manpage.html) to add to `~/.curlrc` (see `man curl` for more):

```
user-agent = "Mozilla/5.0 (Windows NT 6.1; rv:45.0) Gecko/20100101 Firefox/45.0"
referer = ";auto"
connect-timeout = 10
progress-bar
max-time = 90
verbose
show-error
remote-time
ipv4
```

## Web

### Privoxy

Consider using [Privoxy](http://www.privoxy.org/) as a local proxy to filter Web browsing traffic.

A signed installation package for privoxy can be downloaded from [silvester.org.uk](http://silvester.org.uk/privoxy/OSX/) or [Sourceforge](http://sourceforge.net/projects/ijbswa/files/Macintosh%20%28OS%20X%29/). The signed package is [more secure](https://github.com/drduh/OS-X-Security-and-Privacy-Guide/issues/65) than the Homebrew version, and attracts full support from the Privoxy project.

Alternatively, install and start privoxy using Homebrew:

    $ brew install privoxy

    $ brew services start privoxy

By default, privoxy listens on local TCP port 8118.

Set the system **http** proxy for your active network interface `127.0.0.1` and `8118` (This can be done through **System Preferences > Network > Advanced > Proxies**):

    $ sudo networksetup -setwebproxy "Wi-Fi" 127.0.0.1 8118

**(Optional)** Set the system **https** proxy, which still allows for domain name filtering, with:

    $ sudo networksetup -setsecurewebproxy "Wi-Fi" 127.0.0.1 8118

Confirm the proxy is set:

```
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

Visit <http://p.p/> in a browser, or with Curl:

```
$ ALL_PROXY=127.0.0.1:8118 curl -I http://p.p/
HTTP/1.1 200 OK
Content-Length: 2401
Content-Type: text/html
Cache-Control: no-cache
```

Privoxy already comes with many good rules, however you can also write your own.

Edit `~/homebrew/etc/privoxy/user.action` to filter elements by domain or with regular expressions.

Here are some examples:

```
{ +block{social networking} }
www.facebook.com/(extern|plugins)/(login_status|like(box)?|activity|fan)\.php
.facebook.com

{ +block{unwanted images} +handle-as-image }
.com/ads/
/.*1x1.gif
/.*fb-icon.[jpg|gif|png]
/assets/social-.*
/cleardot.gif
/img/social.*
ads.*.co.*/
ads.*.com/

{ +redirect{s@http://@https://@} }
.google.com
.wikipedia.org
code.jquery.com
imgur.com
```

Verify Privoxy is blocking and redirecting:

```
$ ALL_PROXY=127.0.0.1:8118 curl ads.foo.com/ -IL
HTTP/1.1 403 Request blocked by Privoxy
Content-Type: image/gif
Content-Length: 64
Cache-Control: no-cache

$ ALL_PROXY=127.0.0.1:8118 curl imgur.com/ -IL
HTTP/1.1 302 Local Redirect from Privoxy
Location: https://imgur.com/
Content-Length: 0
Date: Sun, 09 Oct 2016 18:48:19 GMT

HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
```

You can replace ad images with pictures of kittens, for example, by starting the a local Web server and [redirecting blocked requests](https://www.privoxy.org/user-manual/actions-file.html#SET-IMAGE-BLOCKER) to localhost.

### Browser

The Web browser poses the largest security and privacy risk, as its fundamental job is to download and execute untrusted code from the Internet.

Use [Google Chrome](https://www.google.com/chrome/browser/desktop/) for most of your browsing. It offers [separate profiles](https://www.chromium.org/user-experience/multi-profiles), [good sandboxing](https://www.chromium.org/developers/design-documents/sandbox), [frequent updates](http://googlechromereleases.blogspot.com/) (including Flash, although you should disable it - see below), and carries [impressive credentials](https://www.chromium.org/Home/chromium-security/brag-sheet).

Chrome also comes with a great [PDF viewer](http://0xdabbad00.com/2013/01/13/most-secure-pdf-viewer-chrome-pdf-viewer/).

If you don't want to use Chrome, [Firefox](https://www.mozilla.org/en-US/firefox/new/) is an excellent browser as well. Or simply use both. See discussion in issues [#2](https://github.com/drduh/OS-X-Security-and-Privacy-Guide/issues/2), [#90](https://github.com/drduh/OS-X-Security-and-Privacy-Guide/issues/90).

If using Firefox, see [TheCreeper/PrivacyFox](https://github.com/TheCreeper/PrivacyFox) for recommended privacy preferences. Also be sure to check out [NoScript](https://noscript.net/) for Mozilla-based browsers, which allows whitelist-based, pre-emptive script blocking.

Create at least three profiles, one for browsing **trusted** Web sites (email, banking), another for **mostly trusted** Web sites (link aggregators, news sites), and a third for a completely **cookie-less** and **script-less** experience.

* One profile **without cookies or Javascript** enabled (e.g., turned off in `chrome://settings/content`) which should be the preferred profile to visiting untrusted Web sites. However, many pages will not load at all without Javascript enabled.

* One profile with [uMatrix](https://github.com/gorhill/uMatrix) or [uBlock Origin](https://github.com/gorhill/uBlock) (or both). Use this profile for visiting **mostly trusted** Web sites. Take time to learn how these firewall extensions work. Other frequently recommended extensions are [Privacy Badger](https://www.eff.org/privacybadger), [HTTPSEverywhere](https://www.eff.org/https-everywhere) and [CertPatrol](http://patrol.psyced.org/) (Firefox only).

* One or more profile(s) for secure and trusted browsing needs, such as banking and email only.

The idea is to separate and compartmentalize data, so that an exploit or privacy violation in one "session" does not necessarily affect data in another.

In each profile, visit `chrome://plugins/` and disable **Adobe Flash Player**. If you must use Flash, visit `chrome://settings/contents` to enable **Let me choose when to run plugin content**, under the Plugins section (also known as *click-to-play*).

Take some time to read through [Chromium Security](https://www.chromium.org/Home/chromium-security) and [Chromium Privacy](https://www.chromium.org/Home/chromium-privacy).

For example you may wish to disable [DNS prefetching](https://www.chromium.org/developers/design-documents/dns-prefetching) (see also [DNS Prefetching and Its Privacy Implications](https://www.usenix.org/legacy/event/leet10/tech/full_papers/Krishnan.pdf) (pdf)).

Also be aware of [WebRTC](https://en.wikipedia.org/wiki/WebRTC#Concerns), which may reveal your local or public (if connected to VPN) IP address(es). This can be disabled with extensions such as [uBlock Origin](https://github.com/gorhill/uBlock/wiki/Prevent-WebRTC-from-leaking-local-IP-address) and [rentamob/WebRTC-Leak-Prevent](https://github.com/rentamob/WebRTC-Leak-Prevent).

Many Chromium-derived browsers are not recommended. They are usually [closed source](http://yro.slashdot.org/comments.pl?sid=4176879&cid=44774943), [poorly maintained](https://plus.google.com/+JustinSchuh/posts/69qw9wZVH8z), [have bugs](https://code.google.com/p/google-security-research/issues/detail?id=679), and make dubious claims to protect privacy. See [The Private Life of Chromium Browsers](http://thesimplecomputer.info/the-private-life-of-chromium-browsers).

Safari is not recommended. The code is a mess and [security](https://nakedsecurity.sophos.com/2014/02/24/anatomy-of-a-goto-fail-apples-ssl-bug-explained-plus-an-unofficial-patch/) [vulnerabilities](https://vimeo.com/144872861) are frequent, and slower to patch (see [discussion on Hacker News](https://news.ycombinator.com/item?id=10150038)). Security does [not appear](https://discussions.apple.com/thread/5128209) to be a priority for Safari. If you do use it, at least [disable](https://thoughtsviewsopinions.wordpress.com/2013/04/26/how-to-stop-downloaded-files-opening-automatically/) the **Open "safe" files after downloading** option in Preferences, and be aware of other [privacy nuances](https://github.com/drduh/OS-X-Security-and-Privacy-Guide/issues/93).

Other miscellaneous browsers, such as [Brave](https://github.com/drduh/OS-X-Security-and-Privacy-Guide/issues/94), are not evaluated in this guide, so are neither recommended nor actively discouraged from use.

For more information about security conscious browsing, see [HowTo: Privacy & Security Conscious Browsing](https://gist.github.com/atcuno/3425484ac5cce5298932), [browserleaks.com](https://www.browserleaks.com/) and [EFF Panopticlick](https://panopticlick.eff.org/).

### Plugins

**Adobe Flash**, **Oracle Java**, **Adobe Reader**, **Microsoft Silverlight** (Netflix now works with [HTML5](https://help.netflix.com/en/node/23742)) and other plugins are [security risks](https://news.ycombinator.com/item?id=9901480) and should not be installed.

If they are necessary, only use them in a disposable virtual machine and subscribe to security announcements to make sure you're always patched.

See [Hacking Team Flash Zero-Day](http://blog.trendmicro.com/trendlabs-security-intelligence/hacking-team-flash-zero-day-integrated-into-exploit-kits/), [Java Trojan BackDoor.Flashback](https://en.wikipedia.org/wiki/Trojan_BackDoor.Flashback), [Acrobat Reader: Security Vulnerabilities](http://www.cvedetails.com/vulnerability-list/vendor_id-53/product_id-497/Adobe-Acrobat-Reader.html), and [Angling for Silverlight Exploits](https://blogs.cisco.com/security/angling-for-silverlight-exploits), for example.

## PGP/GPG

PGP is a standard for encrypting email end to end. That means only the chosen recipients can decrypt a message, unlike regular email which is read and forever archived by providers.

**GPG**, or **GNU Privacy Guard**, is a GPL licensed program compliant with the standard.

**GPG** is used to verify signatures of software you download and install, as well as [symmetrically](https://en.wikipedia.org/wiki/Symmetric-key_algorithm) or [asymmetrically](https://en.wikipedia.org/wiki/Public-key_cryptography) encrypt files and text.

Install from Homebrew with `brew install gnupg2`.

If you prefer a graphical application, download and install [GPG Suite](https://gpgtools.org/).

Here are several [recommended options](https://github.com/drduh/config/blob/master/gpg.conf) to add to `~/.gnupg/gpg.conf`:

```
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
s2k-cipher-algo AES256
charset utf-8
fixed-list-mode
no-comments
no-emit-version
keyid-format 0xlong
list-options show-uid-validity
verify-options show-uid-validity
with-fingerprint
```

Install the keyservers [CA certificate](https://sks-keyservers.net/verify_tls.php):

    $ curl -O https://sks-keyservers.net/sks-keyservers.netCA.pem

    $ sudo mv sks-keyservers.netCA.pem /etc

These settings will configure GnuPG to use SSL when fetching new keys and prefer strong cryptographic primitives.

See also [ioerror/duraconf/configs/gnupg/gpg.conf](https://github.com/ioerror/duraconf/blob/master/configs/gnupg/gpg.conf). You should also take some time to read [OpenPGP Best Practices](https://help.riseup.net/en/security/message-security/openpgp/best-practices).

If you don't already have a keypair, create one using `gpg --gen-key`. Also see [drduh/YubiKey-Guide](https://github.com/drduh/YubiKey-Guide).

Read [online](https://alexcabal.com/creating-the-perfect-gpg-keypair/) [guides](https://security.stackexchange.com/questions/31594/what-is-a-good-general-purpose-gnupg-key-setup) and practice encrypting and decrypting email to yourself and your friends. Get them interested in this stuff!

## OTR

OTR stands for **off-the-record** and is a cryptographic protocol for encrypting and authenticating conversations over instant messaging.

You can use OTR on top of any existing [XMPP](https://xmpp.org/about) chat service, even Google Hangouts (which only encrypts conversations between users and the server using TLS).

The first time you start a conversation with someone new, you'll be asked to verify their public key fingerprint. Make sure to do this in person or by some other secure means (e.g. GPG encrypted mail).

A popular macOS GUI client for XMPP and other chat protocols is [Adium](https://adium.im/)

Consider downloading the [beta version](https://beta.adium.im/) which uses OAuth2, making logging in to Google accounts [more](https://adium.im/blog/2015/04/) [secure](https://trac.adium.im/ticket/16161).

```
Adium_1.5.11b3.dmg
SHA-256: 999e1931a52dc327b3a6e8492ffa9df724a837c88ad9637a501be2e3b6710078
SHA-1:   ca804389412f9aeb7971ade6812f33ac739140e6
```

Remember to [disable logging](https://trac.adium.im/ticket/15722) for OTR chats with Adium.

A good console-based XMPP client is [profanity](http://www.profanity.im/), which can be installed with `brew install profanity`

For improved anonymity, check out [Tor Messenger](https://blog.torproject.org/blog/tor-messenger-beta-chat-over-tor-easily), although it is still in beta, as well as [Ricochet](https://ricochet.im/) (which has recently received a thorough [security audit](https://ricochet.im/files/ricochet-ncc-audit-2016-01.pdf) (pdf)), which both use the Tor network rather than relying on messaging servers.

If you want to know how OTR works, read the paper [Off-the-Record Communication, or, Why Not To Use PGP](https://otr.cypherpunks.ca/otr-wpes.pdf) (pdf)

## Tor

Tor is an anonymizing proxy which can be used for browsing the Web.

Download Tor Browser from the [offical Tor Project Web site](https://www.torproject.org/projects/torbrowser.html).

Do **not** attempt to configure other browsers or applications to use Tor as you will likely make a mistake which will compromise your anonymity.

Download both the `dmg` and `asc` signature files, then verify the disk image has been signed by Tor developers:

```
$ cd Downloads

$ file Tor*
TorBrowser-6.0.5-osx64_en-US.dmg:     bzip2 compressed data, block size = 900k
TorBrowser-6.0.5-osx64_en-US.dmg.asc: PGP signature Signature (old)

$ gpg Tor*asc
gpg: assuming signed data in `TorBrowser-6.0.5-osx64_en-US.dmg'
gpg: Signature made Fri Sep 16 07:51:52 2016 EDT using RSA key ID D40814E0
gpg: Can't check signature: public key not found

$ gpg --recv 0xD40814E0
gpg: requesting key D40814E0 from hkp server keys.gnupg.net
gpg: key 93298290: public key "Tor Browser Developers (signing key) <torbrowser@torproject.org>" imported
gpg: no ultimately trusted keys found
gpg: Total number processed: 1
gpg:               imported: 1  (RSA: 1)

$ gpg Tor*asc
gpg: assuming signed data in 'TorBrowser-6.0.5-osx64_en-US.dmg'
gpg: Signature made Fri Sep 16 07:51:52 2016 EDT using RSA key ID D40814E0
gpg: Good signature from "Tor Browser Developers (signing key) <torbrowser@torproject.org>" [unknown]
gpg: WARNING: This key is not certified with a trusted signature!
gpg:          There is no indication that the signature belongs to the owner.
Primary key fingerprint: EF6E 286D DA85 EA2A 4BA7  DE68 4E2C 6E87 9329 8290
     Subkey fingerprint: BA1E E421 BBB4 5263 180E  1FC7 2E1A C68E D408 14E0
```

Make sure `Good signature from "Tor Browser Developers (signing key) <torbrowser@torproject.org>"` appears in the output. The warning about the key not being certified is benign, as it has not yet been manually assigned trust.

See [How to verify signatures for packages](https://www.torproject.org/docs/verifying-signatures.html) for more information.

To finish installing Tor Browser, open the disk image and drag the it into the Applications folder, or with:

```
$ hdiutil mount TorBrowser-6.0.5-osx64_en-US.dmg

$ cp -rv /Volumes/Tor\ Browser/TorBrowser.app /Applications
```

Tor traffic is **encrypted** to the [exit node](https://en.wikipedia.org/wiki/Tor_(anonymity_network)#Exit_node_eavesdropping) (cannot be read by a passive network eavesdropper), but Tor use **can** be identified - for example, TLS handshake "hostnames" will show up in plaintext:

```
$ sudo tcpdump -An "tcp" | grep "www"
listening on pktap, link-type PKTAP (Apple DLT_PKTAP), capture size 262144 bytes
.............". ...www.odezz26nvv7jeqz1xghzs.com.........
.............#.!...www.bxbko3qi7vacgwyk4ggulh.com.........
.6....m.....>...:.........|../* Z....W....X=..6...C../....................................0...0..0.......'....F./0..    *.H........0%1#0!..U....www.b6zazzahl3h3faf4x2.com0...160402000000Z..170317000000Z0'1%0#..U....www.tm3ddrghe22wgqna5u8g.net0..0..
```

See [Tor Protocol Specification](https://gitweb.torproject.org/torspec.git/tree/tor-spec.txt) and [Tor/TLSHistory](https://trac.torproject.org/projects/tor/wiki/org/projects/Tor/TLSHistory) for more information.

You may wish to additionally obfuscate Tor traffic using a [pluggable transport](https://www.torproject.org/docs/pluggable-transports.html), such as [Yawning/obfs4proxy](https://github.com/Yawning/obfs4) or [SRI-CSL/stegotorus](https://github.com/SRI-CSL/stegotorus).

This can be done by setting up your own [Tor relay](https://www.torproject.org/docs/tor-relay-debian.html) or finding an existing private or public [bridge](https://www.torproject.org/docs/bridges.html.en#RunningABridge) to serve as an obfuscating entry node.

For extra security, use Tor inside a [VirtualBox](https://www.virtualbox.org/wiki/Downloads) or [VMware](https://www.vmware.com/products/fusion) virtualized [GNU/Linux](http://www.brianlinkletter.com/installing-debian-linux-in-a-virtualbox-virtual-machine/) or [BSD](http://www.openbsd.org/faq/faq4.html) machine.

Finally, remember the Tor network provides [anonymity](https://www.privateinternetaccess.com/blog/2013/10/how-does-privacy-differ-from-anonymity-and-why-are-both-important/), which is not necessarily synonymous with privacy. The Tor network does not guarantee protection against a global observer capable of traffic analysis and [correlation](https://blog.torproject.org/category/tags/traffic-correlation). See also [Seeking Anonymity in an Internet Panopticon](http://bford.info/pub/net/panopticon-cacm.pdf) (pdf) and [Traffic Correlation on Tor by Realistic Adversaries](http://www.ohmygodel.com/publications/usersrouted-ccs13.pdf) (pdf).

Also see [Invisible Internet Project (I2P)](https://geti2p.net/en/about/intro) and its [Tor comparison](https://geti2p.net/en/comparison/tor).

## VPN

If you use your Mac on untrusted networks - airports, cafes, etc. - your network traffic is being monitored and possibly tampered with.

It is a good idea to use a VPN which encrypts **all** outgoing network traffic (i.e., not **split tunnel**) with a provider you trust. For an example of how to set up and host your own VPN, see [drduh/Debian-Privacy-Server-Guide](https://github.com/drduh/Debian-Privacy-Server-Guide).

Don't just blindly sign up for a VPN service without understanding the full implications and how your traffic will be routed. If you don't understand how the VPN works or are not familiar with the software used, you are probably better off without it.

When choosing a VPN service or setting up your own, be sure to research the protocols, key exchange algorithms, authentication mechanisms, and type of encryption being used. Some protocols, such as [PPTP](https://en.wikipedia.org/wiki/Point-to-Point_Tunneling_Protocol#Security), should be avoided in favor of [OpenVPN](https://en.wikipedia.org/wiki/OpenVPN), for example.

Some clients may send traffic over the next available interface when VPN is interrupted or disconnected. See [scy/8122924](https://gist.github.com/scy/8122924) for an example on how to allow traffic only over VPN.

Another set of scripts to lock down your system so it will only access the internet via a VPN can be found as part of the Voodoo Privacy project - [sarfata/voodooprivacy](https://github.com/sarfata/voodooprivacy) and there is an updated guide to setting up an IPSec VPN on a virtual machine ([hwdsl2/setup-ipsec-vpn](https://github.com/hwdsl2/setup-ipsec-vpn)) or a docker container ([hwdsl2/docker-ipsec-vpn-server](https://github.com/hwdsl2/docker-ipsec-vpn-server)).

## 病毒和恶意软件

面对[日益增长](https://www.documentcloud.org/documents/2459197-bit9-carbon-black-threat-research-report-2015.html)的恶意软件，Mac 还无法很好的防御这些病毒和恶意软件！

一些恶意软件捆绑在正版软件上，比如 [Java bundling Ask Toolbar](http://www.zdnet.com/article/oracle-extends-its-adware-bundling-to-include-java-for-macs/)，还有 [Mac.BackDoor.iWorm](https://docs.google.com/document/d/1YOfXRUQJgMjJSLBSoLiUaSZfiaS_vU3aG4Bvjmz6Dxs/edit?pli=1) 这种和盗版软件捆绑到一块的。[Malwarebytes Anti-Malware for Mac](https://www.malwarebytes.com/antimalware/mac/) 是一款超棒的应用，它可以帮你摆脱种类繁多的垃圾软件和其他恶意程序的困扰。

看看[恶意软件驻留在 Mac OS X 的方法](https://www.virusbtn.com/pdf/conference/vb2014/VB2014-Wardle.pdf) (pdf) 和[恶意软件在 OS X Yosemite 后台运行](https://www.rsaconference.com/events/us15/agenda/sessions/1591/malware-persistence-on-os-x-yosemite)了解各种恶意软件的功能和危害。

你可以定期运行 [Knock Knock](https://github.com/synack/knockknock) 这样的工具来检查在持续运行的应用(比如脚本，二进制程序)。但这种方法可能已经过时了。[Block Block](https://objective-see.com/products/blockblock.html) 和 [Ostiarius](https://objective-see.com/products/ostiarius.html) 这样的应用可能还有些帮助。可以在 [issue #90](https://github.com/drduh/OS-X-Security-and-Privacy-Guide/issues/90) 中查看相关警告。除此之外，使用 [Little Flocker](https://www.littleflocker.com/) 也能保护部分文件系统免遭非法写入，类似 Little Snitch 保护网络 (注意，该软件目前是 beat 版本，[谨慎使用](https://github.com/drduh/OS-X-Security-and-Privacy-Guide/pull/128))。

**反病毒** 软件是把双刃剑 -- 对于**高级**用户没什么用，却可能面临更多复杂攻击的威胁。然而对于 Mac **新手**用户可能是有用的，可以检测到“各种”恶意软件。不过也要考到额外的处理开销。

看看 [Sophail: Applied attacks against Antivirus](https://lock.cmpxchg8b.com/sophailv2.pdf) (pdf), [Analysis and Exploitation of an ESET Vulnerability](http://googleprojectzero.blogspot.ro/2015/06/analysis-and-exploitation-of-eset.html), [a trivial Avast RCE](https://code.google.com/p/google-security-research/issues/detail?id=546), [Popular Security Software Came Under Relentless NSA and GCHQ Attacks](https://theintercept.com/2015/06/22/nsa-gchq-targeted-kaspersky/), 和 [AVG: "Web TuneUP" extension multiple critical vulnerabilities](https://code.google.com/p/google-security-research/issues/detail?id=675).

因此，最好的防病毒方式是日常地防范。看看 [issue #44](https://github.com/drduh/OS-X-Security-and-Privacy-Guide/issues/44)中的讨论。

macOS 上有很多本地提权漏洞，所以要小心那些从第三方网站或 HTTP([案例](http://arstechnica.com/security/2015/08/0-day-bug-in-fully-patched-os-x-comes-under-active-exploit-to-hijack-macs/)) 下载且运行受信或不受信的程序。

看看 [The Safe Mac](http://www.thesafemac.com/) 上过去和目前的 Mac 安全新闻。

也检查下 [Hacking Team](https://www.schneier.com/blog/archives/2015/07/hacking_team_is.html) 为 Mac OS 开发的恶意软件：[root installation for MacOS](https://github.com/hackedteam/vector-macos-root)、 [Support driver for Mac Agent](https://github.com/hackedteam/driver-macos) 和 [RCS Agent for Mac](https://github.com/hackedteam/core-macos)， 这是一个很好的示例，一些高级的恶意程序是如何在 **用户空间** 隐藏自己的(例如 `ps`、`ls`)。 想了解更多的话，看看 [A Brief Analysis of an RCS Implant Installer](https://objective-see.com/blog/blog_0x0D.html) 和 [reverse.put.as](https://reverse.put.as/2016/02/29/the-italian-morons-are-back-what-are-they-up-to-this-time/)

## 系统完整性保护

[System Integrity Protection](https://support.apple.com/en-us/HT204899) (SIP) 是 OS X 10.11 中一个新的安全特性。默认是开启的，不过[可以禁用](https://derflounder.wordpress.com/2015/10/01/system-integrity-protection-adding-another-layer-to-apples-security-model/)，这可能需要更改某些系统设置，如删除根证书颁发机构或卸载某些启动守护进程。保持这项功能默认开启状态。

摘取自 [OS X 10.11 新增功能](https://developer.apple.com/library/prerelease/mac/releasenotes/MacOSX/WhatsNewInOSX/Articles/MacOSX10_11.html):

> 一项新的安全政策，应用于每个正在运行的进程，包括特权代码和非沙盒中运行的代码。该策略对磁盘上和运行时的组件增加了额外的保护，只允许系统安装程序和软件更新修改系统二进制文件。不再允许代码注入和运行时附加系统二进制文件。

看看 [What is the “rootless” feature in El Capitan, really?](https://apple.stackexchange.com/questions/193368/what-is-the-rootless-feature-in-el-capitan-really)。

[禁用 SIP](http://appleinsider.com/articles/16/11/17/system-integrity-protection-disabled-by-default-on-some-touch-bar-macbook-pros) 的一些 MacBook 已经售出。要验证 SIP 是否已启用，请使用命令 `csrutil status`，该命令应返回: `System Integrity Protection status: enabled.`。 否则，通过恢复模式[启用 SIP](https://developer.apple.com/library/content/documentation/Security/Conceptual/System_Integrity_Protection_Guide/ConfiguringSystemIntegrityProtection/ConfiguringSystemIntegrityProtection.html)。

## Gatekeeper 和 XProtect

**Gatekeeper** 和 **quarantine** 系统试图阻止运行（打开）未签名或恶意程序及文件。

**XProtect** 防止执行已知的坏文件和过时的版本插件，但并不能清除或停止现有的恶意软件。

两者都提供了对常见风险的一些保护，默认设置就好。

也看看 [Mac Malware Guide : How does Mac OS X protect me?](http://www.thesafemac.com/mmg-builtin/) 和 [Gatekeeper, XProtect and the Quarantine attribute](http://ilostmynotes.blogspot.com/2012/06/gatekeeper-xprotect-and-quarantine.html)。

**注意** Quarantine 会将下载的文件信息存储在 `~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`，这可能会造成隐私泄露的风险。简单的使用 `strings` 或下面的命令来检查文件:

    $ echo 'SELECT datetime(LSQuarantineTimeStamp + 978307200, "unixepoch") as LSQuarantineTimeStamp, LSQuarantineAgentName, LSQuarantineOriginURLString, LSQuarantineDataURLString from LSQuarantineEvent;' | sqlite3 /Users/$USER/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2

看看[这篇文章](http://www.zoharbabin.com/hey-mac-i-dont-appreciate-you-spying-on-me-hidden-downloads-log-in-os-x/) 了解更多信息。

想永久禁用此项功能，[清除文件](https://superuser.com/questions/90008/how-to-clear-the-contents-of-a-file-from-the-command-line) 和 [让它不可更改](http://hints.macworld.com/article.php?story=20031017061722471)：

    $ :>~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2
    $ sudo chflags schg ~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2

此外，macOS 附加元数据 ([HFS+ extended attributes](https://en.wikipedia.org/wiki/Extended_file_attributes#OS_X))来下载文件：

```
$ ls -l@ ~/Downloads/TorBrowser-6.0.5-osx64_en-US.dmg
-rw-r--r--@ 1 drduh  staff  59322237 Oct  9 15:20 TorBrowser-6.0.5-osx64_en-US.dmg
com.apple.metadata:kMDItemWhereFroms         186
com.apple.quarantine          68

$ xattr -l ~/Downloads/TorBrowser-6.0.5-osx64_en-US.dmg
com.apple.metadata:kMDItemWhereFroms:
00000000  62 70 6C 69 73 74 30 30 A2 01 02 5F 10 4D 68 74  |bplist00..._.Mht|
00000010  74 70 73 3A 2F 2F 64 69 73 74 2E 74 6F 72 70 72  |tps://dist.torpr|
00000020  6F 6A 65 63 74 2E 6F 72 67 2F 74 6F 72 62 72 6F  |oject.org/torbro|
00000030  77 73 65 72 2F 36 2E 30 2E 35 2F 54 6F 72 42 72  |wser/6.0.5/TorBr|
00000040  6F 77 73 65 72 2D 36 2E 30 2E 35 2D 6F 73 78 36  |owser-6.0.5-osx6|
00000050  34 5F 65 6E 2D 55 53 2E 64 6D 67 5F 10 39 68 74  |4_en-US.dmg_.9ht|
00000060  74 70 73 3A 2F 2F 77 77 77 2E 74 6F 72 70 72 6F  |tps://www.torpro|
00000070  6A 65 63 74 2E 6F 72 67 2F 64 6F 77 6E 6C 6F 61  |ject.org/downloa|
00000080  64 2F 64 6F 77 6E 6C 6F 61 64 2D 65 61 73 79 2E  |d/download-easy.|
00000090  68 74 6D 6C 2E 65 6E 08 0B 5B 00 00 00 00 00 00  |html.en..[......|
000000A0  01 01 00 00 00 00 00 00 00 03 00 00 00 00 00 00  |................|
000000B0  00 00 00 00 00 00 00 00 00 97                    |..........|
000000ba
com.apple.quarantine: 0081;52fb9173;Google Chrome.app;3AB6D46E-4AC5-3C3E-B427-32C7F804AAA3

$ xattr -d com.apple.metadata:kMDItemWhereFroms ~/Downloads/TorBrowser-6.0.5-osx64_en-US.dmg

$ xattr -d com.apple.quarantine ~/Downloads/TorBrowser-6.0.5-osx64_en-US.dmg

$ xattr -l ~/Downloads/TorBrowser-6.0.5-osx64_en-US.dmg
[No output after removal.]
```

## 密码

你可以使用 OpenSSL 生成强密码：

    $ openssl rand -base64 30
    LK9xkjUEAemc1gV2Ux5xqku+PDmMmCbSTmwfiMRI

或者 GPG：

    $ gpg --gen-random -a 0 30
    4/bGZL+yUEe8fOqQhF5V01HpGwFSpUPwFcU3aOWQ

或 `/dev/urandom` output：

    $ dd if=/dev/urandom bs=1 count=30 2>/dev/null | base64
    CbRGKASFI4eTa96NMrgyamj8dLZdFYBaqtWUSxKe

还可以控制字符集：

    $ LANG=C tr -dc 'a-zA-Z0-9' < /dev/urandom | fold -w 40 | head -n 1
    jm0iKn7ngQST8I0mMMCbbi6SKPcoUWwCb5lWEjxK

    $ LANG=C tr -dc 'DrDuh0-9' < /dev/urandom | fold -w 40 | head -n 1
    686672u2Dh7r754209uD312hhh23uD7u41h3875D

你也可以用 **Keychain Access（钥匙串访问）**生成一个令人难忘的密码，或者用 [anders/pwgen](https://github.com/anders/pwgen) 这样的命令行生成。

钥匙串使用 [PBKDF2 派生密钥](https://en.wikipedia.org/wiki/PBKDF2)加密，是个**非常安全**存储凭据的地方。看看 [Breaking into the OS X keychain](http://juusosalonen.com/post/30923743427/breaking-into-the-os-x-keychain)。还要注意钥匙串[不加密](https://github.com/drduh/OS-X-Security-and-Privacy-Guide/issues/118)的密码对应密码输入的名称。

或者，可以自己用 GnuPG (基于 [drduh/pwd.sh](https://github.com/drduh/pwd.sh) 密码管理脚本的一个插件)管理一个加密的密码文件。

除密码外，确保像 GitHub、 Google 账号、银行账户这些网上的账户，开启[两步验证](https://en.wikipedia.org/wiki/Two-factor_authentication)。

看看 [Yubikey](https://www.yubico.com/products/yubikey-hardware/yubikey-neo/) 的两因素和私钥(如：ssh、gpg)硬件令牌。 阅读 [drduh/YubiKey-Guide](https://github.com/drduh/YubiKey-Guide) 和 [trmm.net/Yubikey](https://trmm.net/Yubikey)。两个 Yubikey 的插槽之一可以通过编程来生成一个长的静态密码（例如可以与短的，记住的密码结合使用）。

## 备份

备份到外部介质或在线服务之前，总是先对本地文件进行加密。

一种方法是使用 GPG 对称加密，你选择一个密码。

加密一个文件夹:

    $ tar zcvf - ~/Downloads | gpg -c > ~/Desktop/backup-$(date +%F-%H%M).tar.gz.gpg

解密文档:

    $ gpg -o ~/Desktop/decrypted-backup.tar.gz -d ~/Desktop/backup-2015-01-01-0000.tar.gz.gpg && \
      tar zxvf ~/Desktop/decrypted-backup.tar.gz

你也可以用 **Disk Utility** 或 `hdiutil` 创建加密卷：

    $ hdiutil create ~/Desktop/encrypted.dmg -encryption -size 1g -volname "Name" -fs JHFS+

也可以考虑使用下面的应用和服务：[SpiderOak](https://spideroak.com/)、[Arq](https://www.arqbackup.com/)、[Espionage](https://www.espionageapp.com/) 和 [restic](https://restic.github.io/)。

## Wi-Fi

macOS 会记住它连接过的接入点。比如所有无线设备，每次搜寻网络的时候，Mac 将会显示所有它记住的接入点名称(如，*MyHomeNetwork*) ，比如每次从休眠状态唤醒设备的时候。

这就有泄漏隐私的风险，所以当不再需要的时候最好从列表中移除这些连接过的网络， 在 **System Preferences** > **Network** > **Advanced** 。

看看 [Signals from the Crowd: Uncovering Social Relationships through Smartphone Probes](http://conferences.sigcomm.org/imc/2013/papers/imc148-barberaSP106.pdf) (pdf) 和 [Wi-Fi told me everything about you](http://confiance-numerique.clermont-universite.fr/Slides/M-Cunche-2014.pdf) (pdf)。

保存的 Wi-Fi 信息 (SSID、最后一次连接等)可以在 `/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist` 中找到。

你可能希望在连接到新的和不可信的无线网络之前[伪造网卡 MAC 地址](https://en.wikipedia.org/wiki/MAC_spoofing)，以减少被动特征探测:

    $ sudo ifconfig en0 ether $(openssl rand -hex 6 | sed 's%\(..\)%\1:%g; s%.$%%')

**注意**每次启动，MAC 地址将重置为硬件默认地址。

了解下 [feross/SpoofMAC](https://github.com/feross/SpoofMAC).

最后，WEP 保护在无线网络是[不安全](http://www.howtogeek.com/167783/htg-explains-the-difference-between-wep-wpa-and-wpa2-wireless-encryption-and-why-it-matters/) 的，你应该尽量选择连接 **WPA2** 保护网络，可以减少被窃听的风险。

## SSH

对于向外的 ssh 连接，使用硬件或密码保护的秘钥，[设置](http://nerderati.com/2011/03/17/simplify-your-life-with-an-ssh-config-file/)远程 hosts 并考虑对它们进行[哈希](http://nms.csail.mit.edu/projects/ssh/)，以增强安全性。

将这几个[配置项](https://www.freebsd.org/cgi/man.cgi?query=ssh_config&sektion=5)加到 `~/.ssh/config`:

    Host *
      PasswordAuthentication no
      ChallengeResponseAuthentication no
      HashKnownHosts yes

**注意** [macOS Sierra 默认永久记住 SSH 秘钥密码](https://openradar.appspot.com/28394826)。添加配置 `UseKeyChain no` 来关闭这项功能。

你也可以用 ssh 创建一个[加密隧道](http://blog.trackets.com/2014/05/17/ssh-tunnel-local-and-remote-port-forwarding-explained-with-examples.html) 来发送数据，这有点类似于 VPN。

例如，在一个远程主机上使用 Privoxy:

    $ ssh -C -L 5555:127.0.0.1:8118 you@remote-host.tld

    $ sudo networksetup -setwebproxy "Wi-Fi" 127.0.0.1 5555

    $ sudo networksetup -setsecurewebproxy "Wi-Fi" 127.0.0.1 5555

或者使用 ssh 连接作为 [SOCKS 代理](https://www.mikeash.com/ssh_socks.html):

    $ ssh -NCD 3000 you@remote-host.tld

默认情况下， macOS **没有** sshd ，也不允许**远程登陆**。

启用 sshd 且允许进入的 ssh 连接:

    $ sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist

或者设置 **System Preferences** > **Sharing** 菜单。

如果你准备使用 sshd，至少禁用密码身份验证并考虑进一步[强化](https://stribika.github.io/2015/01/04/secure-secure-shell.html)配置。

找到 `/etc/sshd_config`，添加:

```
PasswordAuthentication no
ChallengeResponseAuthentication no
UsePAM no
```

确认 sshd 是否启用:

    $ sudo lsof -Pni TCP:22

## 物理访问

时刻保证 Mac 物理安全。不要将 Mac 留在无人照看的酒店之类的地方。

有一种攻击就是通过物理访问，通过注入引导 ROM 来安装键盘记录器，偷走你的密码。看看这个案例 [Thunderstrike](https://trmm.net/Thunderstrike)。

有个工具 [usbkill](https://github.com/hephaest0s/usbkill) 可以帮助你，这是**"一个反监视断路开关，一旦发现 USB 端口发生改变就会关闭你的计算机"**。

考虑购买屏幕[隐私过滤器](https://www.amazon.com/s/ref=nb_sb_noss_2?url=node%3D15782001&field-keywords=macbook)防止别人偷瞄。


## 系统监控

#### OpenBSM 监测

macOS 具有强大的 OpenBSM 审计功能。你可以使用它来监视进程执行，网络活动等等。

跟踪监测日志，使用 `praudit` 工具:

```
$ sudo praudit -l /dev/auditpipe
header,201,11,execve(2),0,Thu Sep  1 12:00:00 2015, + 195 msec,exec arg,/Applications/.evilapp/rootkit,path,/Applications/.evilapp/rootkit,path,/Applications/.evilapp/rootkit,attribute,100755,root,wheel,16777220,986535,0,subject,drduh,root,wheel,root,wheel,412,100005,50511731,0.0.0.0,return,success,0,trailer,201,
header,88,11,connect(2),0,Thu Sep  1 12:00:00 2015, + 238 msec,argument,1,0x5,fd,socket-inet,2,443,173.194.74.104,subject,drduh,root,wheel,root,wheel,326,100005,50331650,0.0.0.0,return,failure : Operation now in progress,4354967105,trailer,88
header,111,11,OpenSSH login,0,Thu Sep  1 12:00:00 2015, + 16 msec,subject_ex,drduh,drduh,staff,drduh,staff,404,404,49271,::1,text,successful login drduh,return,success,0,trailer,111,
```

看看 `audit`、`praudit`、`audit_control` 的操作手册，其它文件在 `/etc/security`目录下。

**注意** 虽然 `audit 手册` 上说 `-s` 标签会立即同步到配置中，实际上需要重启才能生效。

更多信息请看 [ilostmynotes.blogspot.com](http://ilostmynotes.blogspot.com/2013/10/openbsm-auditd-on-os-x-these-are-logs.html) 和 [derflounder.wordpress.com](https://derflounder.wordpress.com/2012/01/30/openbsm-auditing-on-mac-os-x/) 上的文章。

#### DTrace

`iosnoop` 监控磁盘 I/O

`opensnoop` 监控文件打开

`execsnoop` 监控进程执行

`errinfo` 监控失败的系统调用

`dtruss` 监控所有系统调用

运行命令 `man -k dtrace` 去了解更多信息。

**注意** [系统完整性保护](https://github.com/drduh/OS-X-Security-and-Privacy-Guide#system-integrity-protection)和 DTrace  [冲突](http://internals.exposed/blog/dtrace-vs-sip.html)， 所以这些工具可能用不上了。

#### 运行

`ps -ef` 列出所有正在运行的进程。

你也可以通过**活动监视器**来查看进程。

`launchctl list` 和 `sudo launchctl list` 分别列出用户运行和加载的程序，系统启动守护程序和代理。

#### 网络

列出公开网络文件:

    $ sudo lsof -Pni

列出各种网络相关的数据结构的内容：

    $ sudo netstat -atln

你也可以通过命令行使用 [Wireshark](https://www.wireshark.org/)。

监控 DNS 查询和响应：

```
$ tshark -Y "dns.flags.response == 1" -Tfields \
  -e frame.time_delta \
  -e dns.qry.name \
  -e dns.a \
  -Eseparator=,
```

监控 HTTP 请求和响应：

```
$ tshark -Y "http.request or http.response" -Tfields \
  -e ip.dst \
  -e http.request.full_uri \
  -e http.request.method \
  -e http.response.code \
  -e http.response.phrase \
  -Eseparator=/s
```

监控 x509 证书：

```
$ tshark -Y "ssl.handshake.certificate" -Tfields \
  -e ip.src \
  -e x509sat.uTF8String \
  -e x509sat.printableString \
  -e x509sat.universalString \
  -e x509sat.IA5String \
  -e x509sat.teletexString \
  -Eseparator=/s -Equote=d
```

也可以考虑简单的网络监控程序 [BonzaiThePenguin/Loading](https://github.com/BonzaiThePenguin/Loading)。

## 其它

如果你想的话，禁用[诊断与用量](https://github.com/fix-macosx/fix-macosx/wiki/Diagnostics-&-Usage-Data).

如果你想播放**音乐**或看**视频**，使用 [VLC 播放器](https://www.videolan.org/vlc/index.html)，这是免费且开源的。

如果你想用 **torrents**， 使用免费、开源的 [Transmission](http://www.transmissionbt.com/download/)(注意：所有软件都一样，即使是开源项目，[恶意软件还是可能找到破解的方式](http://researchcenter.paloaltonetworks.com/2016/03/new-os-x-ransomware-keranger-infected-transmission-bittorrent-client-installer/))。你可能希望使用一个块列表来避免和那些已知的坏主机配对，了解下 [Transmission 上最好的块列表](https://giuliomac.wordpress.com/2014/02/19/best-blocklist-for-transmission/) 和 [johntyree/3331662](https://gist.github.com/johntyree/3331662)。

用 [duti](http://duti.org/) 管理默认文件处理，可以通过 `brew install duti` 来安装。管理扩展的原因之一是为了防止远程文件系统在 Finder 中自动挂载。 ([保护自己免受 Sparkle 后门影响](https://www.taoeffect.com/blog/2016/02/apologies-sky-kinda-falling-protecting-yourself-from-sparklegate/))。这里有几个推荐的管理指令：

```
$ duti -s com.apple.Safari afp

$ duti -s com.apple.Safari ftp

$ duti -s com.apple.Safari nfs

$ duti -s com.apple.Safari smb
```

使用**控制台**应用程序来监控系统日志，也可以用 `syslog -w` 或 `log stream` 命令。

在 macOS Sierra (10.12) 之前的系统，在 `/etc/sudoers`启用 [tty_tickets flag](https://derflounder.wordpress.com/2016/09/21/tty_tickets-option-now-on-by-default-for-macos-sierras-sudo-tool/) 来阻止 sudo 会话在其它终端生效。使用命令 `sudo visudo` 然后添加一行 `Defaults    tty_tickets` 就可以了。

设置进入休眠状态时马上启动屏幕保护程序：

    $ defaults write com.apple.screensaver askForPassword -int 1

    $ defaults write com.apple.screensaver askForPasswordDelay -int 0

在 Finder 中显示隐藏文件和文件夹：

    $ defaults write com.apple.finder AppleShowAllFiles -bool true

    $ chflags nohidden ~/Library

显示所有文件扩展名(这样 "Evil.jpg.app" 就无法轻易伪装了)。

    $ defaults write NSGlobalDomain AppleShowAllExtensions -bool true

不要默认将文档保存到 iCloud：

    $ defaults write NSGlobalDomain NSDocumentSaveNewDocumentsToCloud -bool false

在终端启用[安全键盘输入](https://security.stackexchange.com/questions/47749/how-secure-is-secure-keyboard-entry-in-mac-os-xs-terminal) (除非你用 [YubiKey](https://mig5.net/content/secure-keyboard-entry-os-x-blocks-interaction-yubikeys) 或者像 [TextExpander](https://smilesoftware.com/textexpander/secureinput) 这样的程序)。

禁用崩溃报告(就是那个在程序崩溃后，会出现提示将问题报告给苹果的提示框)：

    $ defaults write com.apple.CrashReporter DialogType none

禁用 Bonjour [多播广告](https://www.trustwave.com/Resources/SpiderLabs-Blog/mDNS---Telling-the-world-about-you-(and-your-device)/):

    $ sudo defaults write /Library/Preferences/com.apple.mDNSResponder.plist NoMulticastAdvertisements -bool YES

如果用不上的话，[禁用 Handoff](https://apple.stackexchange.com/questions/151481/why-is-my-macbook-visibile-on-bluetooth-after-yosemite-install) 和蓝牙功能。

考虑 [sandboxing](https://developer.apple.com/library/mac/documentation/Darwin/Reference/ManPages/man1/sandbox-exec.1.html) 你的应用程序。 了解下 [fG! Sandbox Guide](https://reverse.put.as/wp-content/uploads/2011/09/Apple-Sandbox-Guide-v0.1.pdf) (pdf) 和 [s7ephen/OSX-Sandbox--Seatbelt--Profiles](https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles)。

你知道苹果公司自 [2006](http://osxbook.com/book/bonus/chapter10/tpm/) 后就不再出售带 TPM 的电脑了吗？

## 相关软件

[Santa](https://github.com/google/santa/) - Mac OS X 上一个带二进制白名单/黑名单监控系统的软件。

[kristovatlas/osx-config-check](https://github.com/kristovatlas/osx-config-check) - 检查你的 OSX 设备各种硬件配置设置。

[Lockdown](https://objective-see.com/products/lockdown.html) - 审查和修正安全配置。

[Dylib Hijack Scanner](https://objective-see.com/products/dhs.html) - 扫描那些容易被劫持或已经被黑的应用。

[Little Flocker](https://www.littleflocker.com/) - "Little Snitch for files"， 防止应用程序访问文件。

[facebook/osquery](https://github.com/facebook/osquery) - 可以检索系统底层信息。用户可以编写 SQL 来查询系统信息。

[google/grr](https://github.com/google/grr) - 事件响应框架侧重于远程现场取证。

[yelp/osxcollector](https://github.com/yelp/osxcollector) - 证据收集 & OS X 分析工具包。

[jipegit/OSXAuditor](https://github.com/jipegit/OSXAuditor) - 分析运行系统时的部件，比如隔离的文件， Safari、 Chrome 和 Firefox 历史记录， 下载， HTML5 数据库和本地存储、社交媒体、电子邮件帐户、和 Wi-Fi 接入点的名称。

[libyal/libfvde](https://github.com/libyal/libfvde) - 访问 FileVault Drive Encryption (FVDE) (或 FileVault2) 加密卷的库。

[CISOfy/lynis](https://github.com/CISOfy/lynis) - 跨平台安全审计工具，并协助合规性测试和系统强化。

## 其它资源

*排名不分先后*

[MacOS Hardening Guide - Appendix, Mac OS X and iOS Internals](http://newosxbook.com/files/moxii3/AppendixA.pdf)

[Mac Developer Library: Secure Coding Guide](https://developer.apple.com/library/mac/documentation/Security/Conceptual/SecureCodingGuide/Introduction.html)

[OS X Core Technologies Overview White Paper](https://www.apple.com/osx/all-features/pdf/osx_elcapitan_core_technologies_overview.pdf)

[Reverse Engineering Mac OS X blog](https://reverse.put.as/)

[Reverse Engineering Resources](http://samdmarshall.com/re.html)

[Patrick Wardle's Objective-See blog](https://objective-see.com/blog.html)

[Managing Macs at Google Scale (LISA '13)](https://www.usenix.org/conference/lisa13/managing-macs-google-scale)

[OS X Hardening: Securing a Large Global Mac Fleet (LISA '13)](https://www.usenix.org/conference/lisa13/os-x-hardening-securing-large-global-mac-fleet)

[DoD Security Technical Implementation Guides for Mac OS](http://iase.disa.mil/stigs/os/mac/Pages/mac-os.aspx)

[The EFI boot process](http://homepage.ntlworld.com/jonathan.deboynepollard/FGA/efi-boot-process.html)

[The Intel Mac boot process](http://refit.sourceforge.net/info/boot_process.html)

[Userland Persistence on Mac OS X](https://archive.org/details/joshpitts_shmoocon2015)

[Developing Mac OSX kernel rootkits](http://phrack.org/issues/66/16.html#article)

[IOKit kernel code execution exploit](https://code.google.com/p/google-security-research/issues/detail?id=135)

[Hidden backdoor API to root privileges in Apple OS X](https://truesecdev.wordpress.com/2015/04/09/hidden-backdoor-api-to-root-privileges-in-apple-os-x/)

[IPv6 Hardening Guide for OS X](http://www.insinuator.net/2015/02/ipv6-hardening-guide-for-os-x/)

[Harden the World: Mac OSX 10.11 El Capitan](http://docs.hardentheworld.org/OS/OSX_10.11_El_Capitan/)

[Hacker News discussion](https://news.ycombinator.com/item?id=10148077)

[Hacker News discussion 2](https://news.ycombinator.com/item?id=13023823)

[Apple Open Source](https://opensource.apple.com/)

[OS X 10.10 Yosemite: The Ars Technica Review](http://arstechnica.com/apple/2014/10/os-x-10-10/)

[CIS Apple OSX 10.10 Benchmark](https://benchmarks.cisecurity.org/tools2/osx/CIS_Apple_OSX_10.10_Benchmark_v1.1.0.pdf) (pdf)

[How to Switch to the Mac](https://taoofmac.com/space/HOWTO/Switch)

[Security Configuration For Mac OS X Version 10.6 Snow Leopard](http://www.apple.com/support/security/guides/docs/SnowLeopard_Security_Config_v10.6.pdf) (pdf)

[EFF Surveillance Self-Defense Guide](https://ssd.eff.org/)

[MacAdmins on Slack](https://macadmins.herokuapp.com/)

[iCloud security and privacy overview](http://support.apple.com/kb/HT4865)

[Demystifying the DMG File Format](http://newosxbook.com/DMG.html)

[There's a lot of vulnerable OS X applications out there (Sparkle Framework RCE)](https://vulnsec.com/2016/osx-apps-vulnerabilities/)

[iSeeYou: Disabling the MacBook Webcam Indicator LED](https://jscholarship.library.jhu.edu/handle/1774.2/36569)

[Mac OS X Forensics - Technical Report](https://www.ma.rhul.ac.uk/static/techrep/2015/RHUL-MA-2015-8.pdf) (pdf)

[Mac Forensics: Mac OS X and the HFS+ File System](https://cet4861.pbworks.com/w/file/fetch/71245694/mac.forensics.craiger-burke.IFIP.06.pdf) (pdf)

[Extracting FileVault 2 Keys with Volatility](https://tribalchicken.com.au/security/extracting-filevault-2-keys-with-volatility/)

[Auditing and Exploiting Apple IPC](https://googleprojectzero.blogspot.com/2015/09/revisiting-apple-ipc-1-distributed_28.html)

[Mac OS X and iOS Internals: To the Apple's Core by Jonathan Levin](https://www.amazon.com/Mac-OS-iOS-Internals-Apples/dp/1118057651)
