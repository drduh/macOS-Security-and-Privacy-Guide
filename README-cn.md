> * 原文地址：[macOS Security and Privacy Guide](https://github.com/drduh/macOS-Security-and-Privacy-Guide)
* 原文作者：[drduh](https://github.com/drduh)
* 译文出自：[掘金翻译计划](https://github.com/xitu/gold-miner)
* 译者：
* 校对者：

这里汇集了如何保护运行了 10.12 "Sierra" 操作系统的苹果 mac 电脑的想法，也包含了一些提高网络隐私的小贴士。  

这份指南的目标读者是那些 "高级用户"，他们希望采用企业及标准的安全措施，但是也适用于那些想在 mac 上提高个人隐私和安全性的初级用户们适用。

一个系统只有当它的管理者足够有能力的时候才会变得更加安全。没有一个单独的技术、软件、或者任何一个科技能保证计算机完全安全；现代的计算机和操作系统都是非常复杂的，并且需要大量的增量修改才获得在安全性和隐私性上真正意义的提高。

*免责声明*：以下过程中可能会产生 mac 电脑的损坏，*请您自行负责*。

如果你发现了本文中的错误或者有待改进的内容，请提交 `pull request` 或者 [创建一个 `issue`](https://github.com/drduh/OS-X-Security-and-Privacy-Guide/issues).

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

## 基础知识

最佳标准安全实践适用在以下几点:

* 创建一个威胁模型
    *  什么是你在保护的，避免谁的侵害？你的对手是一个隐藏的机构么？（如果是的，你需要考虑替换使用 [OpenBSD](http://www.openbsd.org)），或者是一个在网络上好管闲事的偷听者，或是针对你采取的一个精心策划的网络攻击？
    * 研究并识别出那些威胁，想一想如何减少被攻击的面。

* 保持系统更新
    * 请一直为你的系统和软件更新补丁，更新补丁，更新补丁！（重要的事情说三遍）
    * 可以使用 `App store` 应用程序来完成对 `macOS` 系统的更新，或者使用命令行工具 `softwareupdate`，这两个都不需要注册苹果账号。
    * 请订阅那些你经常使用的程序的公告邮件列表(例如，[Apple 安全公告](https://lists.apple.com/mailman/listinfo/security-announce))。

* 对敏感数据进行加密
    * 除了对整个磁盘加密之外，创建一个或者多个加密的容器，用它们来保存一些你的密码，秘钥和那些个人文件。
    * 这有助于减少数据泄露造成的危害。

* 经常备份数据
    * 定期创建数据备份，并且做好遇到危机时候的数据恢复工作。 
    * 在拷贝数据备份到外部存储介质或者 “云” 系统中之前，始终对它们进行加密。

* 注意钓鱼网站
    * 最后，管理员使用中的安全意识能大大减少系统的安全风险。
    * 在安装新软件的时候，请加倍小心。始终选择 [自由安全的软件](https://www.gnu.org/philosophy/free-sw.en.html) 和 开源的软件（[macOS 当然不是开源的](https://superuser.com/questions/19492/is-mac-os-x-open-source))

## 固件

设定一个固件的密码能阻止其他任何设备启动你的 Mac 电脑，除了你的启动盘。它也能设定成每次引导的时候。

[当你的计算机被偷的时候，这个功能是非常有用的](https://www.ftc.gov/news-events/blogs/techftc/2015/08/virtues-strong-enduser-device-controls)，因为唯一能重置固件密码的方式是通过 `Apple Store`，或者使用一个 [SPI 程序](https://reverse.put.as/2016/06/25/apple-efi-firmware-passwords-and-the-scbo-myth/)，例如，[Bus Pirate](http://ho.ax/posts/2012/06/unbricking-a-macbook/) 或者其他刷新电路的程序。

1. 开始时，按下 `Command` `R` 键来引导 [恢复模式 / Recovery Mode](https://support.apple.com/en-au/HT201314)。

2. 当出现了恢复模式的界面，从 `Utilities / 工具` 菜单中选择 **Firmware Password Utility / 固件密码实用工具**

3. 在固件工具窗口中，选择 **Turn On Firmware Password / 打开固件密码**

4. 输入一个新的密码，之后在 **Verify / 验证** 处再次输入一样的密码。

5. 选择 **Set Password / 设定密码**。

6. 选择 **Quit Firmware Utility / 退出固件工具** 关闭固件密码实用工具。

7. 选择 Apple 菜单，并且选择重新启动或者关闭计算机。

这个固件密码会在下一次引导后激活。为了验证这个密码，在引导过程中按住 `Alt` 键 - 按照提示输入密码。

固件密码也能通过 `firmwarepasswd` 工具管理，当引导进操作系统以后。

<img width="750" alt="Using a Dediprog SF600 to dump and flash a 2013 MacBook SPI Flash chip to remove a firmware password, sans Apple" src="https://cloud.githubusercontent.com/assets/12475110/17075918/0f851c0c-50e7-11e6-904d-0b56cf0080c1.png">

*使用 [Dediprog SF600](http://www.dediprog.com/pd/spi-flash-solution/sf600)来输出并且烧录一个 2013 款的 MacBook SPI 闪存芯片,或者移除一个固件密码， 在没有 Apple 技术支持下*

可参考 [HT204455](https://support.apple.com/en-au/HT204455), [LongSoft/UEFITool](https://github.com/LongSoft/UEFITool) 或者 [chipsec/chipsec](https://github.com/chipsec/chipsec) 了解更多信息。

## 准备和安装 macOS

有很多种方式来安装一个 macOS 的最新副本。

最简单的方式是在引导过程中按住 `Command` 和 `R` 键进入 [Recovery Mode / 恢复模式](https://support.apple.com/en-us/HT201314)。系统镜像文件能直接从苹官网上申请并且下载。然而，这样的方式会以明文形式直接在网络上暴露出你的机器识别码和其他的识别信息。

<img width="500" alt="PII is transmitted to Apple in plaintext when using macOS Recovery" src="https://cloud.githubusercontent.com/assets/12475110/20312189/8987c958-ab20-11e6-90fa-7fd7c8c1169e.png">

**在 macOS 恢复过程中，捕获到的未加密 HTTP 会话包**

另一种方式是，从 [App Store](https://itunes.apple.com/us/app/macos-sierra/id1127487414) 下载 **macOS Sierra** 安装程序或者从其他地方，之后创建一个自定义可安装的镜像系统。

这个 macOS Sierra 安装应用程序是经过 [代码签名的](https://developer.apple.com/library/mac/documentation/Security/Conceptual/CodeSigningGuide/Procedures/Procedures.html#//apple_ref/doc/uid/TP40005929-CH4-SW6)，它可以使用 `code sign` 命令来验证来确保你接收到的是一个正版文件的拷贝。

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

macOS 安装程序也可以由 `createinstallmedia` 工具制作，它在 `Install macOS Sierra.app/Contents/Resources/` 文件路径中。请参考 [为 OS X Yosemite 制作一个启动安装程序](https://support.apple.com/en-us/HT201372)，或者直接运行这个命令（不需要输入任何参数），看看它是如何工作的。

**注意** Apple 的安装程序 [并不能跨版本工作](https://github.com/drduh/OS-X-Security-and-Privacy-Guide/issues/120)。如果你想要创造一个 10.12 的镜像，例如，以下指令也必须要在 10.12 的机器上运行!

为了创建一个 **mac OS USB 启动安装程序**，需要挂载一个 USB 驱动器，清空它的内容、进行重新分区，之后使用 `createinstallmedia` 工具:

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

为了创建一个自定义、可安装的镜像，能用它恢复一台 Mac 电脑，你需要找到 `InstallESD.dmg`，这个文件也包含在 `Install macOS Sierra.app` 中。

通过 `Finder` 找到，并在这个应用程序图标上点击鼠标右键，选择 **Show Package Contents / 显示包内容**，之后从 **Contents / 内容** 进入到 **SharedSupport / 共享支持**，去找到 `InstallESD.dmg` 文件。

你能通过 `openssl sha1 InstallESD.dmg` 、`shasum -a 1 InstallESD.dmg` 或者 `shasum -a 256 InstallESD.dmg` 得到的加密过的哈希值 [验证](https://support.apple.com/en-us/HT201259) 来确保你得到的是同一份正版拷贝。

可以参考 [InstallESD_Hashes.csv](https://github.com/drduh/OS-X-Security-and-Privacy-Guide/blob/master/InstallESD_Hashes.csv) 这个在我代码仓库中的文件，它是现在和之前该版本文件的哈希值。你也可以使用 Google 搜索这些加密的哈希值，确保这个文件是正版且没有被修改过的。

可以使用 [MagerValp/AutoDMG](https://github.com/MagerValp/AutoDMG) 来创建这个镜像文件，或者手动创建，挂载并且把这个操作系统安装到一个临时镜像中:

    $ hdiutil attach -mountpoint /tmp/install_esd ./InstallESD.dmg

    $ hdiutil create -size 32g -type SPARSE -fs HFS+J -volname "macOS" -uid 0 -gid 80 -mode 1775 /tmp/output.sparseimage

    $ hdiutil attach -mountpoint /tmp/os -owners on /tmp/output.sparseimage

    $ sudo installer -pkg /tmp/install_esd/Packages/OSInstall.mpkg -tgt /tmp/os -verbose

这一步需要花费一些时间，请耐心等待。你能使用 `tail -F /var/log/install.log` 命令在另一个终端的窗口内查看进度。

**(可选项)** 安装额外的软件，例如，[Wireshark](https://www.wireshark.org/download.html):

    $ hdiutil attach Wireshark\ 2.2.0\ Intel\ 64.dmg

    $ sudo installer -pkg /Volumes/Wireshark/Wireshark\ 2.2.0\ Intel\ 64.pkg -tgt /tmp/os

    $ hdiutil unmount /Volumes/Wireshark

遇到安装错误时，请参考 [MagerValp/AutoDMG/wiki/Packages-Suitable-for-Deployment](https://github.com/MagerValp/AutoDMG/wiki/Packages-Suitable-for-Deployment)，使用 [chilcote/outset](https://github.com/chilcote/outset) 来处理首次引导时候的包和脚本。

当你完成的时候，分离，转换并且验证这个镜像:

    $ hdiutil detach /tmp/os

    $ hdiutil detach /tmp/install_esd

    $ hdiutil convert -format UDZO /tmp/output.sparseimage -o ~/sierra.dmg

    $ asr imagescan --source ~/sierra.dmg

现在，`sierra.dmg` 已经可以被用在一个或者多个 Mac 电脑上了。它能继续自定义化这个镜像，比如，包含预先定义的用户、应用程序、预置参数，等。

这个镜像能使用另一个在 [Target Disk Mode / 目标磁盘模式](https://support.apple.com/en-us/HT201462) 下的 Mac 进行安装，或者从 USB 启动安装盘安装。 

为了使用 **Target Disk Mode / 目标磁盘模式**，按住 `T` 键的同时启动 Mac 电脑，并且通过 `Firewire` 接口，`Thunderbolt` 接口或者 `USB-C` 线连接另外一台 Mac 电脑。

如果你没有其他 Mac 电脑，通过启动的时候，按住 *Option* 键用 USB 安装盘启动，把 `sierra.dmg` 和其他需要的文件拷贝到里面。

执行 `diskutil list` 来识别连接着的 Mac 磁盘，通常是 `/dev/disk2`

**(可选项)** 一次性[安全清除](https://www.backblaze.com/blog/securely-erase-mac-ssd/) 磁盘（如果之前通过 FileVault 加密，该磁盘必须先要解锁，并且装载在 `/dev/disk3s2`）:

    $ sudo diskutil secureErase freespace 1 /dev/disk3s2

把磁盘分区成 `Journaled HFS+`:

    $ sudo diskutil unmountDisk /dev/disk2

    $ sudo diskutil partitionDisk /dev/disk2 1 JHFS+ macOS 100%

把该镜像还原到新的卷中:

    $ sudo asr restore --source ~/sierra.dmg --target /Volumes/macOS --erase --buffersize 4m

你也能使用 **Disk Utility / 磁盘工具** 应用程序来清除连接着的 Mac 磁盘，之后将 `sierra.dmg` 还原到新创建的分区中。

如果你正确按照这些步骤执行，该目标 Mac 电脑应该安装了新的 macOS Sierra 了。

如果你想传送一些文件，把它们拷贝到一个共享文件夹，例如在挂载磁盘的镜像中， `/Users/Shared`，例如，`cp Xcode_8.0.dmg /Volumes/macOS/Users/Shared`

<img width="1280" alt="Finished restore install from USB recovery boot" src="https://cloud.githubusercontent.com/assets/12475110/14804078/f27293c8-0b2d-11e6-8e1f-0fb0ac2f1a4d.png">

*完成从 USB 启动的还原安装*

这里还没有大功告成！除非你使用 [AutoDMG](https://github.com/MagerValp/AutoDMG) 创建了镜像，或者把 macOS 安装在你 Mac 上的其他分区内，你需要创建一块还原分区（为了使用对整个磁盘加密的功能）。你能使用 [MagerValp/Create-Recovery-Partition-Installer](https://github.com/MagerValp/Create-Recovery-Partition-Installer) 或者按照以下步骤:

请下载 [RecoveryHDUpdate.dmg](https://support.apple.com/downloads/DL1464/en_US/RecoveryHDUpdate.dmg) 这个文件。

```
RecoveryHDUpdate.dmg
SHA-256: f6a4f8ac25eaa6163aa33ac46d40f223f40e58ec0b6b9bf6ad96bdbfc771e12c
SHA-1:   1ac3b7059ae0fcb2877d22375121d4e6920ae5ba
```

添加并且扩展这个安装程序，之后执行以下命令:

```
$ hdiutil attach RecoveryHDUpdate.dmg

$ pkgutil --expand /Volumes/Mac\ OS\ X\ Lion\ Recovery\ HD\ Update/RecoveryHDUpdate.pkg /tmp/recovery

$ hdiutil attach /tmp/recovery/RecoveryHDUpdate.pkg/RecoveryHDMeta.dmg

$ /tmp/recovery/RecoveryHDUpdate.pkg/Scripts/Tools/dmtest ensureRecoveryPartition /Volumes/macOS/ /Volumes/Recovery\ HD\ Update/BaseSystem.dmg 0 0 /Volumes/Recovery\ HD\ Update/BaseSystem.chunklist
```

必要的时候把 `/Volumes/macOS` 替换成以目标磁盘启动的 Mac 的路径。

这个步骤需要花几分钟才能完成。再次执行 `diskutil list` 来确保 **Recovery HD** 已经存在 `/dev/disk2` 或者相似的路径下。

一旦你完成了这些，执行 `hdituil unmount /Volumes/macOS` 命令弹出磁盘，之后关闭以目标磁盘模式启动的 Mac 电脑。

### 虚拟机

在虚拟机内安装 macOS，可以使用 [VMware Fusion](https://www.vmware.com/products/fusion.html) 工具，按照上文中的说明来创建一个镜像。你**不需要**再下载，也不需要手动创建还原分区。

```
VMware-Fusion-8.5.2-4635224.dmg
SHA-256: f6c54b98c9788d1df94d470661eedff3e5d24ca4fb8962fac5eb5dc56de63b77
SHA-1:   37ec465673ab802a3f62388d119399cb94b05408
```

选择 **Install OS X from the recovery parition** 这个安装方法。可自定义配置任意的内存和 CPU，之后完成设置。默认情况下，这个虚拟机应该进入 [Recovery Mode / 还原模式](https://support.apple.com/en-us/HT201314)。

在还原模式中，选择一个语言，之后在菜单条中由 Utilities 打开 Terminal。

在虚拟机内，输入 `ifconfig | grep inet` — 你应该能看到一个私有地址，比如 `172.16.34.129`

在 Mac 宿主机内，输入 `ifconfig | grep inet` — 你应该能看到一个私有地址，比如 `172.16.34.1`

通过修改 Mac 宿主机内的文件让可安装镜像对虚拟器起作用，比如，修改 `/etc/apache2/htpd.conf` 并且在该文件最上部增加以下内容：(使用网关分配给 Mac 宿主机的地址和端口号 80):

    Listen 172.16.34.1:80

在 Mac 宿主机上，把镜像链接到 Apache 网络服务器目录:

    $ sudo ln ~/sierra.dmg /Library/WebServer/Documents

在 Mac 宿主机的前台运行 Apache:

    $ sudo httpd -X

在虚拟机上通过本地网络命令 `asr`，安装镜像文件到卷分区内: 

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

完成后，在 `sudo httpd -X` 窗口内通过 `Control` 和 `C` 组合键停止在宿主机 Mac 上运行的  Apache 网络服务器服务，并且通过命令 `sudo rm /Library/WebServer/Documents/sierra.dmg` 删除镜像备份文件。

在虚拟机内，在 Apple 菜单的左上角选择 *Startup Disk*，选择硬件驱动器并重启你的电脑。你可能想在初始化虚拟机启动的时候禁用网络适配器。

例如，在访问某些有风险的网站之前保存虚拟机的快照，并在之后用它还原该虚拟机。或者使用一个虚拟机来安装有潜在问题的软件。

## 首次启动

**注意** 在设置 macOS 之前，请先断开网络连接并且配置一个防火墙。

在首次启动时，按住 `Command` `Option` `P` `R` 键位组合，它用于 [清除 NVRAM](https://support.apple.com/en-us/HT204063)。

当 macOS 首次启动时，你会看到 **Setup Assistant / 设置助手** 的欢迎画面。

请在创建你个人账户的时候，使用一个没有任何提示的 [高安全性密码](http://www.explainxkcd.com/wiki/index.php/936:_Password_Strength)。

如果你在设置账户的过程中使用了真实的名字，你得意识到，你的 [计算机的名字和局域网的主机名](https://support.apple.com/kb/PH18720) 将会因为这个名字而泄露 (例如，*John Applesseed's MacBook*)，所以这个名字会显示在局域网络和一些配置文件中。这两个名字都能在 **System Preferences / 系统配置 > Sharing / 共享** 菜单中或者以下命令来改变:

    $ sudo scutil --set ComputerName your_computer_name

    $ sudo scutil --set LocalHostName your_hostname

## 管理员和普通用户账号

第一账户始终是管理员账户。管理员账户是管理组中的成员并且有访问 `sudo` 的能力，允许他们修改其他账户，特别是 `root`，赋予他们对系统更高效的控制权。管理员执行的任何程序也有可能获得一样的权限，这就造成了一个安全风险。类似于 `sudo` 这样的工具 [都有一些能被利用的弱点](https://bogner.sh/2014/03/another-mac-os-x-sudo-password-bypass/)，例如在默认管理员账户运行的情况下，并行打开的程序或者很多系统的设定都是 [处于解锁的状态](http://csrc.nist.gov/publications/drafts/800-179/sp800_179_draft.pdf) [p. 61–62]。[Apple](https://help.apple.com/machelp/mac/10.12/index.html#/mh11389) 提供了一个最佳实践和 [其他一些](http://csrc.nist.gov/publications/drafts/800-179/sp800_179_draft.pdf) [p. 41–42]，例如，为每天基本的工作建立一个单独的账号，使用管理员账号仅为了安装软件和配置系统。

每一次都通过 OS X 登录界面进入管理员帐号并不是必须的。系统会在需要认证许可的时候弹出提示框，之后交给终端就行了。为了达到这个目的，Apple 为隐藏管理员账户和它的根目录提供了一些 [建议](https://support.apple.com/HT203998)。这对避免显示一个可见的 `影子` 账户来说是一个好办法。管理员账户也能 [从 FileVault 里移除](http://apple.stackexchange.com/a/94373)。

#### 错误警告

1. 只有管理员账户才能把应用程序安装在 `/Applications` 路径下 （本地目录）。Finder 和安装程序将为普通用户弹出一个许可对话框。然而，许多应用程序都能安装在 `~/Applications` （该目录能被手动创建） 路径下。经验之谈: 那些不需要管理员权限的应用程序 — 或者在不在 `/Applications` 目录下都没关系的应用程序 — 都应该安装在一般用户路径内，其他的应安装在本地目录。Mac App Store 上的应用程序任然会安装在 `/Applications` 并且不需要额外的管理员认证。

2. `sudo` 无法在一般用户的 shell 内使用，它需要使用 `su` 或者 `login` 在 shell 内输入一个管理员账户。这需要很多技巧和一些基本使用命令行接口的经验。

3. 系统配置和一些系统工具 （比如，Wi-Fi 诊断器） 为了所有的功能都能执行会需要 root 权限。在系统配置界面中的一些面板都是上锁的，所以需要点单独的击解锁按钮。一些应用程序在打开的时候会提示认证对话框，其他一些则需要通过一个管理员账号直接打开才能获得全部功能的权限。（例如，Console。）

4. 有些第三方应用程序无法正确运行，因为他们假设当前的用户是管理员账户。这些程序只能在登录管理员账户的情况下才能被执行，或者使用 `open` 工具。

#### 设置

账户能在系统设置中创建和管理。在一个已经建立的系统中，通常很容易就能创建第二个管理员账号并且把之前的管理员帐号降级。这就避免了数据迁移的问题。新安装的系统都能增加一般账号。对一个账号降级能通过新建立的管理员帐号中的系统设置 — 当然那个管理员账号必须已经注销 — 或者执行这个命令:
```
sudo dscl . -delete /Groups/admin GroupMembership user_name
```

## 对整个磁盘尽心数据加密

[FileVault](https://en.wikipedia.org/wiki/FileVault) 提供了在 macOS 上对整个磁盘加密的能力（技术上来说，是_整个卷宗_。）

FileVault 加密将在休眠的时候保护数据，并且阻止其他人通过物理访问形式偷取数据或者使用你的 Mac 修改数据。

因为大部分的加密操作都 [高效运作在硬件上](https://software.intel.com/en-us/articles/intel-advanced-encryption-standard-aes-instructions-set/)，性能上的损失对 FireVault 来说并不凸显。

FileVault 的安全性依赖于伪随机数生成器 (PRNG)。

> 这个随机设备实现了 Yarrow 伪随机数生成器算法并且维护着它自己的熵池。额外的熵值通常由守护进程 SecurityServer 提供，它由内核测算得到的随机抖动决定。

> SecurityServer 也常常负责定期保存一些熵值到磁盘，并且在启动的时候重新加载他们，把这些熵值提供给早期的系统使用。

参考 `man 4 random` 获得更多信息。

在开启 FileVault 之前，PRNG 也能通过写入 /dev/random 文件手动提供熵的种子。也就是说，在激活 FileVault 之前，我们能用这种方式撑一段时间。

在启用 FileVault *之前*，手动配置种子熵:

    $ cat > /dev/random
    [Type random letters for a long while, then press Control-D]

通过 `sudo fdsetup enable` 启用 FileVault 或者通过 **System Preferences** > **Security & Privacy** 之后重启电脑。

如果你能记住你的密码，那就没有理由不保存一个**还原秘钥**。然而，如果你忘记了密码或者还原秘钥，那意味着你加密的数据将永久丢失了。

如果你想深入了解 FileVault 是如何工作得， 可以参考这篇论文 [Infiltrate the Vault: Security Analysis and Decryption of Lion Full Disk Encryption](https://eprint.iacr.org/2012/374.pdf) (pdf) 和 这篇相关的 [演讲文稿](http://www.cl.cam.ac.uk/~osc22/docs/slides_fv2_ifip_2013.pdf) (pdf)。也可以参阅 [IEEE Std 1619-2007 “The XTS-AES Tweakable Block Cipher”](http://libeccio.di.unisa.it/Crypto14/Lab/p1619.pdf) (pdf).

你可能希望强制开启**休眠**并且从记忆中删除 FileVault 的秘钥，而非传统意义上的从休眠到记忆:

    $ sudo pmset -a destroyfvkeyonstandby 1
    $ sudo pmset -a hibernatemode 25

> 所有计算机都有一些固件，例如 type-EFI, BIOS-to，他们帮助发现其他硬件组件，最终使用期望的操作系统把计算机启动起来。以 Apple 硬件和 EFI 的使用来说，Apple 把有关的信息保存在 EFI 内，来辅助 OS X 的功能正确运行。举例来说，FileVault 的秘钥保存在 EFI 内，在待机模式的时候出现。

> 那些容易被高频攻击的组织机构，或者那些待机模式下，容易被暴露给所有设备访问的设备，它们都应该通过销毁在固件中的 FileVault 秘钥来减少这个风险。这么干并不会损坏 FileVault 的正常使用，但是系统需要用户在每次跳出待机模式的时候输入这个密码。

如果你选择在待机模式下删除 FileVault 秘钥，你也应该修改待机模式的设置。否则，你的机器可能无法正常进入待机模式，会因为缺少 FileVault 秘钥而关机。参考 [issue #124](https://github.com/drduh/OS-X-Security-and-Privacy-Guide/issues/124) 获得更多信息。这些设置可通过以下命令修改:

    $ sudo pmset -a powernap 0
    $ sudo pmset -a standby 0
    $ sudo pmset -a standbydelay 0
    $ sudo pmset -a autopoweroff 0

如果你想了解更多， 请参考 [Best Practices for Deploying FileVault 2](http://training.apple.com/pdf/WP_FileVault2.pdf) (pdf) 和这篇论文 [Lest We Remember: Cold Boot Attacks on Encryption Keys](https://www.usenix.org/legacy/event/sec08/tech/full_papers/halderman/halderman.pdf) (pdf)


## 防火墙

在准备连接进入互联网之前，最好是先为自己配置一个防火墙。

多个种类的防火墙在 macOS 上。

#### 应用程序层的防火墙

内嵌式的，基本的防火墙，它只阻止 **对内** 的连接。

注意，这个防火墙没有监视的能力，也没有阻止 **外出** 的连接。

它能在 **System Preferences** 中 **Security & Privacy** 标签中的 **Firewall**控制，或者使用以下的命令。

开启防火墙:

    $ sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on

开启日志:

    $ sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setloggingmode on

你也想开启私密模式:

    $ sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on

> 计算机黑客会扫描网络，所以他们能标记计算机并且攻击。你能使用**私密模式**，避免你的计算机响应一些这样的扫描。当私密模式开启了，你的电脑就不会响应 ICMP 请求，并且不答复来已关闭的 TCP 或 UDP 端口的连接。这会让攻击者很难发现你的计算机。

最后，你可能会想阻 **内嵌式的软件**和**经过代码签名，下载过得软件自动加入白名单:**

    $ sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setallowsigned off

    $ sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setallowsignedapp off

> 那些经过一个认证签名的应用程序会自动允许加入列表，而不是提示用户再对他们进行认证。包含在 OS X 内的应用程序都被 Apple 代码签名，并且都允许接对内的连接，当这个配置开启了。举例来说，因为 iTunes 已经被 Apple 代码签名，所以它能自动允许防火墙接收对内的连接。

> 如果你执行一个未签名的应用程序，它也没有被纳入防火墙白名单，此时一个带允许或者拒绝该连接选项的对话框会出现。如果你选择允许连接，OS X 对这个应用程序签名并且自动把它增加进防火墙的白名单。如果你选择拒绝连接，OS X 也会把它加入名单中，但是会拒绝对这个应用程序的对内连接。

在使用完 `socketfilterfw` 之后，你需要重新启动计算机（或者结束）这个进程:

    $ sudo pkill -HUP socketfilterfw

#### 第三方防火墙

例如 [Little Snitch](https://www.obdev.at/products/littlesnitch/index.html), [Hands Off](https://www.oneperiodic.com/products/handsoff/), [Radio Silence](http://radiosilenceapp.com/) 和 [Security Growler](https://pirate.github.io/security-growler/) 这样的程序都提供了一个方便、易用且安全的防火墙。

<img width="349" alt="Example of Little Snitch monitored session" src="https://cloud.githubusercontent.com/assets/12475110/10596588/c0eed3c0-76b3-11e5-95b8-9ce7d51b3d82.png">

**以下是 Little Snitch 的监控会话**

```
LittleSnitch-3.7.dmg
SHA-256: 5c44d853dc4178fb227abd3e8eee19ef1bf0d576f49b5b6a9a7eddf6ae7ea951
SHA-1:   1320ca9bcffb8ff8105b7365e792db6dc7b9f46a
```

这些程序都具备有监控和阻拦**对内**和**对外**网络连接的能力。然而，他们可能会需要使用一个闭源的 [内核扩展](https://developer.apple.com/library/mac/documentation/Darwin/Conceptual/KernelProgramming/Extend/Extend.html)。

如果过多的允许或者阻拦网络连接的选择让你不堪重负，使用允许连接的 **静谧模式**，之后定期检查你的设定的选项，来了解这么多应用程序都在干什么。 

需要指出的是，这些防火墙都会被以 **root** 权限运行的程序绕过，或者通过 [OS vulnerabilities](https://www.blackhat.com/docs/us-15/materials/us-15-Wardle-Writing-Bad-A-Malware-For-OS-X.pdf) (pdf)，但是他们还是值得拥有的 — 只是不要期待完全的保护。

若想了解更多有关 Little Snitch 如何工作的内容，可参考以下两篇文章，[Network Kernel Extensions Programming Guide](https://developer.apple.com/library/mac/documentation/Darwin/Conceptual/NKEConceptual/socket_nke/socket_nke.html#//apple_ref/doc/uid/TP40001858-CH228-SW1) 和 [Shut up snitch! – reverse engineering and exploiting a critical Little Snitch vulnerability](https://reverse.put.as/2016/07/22/shut-up-snitch-reverse-engineering-and-exploiting-a-critical-little-snitch-vulnerability/).

#### 内核等级的数据包过滤

有一个高度可定制化、功能强大，但的确也是最复杂的防火墙存在内核中。它能通过 `pfctl` 和很多配置文件控制。

pf 也能通过一个 GUI 应用程序控制，例如 [IceFloor](http://www.hanynet.com/icefloor/) 或者 [Murus](http://www.murusfirewall.com/)。

有很多书和文章介绍 pf 防火墙。这里，我们只介绍一个有关通过 IP 地址阻拦访问的例子。

将以下内容增加到 `pf.rules` 文件中:

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

使用以下命令:

* `sudo pfctl -e -f pf.rules` — 开启防火墙
* `sudo pfctl -d` — 禁用防火墙
* `sudo pfctl -t blocklist -T add 1.2.3.4` — 把某个主机加入阻止清单中
* `sudo pfctl -t blocklist -T show` — 查看阻止清单
* `sudo ifconfig pflog0 create` — 为某个接口创建日志
* `sudo tcpdump -ni pflog0` — 输出打印数据包

我不建议你花大量时间在如何配置 pf 上，除非你对数据包过滤器非常熟悉。比如说，如果你的 Mac 计算机连接在一个 [NAT](https://www.grc.com/nat/nat.htm) 后面，它存在于一个安全的家庭网络中，那以上操作是完全没有必要的。

可以参考 [fix-macosx/net-monitor](https://github.com/fix-macosx/net-monitor) 来了解如何使用 pf 监控用户和系统级别对“背景连接通讯"的使用。

## 系统服务

在你连接到互联网之前，你不妨禁用一些系统服务，它们会使用一些资源或者背景连接通讯到 Apple。

可参考这三个代码仓库获得更多建议，[fix-macosx/yosemite-phone-home](https://github.com/fix-macosx/yosemite-phone-home), [l1k/osxparanoia](https://github.com/l1k/osxparanoia) 和 [karek314/macOS-home-call-drop](https://github.com/karek314/macOS-home-call-drop)。

在 macOS 上的系统服务都由 **launchd** 管理。可参考 [launchd.info](http://launchd.info/)，也可以参考以下两个材料，[Apple's Daemons and Services Programming Guide](https://developer.apple.com/library/mac/documentation/MacOSX/Conceptual/BPSystemStartup/Chapters/CreatingLaunchdJobs.html) 和 [Technical Note TN2083](https://developer.apple.com/library/mac/technotes/tn2083/_index.html)。

你也可以运行 [KnockKnock](https://github.com/synack/knockknock)，它能展示出更多有关启动项的内容。

* 使用 `launchctl list` 查看正在运行的用户代理
* 使用 `sudo launchctl list` 查看正在运行的系统守护进程
* 通过指定服务名称查看，例如，`launchctl list com.apple.Maps.mapspushd`
* 使用 `defaults read` 来检查在 `/System/Library/LaunchDaemons` 和 `/System/Library/LaunchAgents` 工作中的 plist
* 使用 `man`，`strings` 和 Google 来学习运行中的代理和守护进程是什么

举例来说，想要知道某个系统启动的守护进程或者代理干了什么，可以输入以下指令:

    $ defaults read /System/Library/LaunchDaemons/com.apple.apsd.plist

看一看 `Program` 或者 `ProgramArguments` 部分，你就知道哪个二进制文件在运行，此处是 `apsd`。可以通过 `man apsd` 查看更多有关它的信息。

再举一个例子，如果你对 `Apple Push Nofitications` 不感兴趣，可以禁止这个服务:

    $ sudo launchctl unload -w /System/Library/LaunchDaemons/com.apple.apsd.plist

**注意** 卸载某写服务可能造成某些应用程序无法使用。首先，请阅读手册或者使用 Google 检索确保你明白自己在干什么。

禁用那些你不理解的系统守护进程的时候一定要万分小心，因为它可能会让你的系统瘫痪无法引导。如果你弄坏了你的 Mac，可以使用 [单一用户模式](https://support.apple.com/en-us/HT201573) 来修复。

如果你觉得 Mac 持续升温，感觉卡顿或者常常表现诡异，可以使用 [Console](https://en.wikipedia.org/wiki/Console_(OS_X)) 和 [Activity Monitor](https://support.apple.com/en-us/HT201464) 这两个应用程序，因为这可能是你不小心操作造成的。

以下指令可以查看现在已经禁用的服务:

    $ find /var/db/com.apple.xpc.launchd/ -type f -print -exec defaults read {} \; 2>/dev/null

有详细注释的启动系统守护进程和代理的列表，各自运行的程序和程序的哈斯校验值都包含在这个代码仓库中了。

**(可选项)** 运行 `read_launch_plists.py` 脚本，使用 `diff` 输出和你系统对比的差异，例如:

    $ diff <(python read_launch_plists.py) <(cat 16A323_launchd.csv)

你可以参考这篇 [cirrusj.github.io/Yosemite-Stop-Launch](http://cirrusj.github.io/Yosemite-Stop-Launch/)，它解释了一些服务， 也可以看看这篇 [Provisioning OS X and Disabling Unnecessary Services](https://vilimpoc.org/blog/2014/01/15/provisioning-os-x-and-disabling-unnecessary-services/)，它又做了一些其他解释。

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

## Viruses and malware

There is an [ever-increasing](https://www.documentcloud.org/documents/2459197-bit9-carbon-black-threat-research-report-2015.html) amount of Mac malware in the wild. Macs aren't immune from viruses and malicious software!

Some malware comes bundled with both legitimate software, such as the [Java bundling Ask Toolbar](http://www.zdnet.com/article/oracle-extends-its-adware-bundling-to-include-java-for-macs/), and some with illegitimate software, such as [Mac.BackDoor.iWorm](https://docs.google.com/document/d/1YOfXRUQJgMjJSLBSoLiUaSZfiaS_vU3aG4Bvjmz6Dxs/edit?pli=1) bundled with pirated programs. [Malwarebytes Anti-Malware for Mac](https://www.malwarebytes.com/antimalware/mac/) is an excellent program for ridding oneself of "garden-variety" malware and other "crapware".

See [Methods of malware persistence on Mac OS X](https://www.virusbtn.com/pdf/conference/vb2014/VB2014-Wardle.pdf) (pdf) and [Malware Persistence on OS X Yosemite](https://www.rsaconference.com/events/us15/agenda/sessions/1591/malware-persistence-on-os-x-yosemite) to learn about how garden-variety malware functions.

You could periodically run a tool like [Knock Knock](https://github.com/synack/knockknock) to examine persistent applications (e.g. scripts, binaries). But by then, it is probably too late. Maybe applications such as [Block Block](https://objective-see.com/products/blockblock.html) and [Ostiarius](https://objective-see.com/products/ostiarius.html) will help. See warnings and caveats in [issue #90](https://github.com/drduh/OS-X-Security-and-Privacy-Guide/issues/90) first, however.  Using an application such as [Little Flocker](https://www.littleflocker.com/) can also protect parts of the filesystem from unauthorized writes similar to how Little Snitch protects the network (note, however, the software is still in beta and should be [used with caution](https://github.com/drduh/OS-X-Security-and-Privacy-Guide/pull/128)).

**Anti-virus** programs are a double-edged sword -- not useful for **advanced** users and will likely increase attack surface against sophisticated threats, however possibly useful for catching "garden variety" malware on **novice** users' Macs. There is also the additional processing overhead to consider.

See [Sophail: Applied attacks against  Antivirus](https://lock.cmpxchg8b.com/sophailv2.pdf) (pdf), [Analysis and Exploitation of an ESET Vulnerability](http://googleprojectzero.blogspot.ro/2015/06/analysis-and-exploitation-of-eset.html), [a trivial Avast RCE](https://code.google.com/p/google-security-research/issues/detail?id=546), [Popular Security Software Came Under Relentless NSA and GCHQ Attacks](https://theintercept.com/2015/06/22/nsa-gchq-targeted-kaspersky/), and [AVG: "Web TuneUP" extension multiple critical vulnerabilities](https://code.google.com/p/google-security-research/issues/detail?id=675).

Therefore, the best anti-virus is **Common Sense 2016**. See more discussion in [issue #44](https://github.com/drduh/OS-X-Security-and-Privacy-Guide/issues/44).

Local privilege escalation bugs are plenty on macOS, so always be careful when downloading and running untrusted programs or trusted programs from third party websites or downloaded over HTTP ([example](http://arstechnica.com/security/2015/08/0-day-bug-in-fully-patched-os-x-comes-under-active-exploit-to-hijack-macs/)).

Have a look at [The Safe Mac](http://www.thesafemac.com/) for past and current Mac security news.

Also check out [Hacking Team](https://www.schneier.com/blog/archives/2015/07/hacking_team_is.html) malware for Mac OS: [root installation for MacOS](https://github.com/hackedteam/vector-macos-root), [Support driver for Mac Agent](https://github.com/hackedteam/driver-macos) and [RCS Agent for Mac](https://github.com/hackedteam/core-macos), which is a good example of advanced malware with capabilities to hide from **userland** (e.g., `ps`, `ls`), for example. For more, see [A Brief Analysis of an RCS Implant Installer](https://objective-see.com/blog/blog_0x0D.html) and [reverse.put.as](https://reverse.put.as/2016/02/29/the-italian-morons-are-back-what-are-they-up-to-this-time/)

## System Integrity Protection

[System Integrity Protection](https://support.apple.com/en-us/HT204899) (SIP) is a new security feature of OS X 10.11. It is enabled by default, but [can be disabled](https://derflounder.wordpress.com/2015/10/01/system-integrity-protection-adding-another-layer-to-apples-security-model/), which may be necessary to change some system settings, such as deleting root certificate authorities or unloading certain launch daemons. Keep this feature on, as it is by default.

From [What's New in OS X 10.11](https://developer.apple.com/library/prerelease/mac/releasenotes/MacOSX/WhatsNewInOSX/Articles/MacOSX10_11.html):

> A new security policy that applies to every running process, including privileged code and code that runs out of the sandbox. The policy extends additional protections to components on disk and at run-time, only allowing system binaries to be modified by the system installer and software updates. Code injection and runtime attachments to system binaries are no longer permitted.

Also see [What is the “rootless” feature in El Capitan, really?](https://apple.stackexchange.com/questions/193368/what-is-the-rootless-feature-in-el-capitan-really)

Some MacBook hardware has shipped with [SIP disabled](http://appleinsider.com/articles/16/11/17/system-integrity-protection-disabled-by-default-on-some-touch-bar-macbook-pros). To verify SIP is enabled, use the command `csrutil status`, which should return: `System Integrity Protection status: enabled.` Otherwise, [enable SIP](https://developer.apple.com/library/content/documentation/Security/Conceptual/System_Integrity_Protection_Guide/ConfiguringSystemIntegrityProtection/ConfiguringSystemIntegrityProtection.html) through Recovery Mode.

## Gatekeeper and XProtect

**Gatekeeper** and the **quarantine** system try to prevent unsigned or "bad" programs and files from running and opening.

**XProtect** prevents the execution of known bad files and outdated plugin versions, but does nothing to cleanup or stop existing malware.

Both offer trivial protection against common risks and are fine at default settings.

See also [Mac Malware Guide : How does Mac OS X protect me?](http://www.thesafemac.com/mmg-builtin/) and [Gatekeeper, XProtect and the Quarantine attribute](http://ilostmynotes.blogspot.com/2012/06/gatekeeper-xprotect-and-quarantine.html).

**Note** Quarantine stores information about downloaded files in `~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2`, which may pose a privacy risk. To examine the file, simply use `strings` or the following command:

    $ echo 'SELECT datetime(LSQuarantineTimeStamp + 978307200, "unixepoch") as LSQuarantineTimeStamp, LSQuarantineAgentName, LSQuarantineOriginURLString, LSQuarantineDataURLString from LSQuarantineEvent;' | sqlite3 /Users/$USER/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2

See [here](http://www.zoharbabin.com/hey-mac-i-dont-appreciate-you-spying-on-me-hidden-downloads-log-in-os-x/) for more information.

To permanently disable this feature, [clear the file](https://superuser.com/questions/90008/how-to-clear-the-contents-of-a-file-from-the-command-line) and [make it immutable](http://hints.macworld.com/article.php?story=20031017061722471):

    $ :>~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2
    $ sudo chflags schg ~/Library/Preferences/com.apple.LaunchServices.QuarantineEventsV2

Furthermore, macOS attaches metadata ([HFS+ extended attributes](https://en.wikipedia.org/wiki/Extended_file_attributes#OS_X)) to downloaded files:

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

## Passwords

You can generate strong passwords with OpenSSL:

    $ openssl rand -base64 30
    LK9xkjUEAemc1gV2Ux5xqku+PDmMmCbSTmwfiMRI

Or GPG:

    $ gpg --gen-random -a 0 30
    4/bGZL+yUEe8fOqQhF5V01HpGwFSpUPwFcU3aOWQ

Or `/dev/urandom` output:

    $ dd if=/dev/urandom bs=1 count=30 2>/dev/null | base64
    CbRGKASFI4eTa96NMrgyamj8dLZdFYBaqtWUSxKe

With control over character sets:

    $ LANG=C tr -dc 'a-zA-Z0-9' < /dev/urandom | fold -w 40 | head -n 1
    jm0iKn7ngQST8I0mMMCbbi6SKPcoUWwCb5lWEjxK

    $ LANG=C tr -dc 'DrDuh0-9' < /dev/urandom | fold -w 40 | head -n 1
    686672u2Dh7r754209uD312hhh23uD7u41h3875D

You can also generate passwords, even memorable ones, using **Keychain Access** password assistant, or a command line equivalent like [anders/pwgen](https://github.com/anders/pwgen).

Keychains are encrypted with a [PBKDF2 derived key](https://en.wikipedia.org/wiki/PBKDF2) and are a _pretty safe_ place to store credentials. See also [Breaking into the OS X keychain](http://juusosalonen.com/post/30923743427/breaking-into-the-os-x-keychain). Also be aware that Keychain [does not encrypt](https://github.com/drduh/OS-X-Security-and-Privacy-Guide/issues/118) the names corresponding to password entries.

Alternatively, you can manage an encrypted passwords file yourself with GnuPG (shameless plug for my [drduh/pwd.sh](https://github.com/drduh/pwd.sh) password manager script).

In addition to passwords, ensure eligible online accounts, such as GitHub, Google accounts, banking, have [two factor authentication](https://en.wikipedia.org/wiki/Two-factor_authentication) enabled.

Look to [Yubikey](https://www.yubico.com/products/yubikey-hardware/yubikey-neo/) for a two factor and private key (e.g., ssh, gpg) hardware token. See [drduh/YubiKey-Guide](https://github.com/drduh/YubiKey-Guide) and [trmm.net/Yubikey](https://trmm.net/Yubikey). One of two Yubikey's slots can also be programmed to emit a long, static password (which can be used in combination with a short, memorized password, for example).

## Backup

Always encrypt files locally before backing them up to external media or online services.

One way is to use a symmetric cipher with GPG and a password of your choosing.

To encrypt a directory:

    $ tar zcvf - ~/Downloads | gpg -c > ~/Desktop/backup-$(date +%F-%H%M).tar.gz.gpg

To decrypt an archive:

    $ gpg -o ~/Desktop/decrypted-backup.tar.gz -d ~/Desktop/backup-2015-01-01-0000.tar.gz.gpg && \
      tar zxvf ~/Desktop/decrypted-backup.tar.gz

You may also create encrypted volumes using **Disk Utility** or `hdiutil`:

    $ hdiutil create ~/Desktop/encrypted.dmg -encryption -size 1g -volname "Name" -fs JHFS+

Also see the following applications and services: [SpiderOak](https://spideroak.com/), [Arq](https://www.arqbackup.com/), [Espionage](https://www.espionageapp.com/), and [restic](https://restic.github.io/).

## Wi-Fi

macOS remembers access points it has connected to. Like all wireless devices, the Mac will broadcast all access point names it remembers (e.g., *MyHomeNetwork*) each time it looks for a network, such as when waking from sleep.

This is a privacy risk, so remove networks from the list in **System Preferences** > **Network** > **Advanced** when they're no longer needed.

Also see [Signals from the Crowd: Uncovering Social Relationships through Smartphone Probes](http://conferences.sigcomm.org/imc/2013/papers/imc148-barberaSP106.pdf) (pdf) and [Wi-Fi told me everything about you](http://confiance-numerique.clermont-universite.fr/Slides/M-Cunche-2014.pdf) (pdf).

Saved Wi-Fi information (SSID, last connection, etc.) can be found in `/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist`

You may wish to [spoof the MAC address](https://en.wikipedia.org/wiki/MAC_spoofing) of your network card before connecting to new and untrusted wireless networks to mitigate passive fingerprinting:

    $ sudo ifconfig en0 ether $(openssl rand -hex 6 | sed 's%\(..\)%\1:%g; s%.$%%')

**Note** MAC addresses will reset to hardware defaults on each boot.

Also see [feross/SpoofMAC](https://github.com/feross/SpoofMAC).

Finally, WEP protection on wireless networks is [not secure](http://www.howtogeek.com/167783/htg-explains-the-difference-between-wep-wpa-and-wpa2-wireless-encryption-and-why-it-matters/) and you should favor connecting to **WPA2** protected networks only to mitigate the risk of passive eavesdroppers.

## SSH

For outgoing ssh connections, use hardware- or password-protected keys, [set up](http://nerderati.com/2011/03/17/simplify-your-life-with-an-ssh-config-file/) remote hosts and consider [hashing](http://nms.csail.mit.edu/projects/ssh/) them for added privacy.

Here are several recommended [options](https://www.freebsd.org/cgi/man.cgi?query=ssh_config&sektion=5) to add to  `~/.ssh/config`:

    Host *
      PasswordAuthentication no
      ChallengeResponseAuthentication no
      HashKnownHosts yes

**Note** [macOS Sierra permanently remembers SSH key passphrases by default](https://openradar.appspot.com/28394826). Append the option `UseKeyChain no` to turn this feature off.

You can also use ssh to create an [encrypted tunnel](http://blog.trackets.com/2014/05/17/ssh-tunnel-local-and-remote-port-forwarding-explained-with-examples.html) to send your traffic through, which is similar to a VPN.

For example, to use Privoxy on a remote host:

    $ ssh -C -L 5555:127.0.0.1:8118 you@remote-host.tld

    $ sudo networksetup -setwebproxy "Wi-Fi" 127.0.0.1 5555

    $ sudo networksetup -setsecurewebproxy "Wi-Fi" 127.0.0.1 5555

Or to use an ssh connection as a [SOCKS proxy](https://www.mikeash.com/ssh_socks.html):

    $ ssh -NCD 3000 you@remote-host.tld

By default, macOS does **not** have sshd or *Remote Login* enabled.

To enable sshd and allow incoming ssh connections:

    $ sudo launchctl load -w /System/Library/LaunchDaemons/ssh.plist

Or use the **System Preferences** > **Sharing** menu.

If you are going to enable sshd, at least disable password authentication and consider further [hardening](https://stribika.github.io/2015/01/04/secure-secure-shell.html) your configuration.

To `/etc/sshd_config`, add:

```
PasswordAuthentication no
ChallengeResponseAuthentication no
UsePAM no
```

 Confirm whether sshd is enabled or disabled:

    $ sudo lsof -Pni TCP:22

## Physical access

Keep your Mac physically secure at all times. Don't leave it unattended in hotels and such.

A skilled attacker with unsupervised physical access to your computer can infect the boot ROM to install a keylogger and steal your password - see [Thunderstrike](https://trmm.net/Thunderstrike), for example.

A helpful tool is [usbkill](https://github.com/hephaest0s/usbkill), which is *"an anti-forensic kill-switch that waits for a change on your USB ports and then immediately shuts down your computer"*.

Consider purchasing a [privacy filter](https://www.amazon.com/s/ref=nb_sb_noss_2?url=node%3D15782001&field-keywords=macbook) for your screen to thwart shoulder surfers.

## System monitoring

#### OpenBSM audit

macOS has a powerful OpenBSM auditing capability. You can use it to monitor process execution, network activity, and much more.

To tail audit logs, use the `praudit` utility:

```
$ sudo praudit -l /dev/auditpipe
header,201,11,execve(2),0,Thu Sep  1 12:00:00 2015, + 195 msec,exec arg,/Applications/.evilapp/rootkit,path,/Applications/.evilapp/rootkit,path,/Applications/.evilapp/rootkit,attribute,100755,root,wheel,16777220,986535,0,subject,drduh,root,wheel,root,wheel,412,100005,50511731,0.0.0.0,return,success,0,trailer,201,
header,88,11,connect(2),0,Thu Sep  1 12:00:00 2015, + 238 msec,argument,1,0x5,fd,socket-inet,2,443,173.194.74.104,subject,drduh,root,wheel,root,wheel,326,100005,50331650,0.0.0.0,return,failure : Operation now in progress,4354967105,trailer,88
header,111,11,OpenSSH login,0,Thu Sep  1 12:00:00 2015, + 16 msec,subject_ex,drduh,drduh,staff,drduh,staff,404,404,49271,::1,text,successful login drduh,return,success,0,trailer,111,
```

See the manual pages for `audit`, `praudit`, `audit_control` and other files in `/etc/security`

**Note** although `man audit` says the `-s` flag will synchronize the audit configuration, it appears necessary to reboot for changes to take effect.

See articles on [ilostmynotes.blogspot.com](http://ilostmynotes.blogspot.com/2013/10/openbsm-auditd-on-os-x-these-are-logs.html) and [derflounder.wordpress.com](https://derflounder.wordpress.com/2012/01/30/openbsm-auditing-on-mac-os-x/) for more information.

#### DTrace

`iosnoop` monitors disk I/O

`opensnoop` monitors file opens

`execsnoop` monitors execution of processes

`errinfo` monitors failed system calls

`dtruss` monitors all system calls

See `man -k dtrace` for more information.

**Note** [System Integrity Protection](https://github.com/drduh/OS-X-Security-and-Privacy-Guide#system-integrity-protection) [interferes](http://internals.exposed/blog/dtrace-vs-sip.html) with DTrace, so it may no longer be possible to use these tools.

#### Execution

`ps -ef` lists information about all running processes.

You can also view processes with **Activity Monitor**.

`launchctl list` and `sudo launchctl list` list loaded and running user and system launch daemons and agents.

#### Network

List open network files:

    $ sudo lsof -Pni

List contents of various network-related data structures:

    $ sudo netstat -atln

You can also use [Wireshark](https://www.wireshark.org/) from the command line.

Monitor DNS queries and replies:

```
$ tshark -Y "dns.flags.response == 1" -Tfields \
  -e frame.time_delta \
  -e dns.qry.name \
  -e dns.a \
  -Eseparator=,
```

Monitor HTTP requests and responses:

```
$ tshark -Y "http.request or http.response" -Tfields \
  -e ip.dst \
  -e http.request.full_uri \
  -e http.request.method \
  -e http.response.code \
  -e http.response.phrase \
  -Eseparator=/s
```

Monitor x509 certificates:

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

Also see the simple networking monitoring application [BonzaiThePenguin/Loading](https://github.com/BonzaiThePenguin/Loading)

## Miscellaneous

If you wish, disable [Diagnostics & Usage Data](https://github.com/fix-macosx/fix-macosx/wiki/Diagnostics-&-Usage-Data).

If you want to play **music** or watch **videos**, use [VLC media player](https://www.videolan.org/vlc/index.html) which is free and open source.

If you want to use **torrents**, use [Transmission](http://www.transmissionbt.com/download/) which is free and open source (note: like all software, even open source projects, [malware may still find its way in](http://researchcenter.paloaltonetworks.com/2016/03/new-os-x-ransomware-keranger-infected-transmission-bittorrent-client-installer/)). You may also wish to use a block list to avoid peering with known bad hosts - see [Which is the best blocklist for Transmission](https://giuliomac.wordpress.com/2014/02/19/best-blocklist-for-transmission/) and [johntyree/3331662](https://gist.github.com/johntyree/3331662).

Manage default file handlers with [duti](http://duti.org/), which can be installed with `brew install duti`. One reason to manage extensions is to prevent auto-mounting of remote filesystems in Finder (see [Protecting Yourself From Sparklegate](https://www.taoeffect.com/blog/2016/02/apologies-sky-kinda-falling-protecting-yourself-from-sparklegate/)). Here are several recommended handlers to manage:

```
$ duti -s com.apple.Safari afp

$ duti -s com.apple.Safari ftp

$ duti -s com.apple.Safari nfs

$ duti -s com.apple.Safari smb
```

Monitor system logs with the **Console** application or `syslog -w` or `log stream` commands.

In systems prior to macOS Sierra (10.12), enable the [tty_tickets flag](https://derflounder.wordpress.com/2016/09/21/tty_tickets-option-now-on-by-default-for-macos-sierras-sudo-tool/) in `/etc/sudoers` to restrict the sudo session to the Terminal window/tab that started it. To do so, use `sudo visudo` and add the line `Defaults    tty_tickets`.

Set your screen to lock as soon as the screensaver starts:

    $ defaults write com.apple.screensaver askForPassword -int 1

    $ defaults write com.apple.screensaver askForPasswordDelay -int 0

Expose hidden files and Library folder in Finder:

    $ defaults write com.apple.finder AppleShowAllFiles -bool true

    $ chflags nohidden ~/Library

Show all filename extensions (so that "Evil.jpg.app" cannot masquerade easily).

    $ defaults write NSGlobalDomain AppleShowAllExtensions -bool true

Don't default to saving documents to iCloud:

    $ defaults write NSGlobalDomain NSDocumentSaveNewDocumentsToCloud -bool false

Enable [Secure Keyboard Entry](https://security.stackexchange.com/questions/47749/how-secure-is-secure-keyboard-entry-in-mac-os-xs-terminal) in Terminal (unless you use [YubiKey](https://mig5.net/content/secure-keyboard-entry-os-x-blocks-interaction-yubikeys) or applications such as [TextExpander](https://smilesoftware.com/textexpander/secureinput)).

Disable crash reporter (the dialog which appears after an application crashes and prompts to report the problem to Apple):

    $ defaults write com.apple.CrashReporter DialogType none

Disable Bonjour [multicast advertisements](https://www.trustwave.com/Resources/SpiderLabs-Blog/mDNS---Telling-the-world-about-you-(and-your-device)/):

    $ sudo defaults write /Library/Preferences/com.apple.mDNSResponder.plist NoMulticastAdvertisements -bool YES

[Disable Handoff](https://apple.stackexchange.com/questions/151481/why-is-my-macbook-visibile-on-bluetooth-after-yosemite-install) and Bluetooth features, if they aren't necessary.

Consider [sandboxing](https://developer.apple.com/library/mac/documentation/Darwin/Reference/ManPages/man1/sandbox-exec.1.html) your applications. See [fG! Sandbox Guide](https://reverse.put.as/wp-content/uploads/2011/09/Apple-Sandbox-Guide-v0.1.pdf) (pdf) and [s7ephen/OSX-Sandbox--Seatbelt--Profiles](https://github.com/s7ephen/OSX-Sandbox--Seatbelt--Profiles).

Did you know Apple has not shipped a computer with TPM since [2006](http://osxbook.com/book/bonus/chapter10/tpm/)?

## Related software

[Santa](https://github.com/google/santa/) - A binary whitelisting/blacklisting system for Mac OS X.

[kristovatlas/osx-config-check](https://github.com/kristovatlas/osx-config-check) - checks your OSX machine against various hardened configuration settings.

[Lockdown](https://objective-see.com/products/lockdown.html) - audits and remediates security configuration settings.

[Dylib Hijack Scanner](https://objective-see.com/products/dhs.html) - scan for applications that are either susceptible to dylib hijacking or have been hijacked.

[Little Flocker](https://www.littleflocker.com/) - "Little Snitch for files"; prevents applications from accessing files.

[facebook/osquery](https://github.com/facebook/osquery) - can be used to retrieve low level system information.  Users can write SQL queries to retrieve system information.

[google/grr](https://github.com/google/grr) - incident response framework focused on remote live forensics.

[yelp/osxcollector](https://github.com/yelp/osxcollector) - forensic evidence collection & analysis toolkit for OS X.

[jipegit/OSXAuditor](https://github.com/jipegit/OSXAuditor) - analyzes artifacts on a running system, such as quarantined files, Safari, Chrome and Firefox history, downloads, HTML5 databases and localstore, social media and email accounts, and Wi-Fi access point names.

[libyal/libfvde](https://github.com/libyal/libfvde) - library to access FileVault Drive Encryption (FVDE) (or FileVault2) encrypted volumes.

[CISOfy/lynis](https://github.com/CISOfy/lynis) - cross-platform security auditing tool and assists with compliance testing and system hardening.

## Additional resources

*In no particular order*

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
