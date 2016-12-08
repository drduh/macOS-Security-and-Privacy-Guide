## 病毒和恶意软件

面对[日益增长](https://www.documentcloud.org/documents/2459197-bit9-carbon-black-threat-research-report-2015.html)的恶意软件，Mac 还无法很好的防御这些病毒和恶意软件！

一些恶意软件捆绑在正常软件上，比如 [Java bundling Ask Toolbar](http://www.zdnet.com/article/oracle-extends-its-adware-bundling-to-include-java-for-macs/)，还有 [Mac.BackDoor.iWorm](https://docs.google.com/document/d/1YOfXRUQJgMjJSLBSoLiUaSZfiaS_vU3aG4Bvjmz6Dxs/edit?pli=1) 这种和盗版软件捆绑到一块的。[Malwarebytes Anti-Malware for Mac](https://www.malwarebytes.com/antimalware/mac/) 是一款超棒的应用，它可以帮你摆脱种类繁多的垃圾软件和其他恶意程序的困扰。

看看[恶意软件驻留在 Mac OS X 的方法](https://www.virusbtn.com/pdf/conference/vb2014/VB2014-Wardle.pdf) (pdf) 和[恶意软件在 OS X Yosemite 后台运行](https://www.rsaconference.com/events/us15/agenda/sessions/1591/malware-persistence-on-os-x-yosemite)了解各种恶意软件的功能和危害。

你可以定期运行 [Knock Knock](https://github.com/synack/knockknock) 这样的工具来检查持续在运行的应用(比如脚本，二进制)。但那可能已经为时过晚。[Block Block](https://objective-see.com/products/blockblock.html) 和 [Ostiarius](https://objective-see.com/products/ostiarius.html) 这样的应用可能还有些帮助。可以在 [issue #90](https://github.com/drduh/OS-X-Security-and-Privacy-Guide/issues/90) 中查看相关警告。不过使用 [Little Flocker](https://www.littleflocker.com/) 也能保护部分文件系统免遭非法写入，类似 Little Snitch 保护网络 (注意，该软件目前是 beat 版本，[谨慎使用](https://github.com/drduh/OS-X-Security-and-Privacy-Guide/pull/128))。

**反病毒** 软件是把双刃剑 -- 对于**高级**用户没什么用，却可能面临更多复杂攻击的威胁。然而对于 Mac **新手**用户可能是有用的，可以检测到“各种”恶意软件。不过也要考到额外的处理开销。

看看 [Sophail: Applied attacks against Antivirus](https://lock.cmpxchg8b.com/sophailv2.pdf) (pdf), [Analysis and Exploitation of an ESET Vulnerability](http://googleprojectzero.blogspot.ro/2015/06/analysis-and-exploitation-of-eset.html), [a trivial Avast RCE](https://code.google.com/p/google-security-research/issues/detail?id=546), [Popular Security Software Came Under Relentless NSA and GCHQ Attacks](https://theintercept.com/2015/06/22/nsa-gchq-targeted-kaspersky/), 和 [AVG: "Web TuneUP" extension multiple critical vulnerabilities](https://code.google.com/p/google-security-research/issues/detail?id=675).

因此，最好的防病毒是 Common Sense 2016。看看 [issue #44](https://github.com/drduh/OS-X-Security-and-Privacy-Guide/issues/44)中更多的讨论。

macOS 上有很多本地提权漏洞，所以要小心那些从第三方网站或 HTTP([案例](http://arstechnica.com/security/2015/08/0-day-bug-in-fully-patched-os-x-comes-under-active-exploit-to-hijack-macs/)) 下载且运行受信或不受信的程序。

看看 [The Safe Mac](http://www.thesafemac.com/) 上过去和目前的 Mac 安全新闻。

也检查下 [Hacking Team](https://www.schneier.com/blog/archives/2015/07/hacking_team_is.html) 为 Mac OS 开发的恶意软件：[root installation for MacOS](https://github.com/hackedteam/vector-macos-root)、 [Support driver for Mac Agent](https://github.com/hackedteam/driver-macos) 和 [RCS Agent for Mac](https://github.com/hackedteam/core-macos)， 这是一个很好的示例，一些高级的恶意程序是如何在 **用户空间** 隐藏自己的(例如 `ps`、`ls`)。 想了解更多的话，看看 [A Brief Analysis of an RCS Implant Installer](https://objective-see.com/blog/blog_0x0D.html) 和 [reverse.put.as](https://reverse.put.as/2016/02/29/the-italian-morons-are-back-what-are-they-up-to-this-time/)

## 系统完整性保护

[System Integrity Protection](https://support.apple.com/en-us/HT204899) (SIP) 是 OS X 10.11 中一个新的安全特性。默认是开启的，不过[可以禁用](https://derflounder.wordpress.com/2015/10/01/system-integrity-protection-adding-another-layer-to-apples-security-model/)，这可能需要更改某些系统设置，如删除根证书颁发机构或卸载某些启动守护进程。保持这项功能默认开启状态。

摘取自 [OS X 10.11 新增功能](https://developer.apple.com/library/prerelease/mac/releasenotes/MacOSX/WhatsNewInOSX/Articles/MacOSX10_11.html):

> 一项新的安全政策，应用于每个正在运行的进程，包括特权代码和从沙盒中运行的代码。该策略对磁盘上和运行时的组件增加了额外的保护，只允许系统安装程序和软件更新修改系统二进制文件。不再允许代码注入和运行时附加系统二进制文件。

看看 [What is the “rootless” feature in El Capitan, really?](https://apple.stackexchange.com/questions/193368/what-is-the-rootless-feature-in-el-capitan-really)。

[禁用 SIP](http://appleinsider.com/articles/16/11/17/system-integrity-protection-disabled-by-default-on-some-touch-bar-macbook-pros) 的一些 MacBook 已经售出。要验证 SIP 是否已启用，请使用命令 `csrutil status`，该命令应返回: `System Integrity Protection status: enabled.`。 否则，通过恢复模式[启用 SIP](https://developer.apple.com/library/content/documentation/Security/Conceptual/System_Integrity_Protection_Guide/ConfiguringSystemIntegrityProtection/ConfiguringSystemIntegrityProtection.html)。

## Gatekeeper 和 XProtect

**Gatekeeper** 和 **quarantine** 系统试图阻止运行（打开）未签名或“坏”程序及文件。

**XProtect** 防止已知的坏文件和执行过时的插件版本，但并不能清除或停止现有的恶意软件。

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

除密码外，确保像 GitHub、 Google accounts、 银行，开启[两步验证](https://en.wikipedia.org/wiki/Two-factor_authentication)。

看看 [Yubikey](https://www.yubico.com/products/yubikey-hardware/yubikey-neo/) 的两因素和私钥(如：ssh、gpg)硬件令牌。 阅读 [drduh/YubiKey-Guide](https://github.com/drduh/YubiKey-Guide) 和 [trmm.net/Yubikey](https://trmm.net/Yubikey)。两个 Yubikey 的插槽之一可以通过编程来生成一个长的，静态密码（例如可以与短的，记住的密码结合使用）。

## 备份

备份到外部介质或在线服务之前，总是先对本地文件进行加密。

一种方法是使用 GPG 对称加密，你选择一个密码。

加密一个文件夹:

    $ tar zcvf - ~/Downloads | gpg -c > ~/Desktop/backup-$(date +%F-%H%M).tar.gz.gpg

加密一个文档:

    $ gpg -o ~/Desktop/decrypted-backup.tar.gz -d ~/Desktop/backup-2015-01-01-0000.tar.gz.gpg && \
      tar zxvf ~/Desktop/decrypted-backup.tar.gz

你也可以用 **Disk Utility** 或 `hdiutil` 创建加密卷：

    $ hdiutil create ~/Desktop/encrypted.dmg -encryption -size 1g -volname "Name" -fs JHFS+

也可以考虑使用下面的应用和服务：[SpiderOak](https://spideroak.com/)、[Arq](https://www.arqbackup.com/)、[Espionage](https://www.espionageapp.com/) 和 [restic](https://restic.github.io/)。

## Wi-Fi

macOS 会记住它连接过的接入点。比如所有无线设备，每次搜寻网络的时候，Mac 将会显示所有它记住的接入点名称(如，*MyHomeNetwork*) ，比如从休眠中唤醒的时候就会。

这就有泄漏隐私的风险，所有当不再需要的时候最好从列表中移除， 在 **System Preferences** > **Network** > **Advanced** 。

看看 [Signals from the Crowd: Uncovering Social Relationships through Smartphone Probes](http://conferences.sigcomm.org/imc/2013/papers/imc148-barberaSP106.pdf) (pdf) 和 [Wi-Fi told me everything about you](http://confiance-numerique.clermont-universite.fr/Slides/M-Cunche-2014.pdf) (pdf)。

保存的 Wi-Fi 信息 (SSID、最后一次连接等)可以在 `/Library/Preferences/SystemConfiguration/com.apple.airport.preferences.plist` 中找到。

你可能希望在连接到新的和不可信的无线网络之前[伪造网卡 MAC 地址](https://en.wikipedia.org/wiki/MAC_spoofing)，以减少被动痕迹:

    $ sudo ifconfig en0 ether $(openssl rand -hex 6 | sed 's%\(..\)%\1:%g; s%.$%%')

**注意**每次启动，MAC 地址将重置为硬件默认地址。

了解下 [feross/SpoofMAC](https://github.com/feross/SpoofMAC).

最后，WEP 保护在无线网络是[不安全](http://www.howtogeek.com/167783/htg-explains-the-difference-between-wep-wpa-and-wpa2-wireless-encryption-and-why-it-matters/) 的，你应该尽量选择连接 **WPA2** 保护网络，可以减少被窃听的风险。

## SSH

对于向外的 ssh 连接，使用硬件或密码保护的秘钥，[设置](http://nerderati.com/2011/03/17/simplify-your-life-with-an-ssh-config-file/)远程 hosts 并考虑对它们进行[哈希](http://nms.csail.mit.edu/projects/ssh/)，以增强安全性。

这有些推荐的[配置项](https://www.freebsd.org/cgi/man.cgi?query=ssh_config&sektion=5)加到 `~/.ssh/config`:

    Host *
      PasswordAuthentication no
      ChallengeResponseAuthentication no
      HashKnownHosts yes

**注意** [macOS Sierra 默认永久记住 SSH 秘钥密码](https://openradar.appspot.com/28394826)。添加配置 `UseKeyChain no` 来关闭这项功能。

你也可以用 ssh 创建一个[加密隧道](http://blog.trackets.com/2014/05/17/ssh-tunnel-local-and-remote-port-forwarding-explained-with-examples.html) 来发送流量，这有点类似于 VPN。

例如，在一个远程主机上使用 Privoxy:

    $ ssh -C -L 5555:127.0.0.1:8118 you@remote-host.tld

    $ sudo networksetup -setwebproxy "Wi-Fi" 127.0.0.1 5555

    $ sudo networksetup -setsecurewebproxy "Wi-Fi" 127.0.0.1 5555

或者使用 ssh 连接作为 [SOCKS 代理](https://www.mikeash.com/ssh_socks.html):

    $ ssh -NCD 3000 you@remote-host.tld

默认情况下， macOS **没有** sshd ，也不允许*远程登陆*。

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

有个工具 [usbkill](https://github.com/hephaest0s/usbkill) 可以帮助你，这是*"一个反监视断路开关，一旦发现 USB 端口发生改变就会关闭你的计算机"*。

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

看看 `man -k dtrace` 了解更多信息。

**注意** [系统完整性保护](https://github.com/drduh/OS-X-Security-and-Privacy-Guide#system-integrity-protection)和 DTrace  [冲突](http://internals.exposed/blog/dtrace-vs-sip.html)， 所以这些工具可能用不上了。

#### 运行

`ps -ef` 列出所有正在运行的进程。

你也可以通过**活动监视器**来查看进程。

`launchctl list` 和 `sudo launchctl list` 分别列出用户运行和加载的程序，系统启动守护程序和代理。

#### 网络

列出开放的网络文件:

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

用 [duti](http://duti.org/) 管理默认文件处理，可以通过 `brew install duti` 来安装。管理扩展的原因之一是为了防止远程文件系统在 Finder 中自动挂载。 ([保护自己免受 Sparkle 后门影响](https://www.taoeffect.com/blog/2016/02/apologies-sky-kinda-falling-protecting-yourself-from-sparklegate/))。这里有几个处理程序的建议：

```
$ duti -s com.apple.Safari afp

$ duti -s com.apple.Safari ftp

$ duti -s com.apple.Safari nfs

$ duti -s com.apple.Safari smb
```

使用**控制台**应用程序来监控系统日志，也可以用 `syslog -w` 或 `log stream` 命令。

在 macOS Sierra (10.12) 之前的系统，在 `/etc/sudoers`启用 [tty_tickets flag](https://derflounder.wordpress.com/2016/09/21/tty_tickets-option-now-on-by-default-for-macos-sierras-sudo-tool/) 来阻止 sudo 会话在其它终端生效。使用命令 `sudo visudo` 然后添加一行 `Defaults    tty_tickets` 就可以了。

设置屏幕保护程序启动尽快锁定屏幕：

    $ defaults write com.apple.screensaver askForPassword -int 1

    $ defaults write com.apple.screensaver askForPasswordDelay -int 0

在 Finder 中暴露隐藏文件和文件夹：

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

[Santa](https://github.com/google/santa/) - Mac OS X 上一个二进制白名单/黑名单系统。

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
