#!/bin/bash

headline()       { printf "\e[0;1m$@\e[0m:\n"; }

if_zero_or_empty() {
  if [ ! -z "$1" ]; then
    [[ "$1" -eq 0 ]]
  fi
}
if_non_zero_and_empty() {
  if [ ! -z "$1" ]; then
    [[ "$1" -ne 0 ]]
  else
    false
  fi
}


curr_func_name() {
  local currentShell=$(ps -p $$ | awk "NR==2" | awk '{ print $4 }' | tr -d '-')
  if [[ $currentShell == 'bash' ]]; then
    echo ${FUNCNAME[1]}
  elif [[ $currentShell == 'zsh' ]]; then
    echo $funcstack[2]
  fi
}

allow_root_login(){
	headline "$(curr_func_name)"
	sudo sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
	sudo systemctl restart sshd
	#systemctl stop ufw.service
	#systemctl disable ufw.service
}

# allow_root_login


unset xyz; printf "expect true, got "; if_zero_or_empty $xyz && printf "true" || printf "false"; printf " / "; if_non_zero_and_empty $xyz && echo "true" || echo "false"
xyz=""; printf "expect true, got "; if_zero_or_empty $xyz && printf "true" || printf "false"; printf " / "; if_non_zero_and_empty $xyz && echo "true" || echo "false"
xyz="0"; printf "expect true, got "; if_zero_or_empty $xyz && printf "true" || printf "false"; printf " / "; if_non_zero_and_empty $xyz && echo "true" || echo "false"
xyz="1"; printf "expect false, got "; if_zero_or_empty $xyz && printf "true" || printf "false"; printf " / "; if_non_zero_and_empty $xyz && echo "true" || echo "false"
xyz="any-value"; printf "expect true, got "; if_zero_or_empty $xyz && printf "true" || printf "false"; printf " / "; if_non_zero_and_empty $xyz && echo "true" || echo "false"

INSTALL_SAMBA_SERVER=${INSTALL_SAMBA_SERVER:-1}
INSTALL_BASIC_PKGS=${INSTALL_BASIC_PKGS:-1}
INSTALL_ZSH=${INSTALL_ZSH:-1}
INSTALL_GIT_ENV=${INSTALL_GIT_ENV:-1}
INSTALL_GOLANG=${INSTALL_GOLANG:-0}
INSTALL_GCC_10=${INSTALL_GCC_10:-0}

if_zero_or_empty INSTALL_ZSH || echo install_zsh

