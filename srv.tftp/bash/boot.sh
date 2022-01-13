#!/bin/bash
# -*- mode: bash; c-basic-offset: 2; tab-width: 2; indent-tabs-mode: t-*-
# vi: set ft=bash noet ci pi sts=0 sw=2 ts=2:
# st:
#
#
# # /usr/bin/env bash
#
# License: MIT
#  - https://github.com/hedzr/bash.sh
#    Version: 20180215
# HZ:
#   Standard Template for bash/zsh developing.
#

SUDO=sudo
[ "$(id -u)" = "0" ] && SUDO=

GPG_KEYID_MASTER=362622A43CC67D533FFBD33F2E6F77F217AFB9B1
GPG_KEYID=2E213A751C434E36      # GH
GPG_KEYID_MAIL=8D9B6C4242615E10 # Mail

GIT_USERNAME="hedzr"
GIT_USERMAIL="hedzrz@gmail.com"
GIT_SIGN_KEY="${GPG_KEYID}!"

DEBEMAIL="$GIT_USERMAIL"
#DEBFULLNAME="Hedzr Yeh"
DEBFULLNAME="hedzr (hz, hedzr)"

DEFAULT_SSH_KEY="AAAAB3NzaC1yc2EAAAADAQABAAABAQDxjcUOlmgsabCmeYD8MHnsVxueebIocv5AfG3mpmxA3UZu6GZqnp65ipbWL9oGtZK3BY+WytnbTDMYdVQWmYvlvuU6+HbOoQf/3z3rywkerbNQdffm5o9Yv/re6dlMG5kE4j78cXFcR11xAJvJ3vmM9tGSBBu68DR35KWz2iRUV8l7XV6E+XmkPkqJKr3IvrxdhM0KpCZixuz8z9krNue6NdpyELT/mvD5sL9LG4+XtU0ss7xH1jk5nmAQGaJW9IY8CVGy07awf0Du5CEfepmOH5gJbGwpAIIubAzGarefbltXteerB0bhyyC3VX0Q8lIHZ6GhMZSqfD9vBHRnDLIL"

INSTALL_SAMBA_SERVER=${INSTALL_SAMBA_SERVER:-1}
INSTALL_BASIC_PKGS=${INSTALL_BASIC_PKGS:-1}
INSTALL_ZSH=${INSTALL_ZSH:-1}
INSTALL_GIT_ENV=${INSTALL_GIT_ENV:-1}
INSTALL_GOLANG=${INSTALL_GOLANG:-0}
INSTALL_GCC_10=${INSTALL_GCC_10:-0}

# needs INSTALL_BASIC_PKGS=1
INSTALL_MC=${INSTALL_MC:-1} # for larger packages: htop mc ranger jq

# more:

INSTALL_LOCALES=${INSTALL_LOCALES:-0}
INSTALL_AND_SETUP_UFW=${INSTALL_AND_SETUP_UFW:-0}

FORCE_SYSCTL=${FORCE_SYSCTL:-1}

#########################

ALLOW_ROOT_LOGIN=${ALLOW_ROOT_LOGIN:-1}
ALLOW_NOPASS_SUDO=${ALLOW_NOPASS_SUDO:-1}
ALLOW_AUTO_TTY_LOGIN=${ALLOW_AUTO_TTY_LOGIN:-1}
ALLOW_USE_DHCP_ALL=${ALLOW_USE_DHCP_ALL:-1}

ALLOW_GENERATE_LOCALES=${ALLOW_GENERATE_LOCALES:-0}
ALLOW_CONFIG_UFW=${ALLOW_CONFIG_UFW:-0}

#########################

TARGET_TIMEZONE=Asia/Chongqing

LOCAL_DOMAIN="ops.local"

ubuntu_codename=focal
ubuntu_version=20.04.3
ubuntu_iso=ubuntu-${ubuntu_version}-live-server-amd64.iso

ubuntu_mirrors=("mirrors.cqu.edu.cn" "mirrors.ustc.edu.cn" "mirrors.tuna.tsinghua.edu.cn" "mirrors.163.com" "mirrors.aliyun.com")

#########################

boot_first_install() {

	{ _entry; } | tee /var/log/boot.sh.log

	info_print
	# rm -rf /root/boot.sh
}

info_print() {
	$SUDO parted -l
	df -hT
	lsblk
	# less /var/log/cloud-init-output.log
	ip a|grep 'inet '|grep -v '127\.0\.0\.1'
	timedatectl

	echo '======= boot.sh: ALL FOLKS! Restart OS so that auto login to tty1'
	echo '         Or run: sudo systemctl restart getty@tty1.service'
	#sleep 5
	#$SUDO systemctl restart getty@tty1.service
}

_entry() {
	# echo "vms ok";

	# local HostName=u20v.local
	# local hostName=u20v
	local Username=hz
	local HostName=$(hostname -f)
	local hostName=$(hostname -s)
	echo && echo && env | sort && echo && echo
	echo && echo && hostnamectl && echo && echo
	echo && echo && timedatectl && echo && echo

	apt_source

	#setup_hostnames
	if_zero_or_empty $ALLOW_ROOT_LOGIN || allow_root_login
	adjust_ntp
	tune_limits
	if_zero_or_empty $ALLOW_NOPASS_SUDO || nopass_sudo
	if_zero_or_empty $ALLOW_AUTO_TTY_LOGIN || auto_tty
	if_zero_or_empty $ALLOW_USE_DHCP_ALL || all_dhcp

	if_zero_or_empty $INSTALL_SAMBA_SERVER || install_samba_server
	if_zero_or_empty $INSTALL_BASIC_PKGS || install_basic_pkgs
	if_zero_or_empty $INSTALL_LOCALES || install_locales
	if_zero_or_empty $INSTALL_AND_SETUP_UFW || install_ufw

	if_zero_or_empty $ALLOW_GENERATE_LOCALES || install_locales
	if_zero_or_empty $ALLOW_CONFIG_UFW || install_ufw

	if_zero_or_empty $INSTALL_ZSH || install_zsh
	if_zero_or_empty $INSTALL_GIT_ENV || install_git_env
	if_zero_or_empty $INSTALL_GOLANG || install_golang
	if_zero_or_empty $INSTALL_GCC_10 || install_gcc_10

	[ -f /root/boot.sh ] && {
		$SUDO chmox a+x /root/boot.sh
		$SUDO mv /root/boot.sh /usr/local/bin/booter.sh
	}
	[ -f /root/gpg.key ] && $SUDO rm /root/gpg.key
}

setup_hostnames() {
	headline $(_curr_func_name)
	$SUDO hostnamectl set-hostname $HostName
	$SUDO hostnamectl set-icon-name $hostName
	$SUDO hostnamectl set-chassis vm  # "desktop", "laptop", "convertible", "server", "tablet", "handset", "watch", "embedded"
	$SUDO hostnamectl set-deployment development # "development", "integration", "staging", "production"
	$SUDO hostnamectl set-location "$TARGET_TIMEZONE"
	hostnamectl
}

allow_root_login() {
	headline $(_curr_func_name)
	$SUDO sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
	$SUDO systemctl restart sshd
	#systemctl stop ufw.service
	#systemctl disable ufw.service
}

adjust_ntp() {
	headline $(_curr_func_name)
	echo -e "NTP=ntp1.aliyun.com\nFallbackNTP=ntp.ubuntu.com" | $SUDO tee -a /etc/systemd/timesyncd.conf
	$SUDO systemctl restart systemd-timesyncd
}

tune_limits() {
	headline $(_curr_func_name)

	cat <<-EOF | $SUDO tee -a /etc/security/limits.conf
		*       soft        nofile  655350
		*       hard        nofile  655350
		*       soft        nproc   655350
		*       hard        nproc   655350
		root        soft        nofile  655350
		root        hard        nofile  655350
		root        soft        nproc   655350
		root        hard        nproc   655350
	EOF

	# http://coolshell.cn/articles/7490.html
	if if_non_zero_and_empty $FORCE_SYSCTL; then
		#
		# TODO 针对 1/2/4/8/16/32 core, 1/2/4/8/16/32 GB 规格，需要分别定制内核参数才有意义
		#
		#$SUDO sed -i 's/#net.ipv4.ip_forward=1/net.ipv4.ip_forward=1/g' /etc/sysctl.conf
		#$SUDO sed -i 's/#net.ipv6.conf.all.forwarding=1/net.ipv6.conf.all.forwarding=1/g' /etc/sysctl.conf
		cat <<-EOH | $SUDO tee /etc/sysctl.d/51.net.opts.conf
			net.ipv4.ip_forward=1
			net.ipv6.conf.all.forwarding=1
			## JY ##
			net.ipv4.tcp_keepalive_probes = 5
			net.ipv4.tcp_keepalive_intvl = 20
			net.ipv4.tcp_fin_timeout = 3
			net.ipv4.tcp_keepalive_time = 600
			##
			net.ipv4.tcp_tw_reuse=1
			net.ipv4.tcp_tw_recycle=1
			##
			net.ipv4.tcp_syn_retries = 1
			net.ipv4.tcp_synack_retries = 1
			net.ipv4.tcp_retries2 = 5
			net.ipv4.tcp_max_tw_buckets = 36000
			net.ipv4.tcp_max_orphans = 32768
			net.ipv4.tcp_syncookies = 1
			net.ipv4.tcp_max_syn_backlog = 16384
			net.ipv4.tcp_wmem = 8192 131072 16777216
			net.ipv4.tcp_rmem = 32768 131072 16777216
			net.ipv4.tcp_mem = 786432 1048576 1572864
			net.ipv4.ip_local_port_range = 1024 65000
			net.ipv4.ip_conntrack_max = 65536
			net.ipv4.netfilter.ip_conntrack_max=65536
			net.ipv4.netfilter.ip_conntrack_tcp_timeout_established=180
			net.core.somaxconn = 16384
			net.core.netdev_max_backlog = 16384
			##
			net.core.wmem_default = 8388608
			net.core.rmem_default = 8388608
			net.core.rmem_max = 16777216
			net.core.wmem_max = 16777216
		EOH
		$SUDO sysctl -p
	fi

	cat <<-EOH | $SUDO tee /etc/profile.d/10.eth_txqueuelen.sh
		#!/bin/bash
		#[ "\$(id -u)" = "0" ] && ifconfig eth0 txqueuelen 5000
		[ "\$(id -u)" = "0" ] && for i in \$(ifconfig -s -a|grep -Poi 'eth\d+'); do ifconfig \$i txqueuelen 5000; done
	EOH

	# 表 1. ulimit 参数说明
	# 选项 [options]	含义	例子
	# -H	设置硬资源限制，一旦设置不能增加。	ulimit –Hs 64；限制硬资源，线程栈大小为 64K。
	# -S	设置软资源限制，设置后可以增加，但是不能超过硬资源设置。	ulimit –Sn 32；限制软资源，32 个文件描述符。
	# -a	显示当前所有的 limit 信息。	ulimit –a；显示当前所有的 limit 信息。
	# -c	最大的 core 文件的大小， 以 blocks 为单位。	ulimit –c unlimited； 对生成的 core 文件的大小不进行限制。
	# -d	进程最大的数据段的大小，以 Kbytes 为单位。	ulimit -d unlimited；对进程的数据段大小不进行限制。
	# -f	进程可以创建文件的最大值，以 blocks 为单位。	ulimit –f 2048；限制进程可以创建的最大文件大小为 2048 blocks。
	# -l	最大可加锁内存大小，以 Kbytes 为单位。	ulimit –l 32；限制最大可加锁内存大小为 32 Kbytes。
	# -m	最大内存大小，以 Kbytes 为单位。	ulimit –m unlimited；对最大内存不进行限制。
	# -n	可以打开最大文件描述符的数量。	ulimit –n 128；限制最大可以使用 128 个文件描述符。
	# -p	管道缓冲区的大小，以 Kbytes 为单位。	ulimit –p 512；限制管道缓冲区的大小为 512 Kbytes。
	# -s	线程栈大小，以 Kbytes 为单位。	ulimit –s 512；限制线程栈的大小为 512 Kbytes。
	# -t	最大的 CPU 占用时间，以秒为单位。	ulimit –t unlimited；对最大的 CPU 占用时间不进行限制。
	# -u	用户最大可用的进程数。	ulimit –u 64；限制用户最多可以使用 64 个进程。
	# -v	进程最大可用的虚拟内存，以 Kbytes 为单位。	ulimit –v 200000；限制最大可用的虚拟内存为 200000 Kbytes。
	# cat >/etc/profile.d/11.ulimit.sh<<-EOH
	# #!/bin/bash
	# [ "\$(id -u)" = "0" ] && {
	# 	ulimit -S -c 0 > /dev/null 2>&1
	# 	ulimit -s 8192		# aws cn default 8192
	# 	ulimit -u 10000		# aws cn default 3896
	# 	ulimit -n 65535		# aws cn default 1024
	# }
	# EOH

	# ls -la /etc/profile.d/
}

apt_source() {
	headline $(_curr_func_name)
	[ -f /etc/apt/sources.list.cqu.bak ] || {
		local mirror="${ubuntu_mirrors[0]}"
		$SUDO cp /etc/apt/sources.list{,.cqu.bak}
		$SUDO sed -i -r "s/us.archive.ubuntu.com/$mirror/" /etc/apt/sources.list
		$SUDO sed -i -r "s/cn.archive.ubuntu.com/$mirror/" /etc/apt/sources.list
		$SUDO sed -i -r "s/archive.ubuntu.com/$mirror/" /etc/apt/sources.list

		$SUDO apt-get update
	}
	$SUDO apt install -y curl wget lsof net-tools whois
}

nopass_sudo() {
	headline $(_curr_func_name)

	first_init_users

	$SUDO groupadd -g 201 power
	$SUDO usermod -aG power $Username
	echo "%power   ALL=(ALL) NOPASSWD: ALL" | $SUDO tee /etc/sudoers.d/power
	$SUDO chmod 440 /etc/sudoers.d/power
}

auto_tty() {
	headline $(_curr_func_name)
	local odir=/etc/systemd/system/getty@tty1.service.d
	[ -d $odir ] || $SUDO mkdir -pv $odir
	cat <<-EOF | $SUDO tee $odir/override.conf
		[Service]
		ExecStart=
		ExecStart=-/sbin/agetty --noissue --autologin $Username %I \$TERM
		Type=idle
	EOF
}

all_dhcp() {
	declare -a na
	local network_str="" str="" n=1 i
	na=($(ifconfig -s -a | tail -n +2 | grep -v '^lo' | awk '{print $1}'))
	for i in ${na[@]}; do
		[[ $n -gt 1 ]] && str=", " || str=""
		str="${str}${i}: {dhcp4: yes,dhcp6: yes,optional: true}"
		network_str="${network_str}${str}"
		let n++
	done

	local f="$(ls -b /etc/netplan/*.yaml | head -1)"
	grep -q 'ethernets: \{' $f || {
		cat <<-EOF | $SUDO tee $f
			network:
			  ethernets: { $network_str }
			    # ens33:
			    #   critical: true
			    #   dhcp-identifier: mac
			    #   dhcp4: true
			    #   nameservers:
			    #     addresses:
			    #     - 172.16.207.2
			    #     search:
			    #     - localdomain
			    # ens38:
			    #   dhcp4: true
			    # ens39:
			    #   dhcp4: true
			  version: 2
		EOF
	}
}

install_samba_server() {
	headline $(_curr_func_name)
	$SUDO apt-get install -y samba
	# $SUDO systemctl status smbd.service
	$SUDO systemctl enable smbd.service

	cat <<-"EOF" | $SUDO tee -a /etc/samba/smb.conf


		## HZ


		[homes]
		   comment = Home Directories
		   browseable = yes

		# By default, the home directories are exported read-only. Change the
		# next parameter to 'no' if you want to be able to write to them.
		   read only = no

		# File creation mask is set to 0700 for security reasons. If you want to
		# create files with group=rw permissions, set next parameter to 0775.
		   create mask = 0664

		# Directory creation mask is set to 0700 for security reasons. If you want to
		# create dirs. with group=rw permissions, set next parameter to 0775.
		   directory mask = 0755

		# By default, \\server\username shares can be connected to by anyone
		# with access to the samba server.
		# Un-comment the following parameter to make sure that only "username"
		# can connect to \\server\username
		# This might need tweaking when using external authentication schemes
		   valid users = %S

	EOF
	# $SUDO nano /etc/samba/smb.conf
	$SUDO systemctl restart smbd.service

	#### add new samba user and password
	echo -e "password\npassword" | $SUDO smbpasswd -a hz
}

install_basic_pkgs() {
	headline $(_curr_func_name)
	$SUDO apt-get install -y curl wget git build-essential make gnu-standards lsof net-tools dnsutils
	if_zero_or_empty $INSTALL_MC || $SUDO apt-get install -y htop mc ranger jq
	$SUDO snap install -y yq
	# ninja-build gdb m4 nasm valgrind ccache
	# libtool ccze mc ranger jq
	# flex bison cmake
}

install_locales() {
	headline $(_curr_func_name)
	# headline "install-locales ..."
	for l in en en_US en_US.UTF-8 zh zh.UTF-8 zh_CN zh_TW zh_CN.UTF-8 zh_TW.UTF-8 ja ko_KR ru_RU ca; do $SUDO locale-gen $l; done
	$SUDO update-locale
	for l in zh jp ru en; do $SUDO apt-get install -y language-pack-$l; done
	# https://askubuntu.com/questions/76013/how-do-i-add-locale-to-ubuntu-server
	# $SUDO locale-gen ru_RU
	# $SUDO locale-gen ru_RU.UTF-8
}

install_ufw() {
	local SS_PORT=${SS_PORT:-6379}

	headline $(_curr_func_name)
	# headline "install-ufw"
	$SUDO apt-get install -y ufw
	sed -i 's/IPV6=no/IPV6=yes/' /etc/default/ufw
	ufw default deny incoming
	ufw default allow outgoing
	ufw allow 22
	ufw allow 80
	ufw allow 443
	ufw allow $SS_PORT # used for ss, not redis
	echo 'y' | ufw enable
}

install_ports() {
	headline $(_curr_func_name)
	local name=${1:-$Username}
	local home=$(_homedir $name)
	local file=${1:-$home/.bashrc}
	grep -qE 'ports[ ]*\(\)[ ]*\{' $file || {
		cat >>$file <<-"EOF"
			#
			#
			function ports () {
			  local SUDO=sudo
			  [ "$(id -u)" = "0" ] && SUDO=
			  if [ $# -eq 0 ]; then
			    $SUDO lsof -Pni | grep -P "LISTEN|UDP"
			  else
			    local p='' i
			    for i in "$@"; do
			      if [[ "$i" -gt 0 ]]; then
			        p="$p -i :$i"
			      else
			        p="$p -i $i"
			      fi
			    done
			    # DEBUG echo "lsof -Pn $p"
			    $SUDO lsof -Pn $p
			  fi
			}
		EOF
	}
}

has_user() {
	local name=${1:-mysql-bug-anyone}
	[ "$name" == "mysql-bug-anyone" ] && {
		echo "has-user 需要一个账户名称作为参数"
		exit -1
	}
	grep -q "^$name:" /etc/passwd
}

create_daemon_user() {
	local name=${1:-mysql}
	[ -d /var/lib/home ] || $SUDO mkdir /var/lib/home
	has_user $name || $SUDO adduser --system --group --home /var/lib/home/$name $name
}

destroy_daemon_user() {
	local name=${1:-mysql}
	has_user $name && $SUDO deluser $name
	# delgroup $name
	[ -d /var/lib/home/$name ] && $SUDO rm -rf /var/lib/home/$name
}

create_daemon_user_nohome() {
	local name=${1:-mysql}
	has_user $name || $SUDO adduser --system --group --no-create-home --disabled-password --disabled-login $name
}

create_admin_user() {
	local name=${1:-admin}
	local home=$(_homedir $name)
	local F=$home/.ssh/id_rsa

	has_user $name && return

	# adduser 没有 skel 步骤
	# useradd 是正确的后端，具备 skel 步骤
	$SUDO useradd --system --user-group -m -d $home --shell /bin/bash $name
	[ -f $F ] || su - $name -c "ssh-keygen -b 2048 -C '$name@$(hostname)' -q -N '' -f $F"
	[ -f $F.pub ] && {
		echo ""
		echo "SSH Key for $name:"
		cat $F.pub
	}
}

create_sync_user() {
	local name=${1:-cobb}
	local home=$(_homedir $name)
	local A=$home/.ssh/authorized_keys
	local F=$home/.ssh/id_rsa

	has_user $name && return

	# adduser 没有 skel 步骤
	# useradd 是正确的后端，具备 skel 步骤
	$SUDO useradd --user-group -m -d $home --shell /bin/bash $name
	[ -f $F ] || su - $name -c "ssh-keygen -b 2048 -C '$name@$(hostname)' -q -N '' -f $F"
	[ -f $F.pub ] && {
		echo ""
		echo "SSH Key for $name:"
		cat $F.pub
	}
	#check-cobb-auth $name
	#check-cobb-auth "root"
}

create_hz_user() {
	F=/etc/sudoers
	$SUDO test -f $F && {
		$SUDO grep -qE '^%hzadmin' $F || {
			echo "%hzadmin  ALL=(ALL) NOPASSWD:ALL" >>$F
			echo "group hzadmin -> nopasswd sudo setup."
		}
	}
	grep -qE '^hzadmin:x:313' /etc/group || $SUDO addgroup --system --gid 313 hzadmin

	grep -qE '^hz:' /etc/passwd || {
		create_admin_user hz
		local pwd=${PASS:-tinder#5%glich}
		echo "hz:$pwd" | /usr/sbin/chpasswd
	}
	$SUDO usermod -aG hzadmin,adm,cdrom,dip,plugdev,lxd hz

	install_ports hz
}

check_hz_auth() {
	local name=${1:-hz}
	echo "checking auth for account '$name':"
	check_ssh_auth $name "$DEFAULT_SSH_KEY" "$GIT_USERMAIL"
}

check_ssh_auth() {
	local name="$1"
	local key="$2"
	local title="$3"
	local home=$(_homedir $name)
	local A=$home/.ssh/authorized_keys
	$SUDO test -f $A && {
		$SUDO grep -q "ssh-rsa $key" $A >/dev/null && echo "    $title existed." || {
			echo "ssh-rsa $key $title" | $SUDO tee -a $A 1>/dev/null
			echo "    $title appended"
		}
	} || {
		$SUDO tee $A 1>/dev/null <<-EOF
			ssh-rsa $key $title
		EOF
		echo "    $title created"
	}
	$SUDO chown -R $name: $A
	$SUDO chmod 600 $A
}

first_init_users() {
	headline $(_curr_func_name)
	create_hz_user
	check_hz_auth
	check_hz_auth root
}

install_zsh() {
	headline $(_curr_func_name)

	$SUDO apt-get install -y zsh # zsh-doc
	zsh --version

	install_zsh_to $Username
}

install_zsh_to() {
	local name="${1:-$Username}"
	local home=$(_homedir $name)
	local zsh_theme="linuxonly"
	local zsh_history_size=9999

	$SUDO chsh -s $(which zsh) $name
	$SUDO usermod --shell $(which zsh) $name

	headline 'install oh-my-zsh ...'
	$SUDO wget https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh -O /tmp/install.sh
	$SUDO chmod +x /tmp/install.sh
	$SUDO su - $name -c "RUNZSH=no CHSH=no /tmp/install.sh"

	headline 'cloneing zsh-autosuggestions ...'
	$SUDO su - $name -c "git clone https://github.com/zsh-users/zsh-autosuggestions $home/.oh-my-zsh/custom/plugins/zsh-autosuggestions"
	headline 'cloneing zsh-syntax-highlighting ...'
	$SUDO su - $name -c "git clone https://github.com/zsh-users/zsh-syntax-highlighting.git $home/.oh-my-zsh/custom/plugins/zsh-syntax-highlighting"

	headline 'configuring .zshrc ...'
	$SUDO test -f /root/ys-rich.zsh-theme && {
		$SUDO cp /root/ys-rich.zsh-theme $home/.oh-my-zsh/themes/
		$SUDO chown $USER: $home/.oh-my-zsh/themes/ys-rich.zsh-theme
		zsh_theme="ys-rich"
	}
	$SUDO su - $name -c "perl -i -pe \"s/plugins=\(git\)/plugins=(git z zsh-autosuggestions zsh-syntax-highlighting)/\" $home/.zshrc"
	# https://github.com/ohmyzsh/ohmyzsh/wiki/Themes
	$SUDO su - $name -c "perl -i -pe 's/ZSH_THEME=\"robbyrussell\"/ZSH_THEME=\"${zsh_theme}\"/' $home/.zshrc"

	$SUDO su - $name -c "perl -i -pe 's#\# export PATH=.+$#PATH=\$HOME/\.local/bin:\$PATH#' $home/.zshrc"

	cat >>$home/.zshrc <<-EOF



		# Lines configured by zsh-newuser-install
		# export LC_ALL=C
		export LC_ALL=en_US.UTF-8  # solve perl warning, git-prompt-info chracter not in range
		HISTFILE=~/.zsh_history
		HISTSIZE=$zsh_history_size
		SAVEHIST=$zsh_history_size
		bindkey -e
		# End of lines configured by zsh-newuser-install


		## autocomp system

		fpath=(/usr/local/share/zsh/site-functions \$fpath)

		# The following lines were added by compinstall
		zstyle :compinstall filename '/home/hz/.zshrc'

		autoload -Uz compinit
		compinit
		# End of lines added by compinstall



		# user defined

		[ -d ~/.local/bin ] && \
		  for f in ~/.local/bin/.zsh.*; do source \$f; done
		[ -d ~/bin ] && \
		  for f in ~/bin/.zsh.*; do source \$f; done

		# end of user defined

	EOF

	headline "mkdir $home/.local/bin"
	$SUDO mkdir -pv $home/.local/bin &&
		$SUDO touch $home/.local/bin/.zsh.{10.alias,00.path,30.tool,99.tail} &&
		$SUDO chown -R $name: $home/.local $home/.zsh*
	$SUDO cat >>$home/.local/bin/.zsh.30.tool <<-"EOF"

		function ports() {
		  local SUDO=sudo
		  [ "$(id -u)" = "0" ] && SUDO=
		  if [ $# -eq 0 ]; then
		    $SUDO lsof -Pni | grep -P "LISTEN|UDP"
		  else
		    local p='' i
		    for i in "$@"; do
		      if [[ "$i" -gt 0 ]]; then
		        p="$p -i :$i"
		      else
		        p="$p -i $i"
		      fi
		    done
		    # DEBUG echo "lsof -Pn $p"
		    $SUDO lsof -Pn $p
		  fi
		}

		function zsh_theme_set() {
		  local theme_name=${1:-af-magic}
		  perl -i -pe "s/ZSH_THEME=\".+\"/ZSH_THEME=\"$theme_name\"/" ~/.zshrc
		}

	EOF

	$SUDO cat >>$home/.local/bin/.zsh.30.tool <<-"EOF"

		# eval `ssh-agent`
		# [ -f ~/.ssh/id_rsa ] && ssh-add ~/.ssh/id_rsa
		alias ssh='ssh -A'
		# you may review it with: ssh-add -l

	EOF

	sed_yes_no AllowAgentForwarding
	sed_yes_no AllowTcpForwarding
	cat <<-EOF | $SUDO tee /etc/ssh/sshd_config.d/all_agent_forwarding
	Host *
	    ForwardAgent yes
	EOF

	sed_yes_no TCPKeepAlive
	sed_key_value ClientAliveInterval 60
	sed_key_value ClientAliveCountMax 100000

	$SUDO cat >>$home/.local/bin/.zsh.00.path <<-EOF


		# the gpg keys
		export GPG_KEYID_MASTER=$GPG_KEYID_MASTER
		export GPG_KEYID=$GPG_KEYID          # GH
		export GPG_KEYID_MAIL=$GPG_KEYID_MAIL     # Mail


		# for DEB MAKE
		DEBEMAIL="$DEBEMAIL"
		DEBFULLNAME="$DEBFULLNAME"
		export DEBEMAIL DEBFULLNAME
		#DEBUILD_DPKG_BUILDPACKAGE_OPTS="-i -I -us -uc"
		#DEBUILD_LINTIAN_OPTS="-i -I --show-overrides"
		DEBSIGN_KEYID="\$GPG_KEYID_MASTER"
		DEB_SIGN_KEYID="\$GPG_KEYID_MASTER"
		export DEBSIGN_KEYID DEB_SIGN_KEYID

	EOF
	$SUDO chown -R $name: $home/.local $home/.zsh*
}

sed_yes_no () {
	local key=$1
	local f=$2
	if grep -qP "^#$key yes" $f; then
		$SUDO sed -i -r "s/^#$key yes/$key yes/" $f
	else
		if grep -qP "^$key yes" $f; then
			:
		else
			cat <<-EOF | $SUDO tee -a $f
			$key yes
			EOF
		fi
		if grep -qP "^$key no" $f; then
			$SUDO sed -i -r "s/^$key no/#$key no/" $f
		fi
	fi
}
sed_key_value () {
	local key=$1
	local value=$2
	local f=$3
	if grep -qP "^#$key $value" $f; then
		$SUDO sed -i -r "s/^#$key $value/$key $value/" $f
	else
		if grep -qP "^$key $value" $f; then
			:
		else
			cat <<-EOF | $SUDO tee -a $f
			$key $value
			EOF
		fi
	fi
}

install_git_env() {
	headline $(_curr_func_name)

	local name="${1:-$Username}"
	local home=$(_homedir $name)

	$SUDO apt-get install -y git

	local GK=/root/gpg.key
	$SUDO test -f $GK && $SUDO chmod a+r $GK &&
		$SUDO su - $name -c "gpg --import $GK" &&
		$SUDO rm -f $GK &&
		$SUDO su - $name -c "
		  git config --global user.signingkey $GIT_SIGN_KEY;
		  git config --global commit.gpgsign 'true';
			"

	$SUDO su - $name -c "
		git config --global user.name '$GIT_USERNAME';
		git config --global user.email '$GIT_USERMAIL';

		git config --global core.excludesfile '$home/.gitignore';
		git config --global core.filemode 'false';
		git config --global core.safecrlf warn;
		git config --global core.autocrlf input;
		git config --global core.editor nano;
		git config --global core.pager 'less -FX';

		git config --global commit.template '$home/.stCommitMsg';
	"

	cat <<-"EOF" | $SUDO su - $name -c "tee -a $home/.gitconfig"

		[init]
		  defaultBranch = master

		[alias]
		  st = status -s
		  ci = commit
		  co = checkout
		  br = branch
		  rb = rebase
		  dci = dcommit
		  sbi = submodule init
		  sbu = submodule update
		  sbp = submodule foreach git pull
		  sbc = submodule foreach git co master
		  # st = status -sb
		  #dci = dcommit
		  rebase-to = "! bash -c \"X1=\\`git symbolic-ref HEAD 2> /dev/null | cut -b 12-\\`; echo rebasing from \\$X1 to $1 ...; git checkout $1; git rebase \\$X1; git checkout \\$X1 \""
		  rr = "! bash -c \"X1=\\`git symbolic-ref HEAD 2> /dev/null | cut -b 12-\\`; echo rebasing from \\$X1 to $1 ...; git checkout $1; git rebase \\$X1; git checkout \\$X1 \""
		  merge-no-ff = merge --no-ff
		  mg = merge --no-ff
		  upull = pull upstream
		  upp = "! bash -c \"X1=\\`git symbolic-ref HEAD 2> /dev/null | cut -b 12-\\`; echo Pulling branch *\\$X1* from *upstream* ...; git pull upstream \\$X1 \""
		  files = ls-tree --full-tree -r --name-only HEAD
		  #l = log --oneline --decorate -13
		  l = log --oneline --decorate -12 --color
		  ll = log --oneline --decorate --color
		  lc = log --graph --color
		  lp = log -p
		  lg = log --color --graph --oneline --decorate --pretty=format:'%Cred%h%Creset -%C(yellow)%d%Creset %s %Cgreen(%cr) %C(bold blue)<%an>%Creset' --abbrev-commit
		  pulls = "! bash -c \"for br in $@; do git pull origin $br:$br; done \""
		  pu = "! bash -c \"for br in $@; do git push origin $br:$br; done \""
		  pushs = "! bash -c \"for br in $@; do git push origin $br:$br; done \""
		  push-all = "! bash -c \"git push origin --all;git push origin --tags \""
		  tarball = "! bash -c \"git archive --format=tar.gz -o ../$1.tar.gz --prefix=$1/ HEAD; ls -la ../$1.tar.gz \""
		  m2 = "! bash -c \"git checkout $1; git merge --no-ff $2; git checkout $2 \""
		  m3 = ! bash -c \"echo \\\"$3\\\" \\\"$4\\\" \"
		  m4 = ! bash -c \"echo \\\"$*\\\" \"
		  mm = "! bash -c \"X1=\\`git symbolic-ref HEAD 2> /dev/null | cut -b 12-\\`; echo merging from \\$X1 to $1 ...; git checkout $1; git merge --no-ff \\$X1; git checkout \\$X1 \""
		  mt = "! bash -c \"X1=\\`git symbolic-ref HEAD 2> /dev/null | cut -b 12-\\`; echo merging from \\$X1 to $1 ...; git checkout $1; git merge --no-ff \\$X1; git tag $2; git checkout \\$X1 \""
		  tt = "! bash -c \"X1=\\`git symbolic-ref HEAD 2> /dev/null | cut -b 12-\\`; git checkout master; git tag $1; git checkout \\$X1 \""
		  gh = "!bash -c \"git co master; git merge --no-ff devel; git push origin master; git co devel\""
		  ac = !git add -A && git commit
		  branches = branch -a
		  tags = tag -l
		  remotes = remote -v
		  cleanup = !git branch --merged | grep -v '*' | xargs git branch -d
		  tag-rel = "! bash -c \"X1=\\`git symbolic-ref HEAD 2> /dev/null | cut -b 12-\\`; echo taging master to release $1 [\\$X1] ...; git checkout master; git tag release/v$1; git checkout \\$X1 \""
		  rm-remote-tag = ! bash -c \"git push -v ${2:-origin} :refs/tags/$1\"
		  rm-local-branch = branch --delete
		  rm-local-branch-force = branch --delete --force
		  rm-remote-branch = ! bash -c \"git push -v ${2:-origin} --delete $1\"
		  # remove remote branch or tag: git push <remote_name> :<branch_name>

		[color]
		  interactive = true
		  ui = auto
		  diff = auto
		  status = auto
		  branch = auto

		[color "branch"]
		  current = yellow reverse
		  local = yellow
		  remote = green
		[color "diff"]
		  meta = yellow bold
		  frag = magenta bold
		  old = red bold
		  new = green bold
		[color "status"]
		  added = yellow
		  changed = green
		  untracked = cyan

		[push]
		  default = matching

		# git config --global pull.rebase false  # merge (the default strategy)
		# git config --global pull.rebase true   # rebase
		# git config --global pull.ff only       # fast-forward only
		[pull]
		  ff = false
		  rebase = false

		[http]
		  sslVerify = true
		  postBuffer = 524288000

		#[https "https://my-repo.com"]
		# proxy = http://127.0.0.1:7890
		[filter "lfs"]
		  clean = git-lfs clean -- %f
		  smudge = git-lfs smudge -- %f
		  process = git-lfs filter-process
		  required = true

	EOF

	_make_git_test_repo
}

_make_git_test_repo() {
	$SUDO su - ${1:-$Username} -c '
	mkdir test && cd test;
	git init .;
	touch README.md;
	git add . && git commit -m "new repo for testing";
	'
}

boot_install-golang() { install_golang "$@"; }
boot_install_golang() { install_golang "$@"; }

# install go 1.13 or higher
install_golang() {
	headline $(_curr_func_name)

	$SUDO apt-get install -y golang-go golang-1.13

	_install_golang_env_to $Username
}

_install_golang_env_to() {
	local name=${1:-$Username}
	$SUDO su - $name -c "go env -w GO111MODULE=on;
		go env -w GOPROXY='https://goproxy.cn,direct';
		go env -w GOFLAGS='-count=1'"
}

boot_install-gcc-10() { install_gcc_10 "$@"; }
boot_install_gcc_10() { install_gcc_10 "$@"; }

install_gcc_10() {
	headline $(_curr_func_name)

	$SUDO add-apt-repository --yes -u ppa:ubuntu-toolchain-r/test
	$SUDO apt install -y g++-10 gcc-10-locales g++-10-multilib gcc-10-doc

	$SUDO update-alternatives --list gcc
	$SUDO update-alternatives --list g++
	$SUDO update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-7 90 --slave /usr/bin/g++ g++ /usr/bin/g++-7
	$SUDO update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-9 70 --slave /usr/bin/g++ g++ /usr/bin/g++-9
	$SUDO update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-10 60 --slave /usr/bin/g++ g++ /usr/bin/g++-10

	echo 1 | $SUDO update-alternatives --config gcc

	gcc --version
	g++ -v
}

# Usages:
#  $ DEBUG=1 ./bash.sh cool
#  $ DEBUG=1 ./bash.sh
#
#  $ ./bash.sh 'is_root && echo Y'
#  $ $SUDO ./bash.sh 'is_root && echo Y'
#  $ $SUDO DEBUG=1 ./bash.sh 'is_root && echo y'
#
#  $ HAS_END=: ./bash.sh
#  $ HAS_END=false ./bash.sh
#

boot_cool() { echo cool; }
boot_sleeping() { echo sleeping; }
_my.main.do.sth() {
	local cmd=${1:-first_install} && { [ $# -ge 1 ] && shift; } || :
	# for linux only:
	# local cmd=${1:-sleeping} && && shift || :

	# echo "$cmd - $@"
	eval "boot_$cmd $@" || :
}

# unset xyz; printf "expect true, got "; if_zero_or_empty $xyz && printf "true" || printf "false"; printf " / "; if_non_zero_and_empty $xyz && echo "true" || echo "false"
# xyz=""; printf "expect true, got "; if_zero_or_empty $xyz && printf "true" || printf "false"; printf " / "; if_non_zero_and_empty $xyz && echo "true" || echo "false"
# xyz="0"; printf "expect true, got "; if_zero_or_empty $xyz && printf "true" || printf "false"; printf " / "; if_non_zero_and_empty $xyz && echo "true" || echo "false"
# xyz="1"; printf "expect false, got "; if_zero_or_empty $xyz && printf "true" || printf "false"; printf " / "; if_non_zero_and_empty $xyz && echo "true" || echo "false"
# xyz="any-value"; printf "expect true, got "; if_zero_or_empty $xyz && printf "true" || printf "false"; printf " / "; if_non_zero_and_empty $xyz && echo "true" || echo "false"
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

_curr_func_name() {
	local currentShell=$(ps -p $$ | awk "NR==2" | awk '{ print $4 }' | tr -d '-')
	if [[ $currentShell == 'bash' ]]; then
		echo ${FUNCNAME[1]}
	elif [[ $currentShell == 'zsh' ]]; then
		echo $funcstack[2]
	fi
}

_homedir() {
	local name=${1:-hz}
	local home=/home/$name
	[ "$name" = "root" ] && home=/root
	echo $home
}

#### HZ Tail BEGIN ####
in_debug() { [[ $DEBUG -eq 1 ]]; }
is_root() { [ "$(id -u)" = "0" ]; }
is_bash() { [ -n "$BASH_VERSION" ]; }
is_bash_t2() { [ ! -n "$BASH" ]; }
is_zsh() { [ -n "$ZSH_NAME" ]; }
is_darwin() { [[ $OSTYPE == *darwin* ]]; }
is_linux() { [[ $OSTYPE == *linux* ]]; }
in_sourcing() { is_zsh && [[ $ZSH_EVAL_CONTEXT == 'toplevel' ]] || [[ $(basename -- "$0") != $(basename -- "${BASH_SOURCE[0]}") ]]; }
headline() { printf "\e[0;1m$@\e[0m:\n"; }
headline-begin() { printf "\e[0;1m"; }
headline-end() { printf "\e[0m:\n"; }
main.do.sth() {
	set -e
	trap 'previous_command=$this_command; this_command=$BASH_COMMAND' DEBUG
	trap '[ $? -ne 0 ] && echo FAILED COMMAND: $previous_command with exit code $?' EXIT
	MAIN_DEV=${MAIN_DEV:-eth0}
	MAIN_ENTRY=${MAIN_ENTRY:-_my.main.do.sth}
	# echo $MAIN_ENTRY - "$@"
	in_debug && cat <<-EOF
		    in_debug: $(in_debug && echo Y || echo N)
		     is_root: $(is_root && echo Y || echo N)
		     is_bash: $(is_bash && echo Y || echo N)
		  is_bash_t2: $(is_bash_t2 && echo Y || echo N)
		      is_zsh: $(is_zsh && echo Y || echo N)
		 in_sourcing: $(in_sourcing && echo Y || echo N)
	EOF
	$MAIN_ENTRY "$@"
	trap - EXIT
	${HAS_END:-false} && echo 'Success!' || :
}
DEBUG=${DEBUG:-0}
is_darwin && realpathx() { [[ $1 == /* ]] && echo "$1" || echo "$PWD/${1#./}"; } || realpathx() { readlink -f $*; }
in_sourcing && {
	CD=${CD}
	in_debug && echo ">> IN SOURCING, \$0=$0, \$_=$_"
} || { SCRIPT=$(realpathx $0) && CD=$(dirname $SCRIPT) && in_debug && echo ">> '$SCRIPT' in '$CD', \$0='$0','$1'."; }
main.do.sth "$@"
#### HZ Tail END ####