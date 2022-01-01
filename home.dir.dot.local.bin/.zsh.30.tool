ports() {
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

zsh_theme_set() {
	local theme_name=${1:-af-magic}
	perl -i -pe "s/ZSH_THEME=\".+\"/ZSH_THEME=\"$theme_name\"/" ~/.zshrc
}
