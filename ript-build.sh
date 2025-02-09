#!/bin/bash
SCRIPT_VERSION="v2025.1"
LOG_FILE="/root/ript-build.log";
DEBUG_LOG="/root/ript-debug.log";
START_TIME=$(date "+%Y-%m-%d %H:%M:%S");
OS="DEBIAN";
CHROME_PKG_NAME="chromium"; 			# may be diff depending on OS
FIREFOX_PKG_NAME="firefox-esr";			# may be diff depending on OS
LINUX_FIRMWARE_PKG_NAME="linux-headers" # may be diff depending on OS
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/go/bin:/root/go/bin:$HOME/.local/bin:$HOME/go/bin:$HOME/.cargo/bin;
DEBIAN_FRONTEND=noninteractive;
PRIVATE_IP=$(hostname -I | cut -d ' ' -f 1);
NEEDRESTART_MODE=a;
DEBIAN_PRIORITY=critical;
IS_ARM=false;
DO_UPGRADE="n";
DO_VENV="n";
DO_WIFI="n";

ript-build() {

	if [ "${EUID}" -ne 0 ]; then
		log error "You need to execute as root";
		log info "Elevate your shell with:\033[0;35m sudo su - ";
		exit 1;
	fi

	if [[ $(grep -i "ID=KALI" /etc/os-release &>> "${DEBUG_LOG}"; echo $?;) -ne "0" ]]; then
		log error "Your OS is not currently supported, my apologies. Please use Kali (for now).";
		exit 1;
	else
		OS="KALI";
		LINUX_FIRMWARE_PKG_NAME="kali-linux-firmware"
		apt-get -yqq update  &>> "${DEBUG_LOG}" && apt-get install -yqq kali-root-login &>> "${DEBUG_LOG}";
	fi

	mkdir -p /opt/tools
	touch /root/.hushlogin
	touch $LOG_FILE && touch $DEBUG_LOG;

	exec &> >(tee -i $LOG_FILE); # log all output
	echo "${START_TIME}" > date-executed.txt
	log "${START_TIME} - Executing ript-build.sh script (${SCRIPT_VERSION}) - hold on tight...";
	log info "Script output will be in ${LOG_FILE}";
	log info "Host IP address:\033[0;35m ${PRIVATE_IP}";

	ript-user-prompts;
	ript-prebuild
	ript-install-desktop;
	ript-install-tools;
	if [[ "${DO_VENV}" == "y" ]]; then ript-venv-setup;	fi
	ript-zsh-setup;
	ript-install-tailscale;
	ript-tmux-setup;
	ript-configure-services;

	log "All of this output has been saved to 'ript-build.log'.";
	log info "If any errors are detected in the log file, they will print here. Install these packages manually:";
	grep "\[\!\]" ${LOG_FILE}
	log notice "Script execution completed! You should probably reboot at this point.";
}

ript-user-prompts() {
	log "When the time comes, would you like to (will take ~5 extra minutes):";
	while true; do
		log notice "Do a full upgrade? [Y/n]";
		read DO_UPGRADE;
		DO_UPGRADE=$(echo "${DO_UPGRADE}" | tr '[:upper:]' '[:lower:]');
		if [[ -z "${DO_UPGRADE}" ]] || [[ "${DO_UPGRADE}" == "y" ]]; then
			DO_UPGRADE="y"; # to ensure it's not empty when [ENTER] is used
			log info "A full upgrade will be performed";
			break
		elif [[ "${DO_UPGRADE}" == "n" ]]; then
			log info "A full upgrade will be skipped";
			break
		else
			log error "Please use 'y' or 'n' only\!"
		fi
	done;

	while true; do
		log notice "Setup venvs for Python projects in /opt/tools? [Y/n]";
		read DO_VENV;
		DO_VENV=$(echo "${DO_VENV}" | tr '[:upper:]' '[:lower:]');
		if [[ -z "${DO_VENV}" ]] || [[ "${DO_VENV}" == "y" ]]; then
			DO_VENV="y"; # to ensure it's not empty when [ENTER] is used
			log info "Python packages will be iterated in an effort to preload venvs for you.";
			break;
		elif [[ "${DO_VENV}" == "n" ]]; then
			log info "Skipping venv setup with /opt/tools/ packages";
			break
		else
			log error "Please use 'y' or 'n' only\!"
		fi
	done;

	while true; do
		log notice "Install the WiFi-related tools and packages? [Y/n]";
		read DO_WIFI;
		DO_WIFI=$(echo "${DO_WIFI}" | tr '[:upper:]' '[:lower:]');
		if [[ -z "${DO_WIFI}" ]] || [[ "${DO_WIFI}" == "y" ]]; then
			DO_WIFI="y"; # to ensure it's not empty when [ENTER] is used
			log info "WiFi toolbox will be installed.";
			break;
		elif [[ "${DO_WIFI}" == "n" ]]; then
			log info "Skipping WiFi toolbox.";
			break
		else
			log error "Please use 'y' or 'n' only\!"
		fi
	done;
}

ript-prebuild() {

	echo "APT::Install-Recommends \"0\";" > /etc/apt/apt.conf;
	echo "APT::Install-Suggests \"0\";" >> /etc/apt/apt.conf;
	echo "Acquire::http::Timeout \"5\";" >> /etc/apt/apt.conf
	echo "Acquire::ftp::Timeout \"5\";" >> /etc/apt/apt.conf
	echo "Acquire::Retries \"0\";" >> /etc/apt/apt.conf

	if [[ -f /etc/needrestart/needrestart.conf ]]; then
		sed -i 's/#$nrconf{kernelhints} = -1;/$nrconf{kernelhints} = 0;/' /etc/needrestart/needrestart.conf;
	fi

	if [[ $(uname -m) == 'aarch64' ]]; then
		log "Detected ARM CPU"
		IS_ARM=true
	fi

	log "Installing 'debconf-utils' to bypass the interactive prompts.";
	apt-get -yqq update --fix-missing &>> "${DEBUG_LOG}" && apt-get -yqq install debconf-utils &>> "${DEBUG_LOG}";
	apt-get -yqq autoremove &>> "${DEBUG_LOG}" && apt-get -yqq autoclean &>> "${DEBUG_LOG}";
	if [[ $? -ne 0 ]]; then
		log error "There was an error while using APT, so we are going to exit just to be safe.";
		exit 1;
	fi

	echo "keyboard-configuration	keyboard-configuration/variant	select	English (US)" | debconf-set-selections &>> "${DEBUG_LOG}";
	echo "krb5-config	krb5-config/default_realm	string	CONTOSO.LOCAL" | debconf-set-selections &>> "${DEBUG_LOG}";
	echo "krb5-config	krb5-config/kerberos_servers	string	" | debconf-set-selections &>> "${DEBUG_LOG}";
	echo "krb5-config	krb5-config/read_conf	boolean	true" | debconf-set-selections &>> "${DEBUG_LOG}";
	echo "krb5-config	krb5-config/add_servers_realm	string	CONTOSO.LOCAL" | debconf-set-selections &>> "${DEBUG_LOG}";
	echo "krb5-config	krb5-config/add_servers	boolean	true" | debconf-set-selections &>> "${DEBUG_LOG}";
	echo "krb5-config	krb5-config/admin_server	string	" | debconf-set-selections &>> "${DEBUG_LOG}";
	echo "libc6	glibc/restart-services	string	" | debconf-set-selections &>> "${DEBUG_LOG}";
	echo "libc6:amd64	glibc/restart-services	string	" | debconf-set-selections &>> "${DEBUG_LOG}";
	echo "libc6	glibc/restart-failed	error	" | debconf-set-selections &>> "${DEBUG_LOG}";
	echo "libc6:amd64	glibc/restart-failed	error	" | debconf-set-selections &>> "${DEBUG_LOG}";
	echo "libc6	glibc/disable-screensaver	error	" | debconf-set-selections &>> "${DEBUG_LOG}";
	echo "libc6:amd64	glibc/disable-screensaver	error	" | debconf-set-selections &>> "${DEBUG_LOG}";
	echo "libc6	glibc/kernel-not-supported	note	" | debconf-set-selections &>> "${DEBUG_LOG}";
	echo "libc6:amd64	glibc/kernel-not-supported	note	" | debconf-set-selections &>> "${DEBUG_LOG}";
	echo "libc6	glibc/kernel-too-old	error	" | debconf-set-selections &>> "${DEBUG_LOG}";
	echo "libc6:amd64	glibc/kernel-too-old	error	" | debconf-set-selections &>> "${DEBUG_LOG}";
	echo "libc6	libraries/restart-without-asking	boolean	true" | debconf-set-selections &>> "${DEBUG_LOG}";
	echo "libc6:amd64	libraries/restart-without-asking	boolean	true" | debconf-set-selections &>> "${DEBUG_LOG}";
	echo "libc6	glibc/upgrade	boolean	true" | debconf-set-selections &>> "${DEBUG_LOG}";
	echo "libc6:amd64	glibc/upgrade	boolean	true" | debconf-set-selections  &>> "${DEBUG_LOG}";

	if [[ "${DO_UPGRADE}" == "y" ]]; then
		log "Performing a full upgrade, please wait...";
		apt-get -yqq full-upgrade &>> "${DEBUG_LOG}";
		apt-get -yqq autoremove &>> "${DEBUG_LOG}";
		apt-get -yqq autoclean &>> "${DEBUG_LOG}";
	else
		log "System upgrade is being skipped per user request.";
	fi

	log "Installing and enabling SSH. Only root with a key can connect.";
	apt-get install -yq openssh-server &>> "${DEBUG_LOG}" && systemctl enable --now ssh;
	if [[ $? -eq 0 ]]; then
		tee /etc/ssh/sshd_config <<-'EOF' > /dev/null
			PermitRootLogin prohibit-password
			PubkeyAuthentication yes
			AuthorizedKeysFile .ssh/authorized_keys
			PasswordAuthentication no
			ChallengeResponseAuthentication no
			UsePAM yes
			X11Forwarding yes
			PrintMotd no
			AcceptEnv LANG LC_*
			Subsystem sftp /usr/lib/openssh/sftp-server
			GSSAPIAuthentication yes	#kerberos
			GSSAPIKeyExchange yes		#kerberos
			HostKeyAlgorithms +ssh-rsa
			PubkeyAcceptedKeyTypes +ssh-rsa
		EOF
		systemctl restart ssh;
	else
		log error "Error installing/enabling SSH. Exiting due to probable underlying issues.";
		exit 1;
	fi

	log "Disabling password requirements for all users when using 'sudo'.";
	apt-get install -yqq sudo &>> "${DEBUG_LOG}";
	touch "/root/.hushlogin";
	for u in $(\ls /home); do
		echo "${u} ALL=(ALL) NOPASSWD: ALL" | tee "/etc/sudoers.d/${u}" > /dev/null;
		touch "/home/${u}/.hushlogin";
		log info "${u} is now a privileged user.";
	done
}

ript-install-desktop() {

	log "Installing desktop environment requirements.";
	rm -rf "/etc/lightdm/";
	apt-get update -yqq  &>> "${DEBUG_LOG}"; 
	apt-get install -yqq curl xserver-xorg xserver-xorg-core xfonts-base xinit x11-xserver-utils &>> "${DEBUG_LOG}";
	if [[ $? -ne 0 ]]; then log error "Error installing graphics packages."; fi

	log "Installing a minimal xfce4 desktop environment.";
	apt-get install -yqq xfce4 xfce4-terminal xfce4-taskmanager xfce4-appfinder lightdm &>> "${DEBUG_LOG}";
	if [[ $? -ne 0 ]]; then log error "Error installing desktop environment."; fi

	# initialize lightdm
	mkdir -p '/usr/share/backgrounds/xfce' && mkdir -p /etc/lightdm/;
	echo "/usr/sbin/lightdm" > /etc/X11/default-display-manager;
	echo -n "R0lGODlhAQABAIAAAAUEBAAAACwAAAAAAQABAAACAkQBADs=" | base64 -d > '/usr/share/backgrounds/desktop_background.png';
	echo -n "R0lGODlhAQABAIAAAAUEBAAAACwAAAAAAQABAAACAkQBADs=" | base64 -d > '/usr/share/backgrounds/user_background.png';

	touch "/etc/lightdm/lightdm-gtk-greeter.conf" && tee "/etc/lightdm/lightdm-gtk-greeter.conf" <<-'EOF' > /dev/null
		[greeter]
		background=/usr/share/backgrounds/desktop_background.png
		default-user-image=/usr/share/backgrounds/user_background.png
	EOF

	touch "/etc/lightdm/lightdm.conf" && tee "/etc/lightdm/lightdm.conf" <<-'EOF' > /dev/null
		[LightDM]
		logind-check-graphical=true
		greeter-user=lightdm
		log-directory=/var/log/lightdm

		[Seat:*]

		[XDMCPServer]

		[VNCServer]
	EOF
}

ript-install-tools() {

	log "Installing packages:";
    mkdir -p /opt/tools;
	apt-get --allow-releaseinfo-change update -yqq --fix-missing;
	for p in ${APT_PACKAGES[@]}; do
		log info "+ ${p}";
		apt-get install -yqq $p &>> "${DEBUG_LOG}";
		if [[ $? != 0 ]]; then log error "Error installing ${p}"; fi
	done

	apt-get -yqq autoremove &>> "${DEBUG_LOG}" && apt-get -yqq autoclean &>> "${DEBUG_LOG}";
	ript-install-tailscale;

	log "Upgrading pip.";
	python3 -m pip install --upgrade pip --break-system-packages &>> "${DEBUG_LOG}";
	python3 -m pip install setuptools pipx --break-system-packages &>> "${DEBUG_LOG}";

	log "Installing pip packages:";
	for p in ${PIP_PACKAGES[@]}; do
		log info "+ ${p}";
		python3 -m pip install $p --break-system-packages &>> "${DEBUG_LOG}";
		if [ $? -ne 0 ]; then 
			log error "Error installing ${p}."
			log info "Re-running to see output:";
			python3 -m pip install $p --break-system-packages;
		fi
	done
	
	log "Cloning tools from GitHub:";
	git config --global https.postBuffer 157286400 && git config --global http.postBuffer 157286400;
	rm -rf /opt/tools/BloodHound.py && git clone https://github.com/fox-it/BloodHound.py.git /opt/tools/BloodHound.py;
	rm -rf /opt/tools/DFSCoerce && git clone https://github.com/Wh04m1001/DFSCoerce.git /opt/tools/DFSCoerce;
	rm -rf /opt/tools/dirsearch && git clone https://github.com/maurosoria/dirsearch /opt/tools/dirsearch;
	rm -rf /opt/tools/enum4linux && git clone https://github.com/cddmp/enum4linux-ng.git /opt/tools/enum4linux;
	rm -rf /opt/tools/EyeWitness && git clone https://github.com/ChrisTruncer/EyeWitness /opt/tools/EyeWitness;
	rm -rf /opt/tools/FindUncommonShares && git clone https://github.com/p0dalirius/FindUncommonShares /opt/tools/FindUncommonShares;
	rm -rf /opt/tools/krbrelayx && git clone https://github.com/dirkjanm/krbrelayx.git /opt/tools/krbrelayx;
	rm -rf /opt/tools/ldaprelayscan && git clone https://github.com/zyn3rgy/LdapRelayScan.git /opt/tools/ldaprelayscan;
	rm -rf /opt/tools/linkedin2username && git clone https://github.com/initstring/linkedin2username.git /opt/tools/linkedin2username;
	rm -rf /opt/tools/patator && git clone https://github.com/lanjelot/patator.git /opt/tools/patator;
	rm -rf /opt/tools/pcredz && git clone https://github.com/lgandx/PCredz.git /opt/tools/pcredz;
	rm -rf /opt/tools/petitpotam && git clone https://github.com/topotam/PetitPotam.git /opt/tools/petitpotam;
	rm -rf /opt/tools/responder && git clone https://github.com/lgandx/Responder.git /opt/tools/responder;
	rm -rf /opt/tools/rubeus2ccache && git clone https://github.com/curi0usJack/rubeus2ccache.git /opt/tools/rubeus2ccache;
	rm -rf /opt/tools/statistically-likely-usernames && git clone https://github.com/insidetrust/statistically-likely-usernames.git /opt/tools/statistically-likely-usernames
	rm -rf /opt/tools/windapsearch && git clone https://github.com/ropnop/windapsearch.git /opt/tools/windapsearch;
	git config --global --unset https.postBuffer && git config --global --unset http.postBuffer;

	if [ ! -f /usr/bin/msfconsole ]; then
		log "Installing and initializing Metasploit.";
		if [[ $OS == "KALI" ]]; then
			apt-get -yqq install metasploit-framework &>> "${DEBUG_LOG}" && msfdb init;
		else
			log info "Installing via msfupdate script"
			curl -s https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod 755 msfinstall && ./msfinstall;
			apt-get update -yqq &>> "${DEBUG_LOG}" && apt-get install -yqq metasploit-framework &>> "${DEBUG_LOG}";
			echo "no" > no && echo "yes" > yes; sudo su -c "msfdb init" postgres < no < yes; rm -rf no yes;
		fi

		mkdir -p /root/.msf4 && mkdir -p /root/logs/msf;
		tee "/root/.msf4/msfconsole.rc" <<-'EOF' > /dev/null
			set PROMPT %bld%red%T %whi%L %blu"s:"%S "j:"%J%clr
			echo "\033[0;36m[**] Collect logs by running:\033[0m spool /root/logs/msf/<filename> \033[0m\n\n"
		EOF
	fi

	if [ "$(which aquatone >/dev/null; echo $?)" -ne 0 ]; then
		log "Installing Aquatone";
		wget -qO /tmp/aquatone.zip https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_linux_amd64_1.7.0.zip;
		unzip -j /tmp/aquatone.zip aquatone -d /usr/local/bin/ && rm /tmp/aquatone.zip;
	fi

	if [ -d "/opt/tools/EyeWitness" ]; then
		log "Installing EyeWitness.";
		sed -i 's/clear/#clear/' /opt/tools/EyeWitness/Python/setup/setup.sh;
		/bin/bash /opt/tools/EyeWitness/Python/setup/setup.sh  &>> "${DEBUG_LOG}";
		if [[ $? -ne 0 ]]; then log error "EyeWitness failed to install"; fi
	fi

	log "Installing Impacket. (pipx)";
	apt-get -yqq remove python3-impacket &>> "${DEBUG_LOG}";
	rm -rf /opt/tools/impacket && git clone -q https://github.com/CoreSecurity/impacket.git /opt/tools/impacket;
	pipx install /opt/tools/impacket/.  &>> "${DEBUG_LOG}";
	if [[ $? -ne 0 ]]; then 
		log error "Impacket failed to install."; 
	else 
		log info "Impacket Version: $(GetUserSPNs.py -h | grep "Impacket v")"; 
	fi
	
	log "Installing NetExec. (pipx)";
	rm -rf /opt/tools/NetExec && git clone https://github.com/Pennyw0rth/NetExec /opt/tools/NetExec;
	pipx install /opt/tools/NetExec/. &>> "${DEBUG_LOG}";
	if [[ $? -ne 0 ]]; then 
		log error "NetExec failed to install."; 
	else 
		log info "NetExec $(nxc -h | grep 'Version')"; 
	fi
	
	log "Installing evil-winrm.";
	gem install evil-winrm &>> "${DEBUG_LOG}";
	if [[ $? -ne 0 ]]; then log error "evil-winrm failed to install."; fi

	log "Installing Go.";
 	GO_VERSION=$(curl -sL https://golang.org/VERSION\?m\=text | head -n 1)
	if [[ "${IS_ARM}" == true ]]; then 
		curl -sL https://go.dev/dl/$GO_VERSION.linux-arm64.tar.gz -o /tmp/$GO_VERSION.tar.gz && tar -C /usr/local -xzf /tmp/$GO_VERSION.tar.gz;
	else
		curl -sL https://go.dev/dl/$GO_VERSION.linux-amd64.tar.gz -o /tmp/$GO_VERSION.tar.gz && tar -C /usr/local -xzf /tmp/$GO_VERSION.tar.gz;
	fi

	if [ "$(which go >/dev/null; echo $?)" -ne 0 ]; then
		log error "Error installing Go - Check the \$PATH variable to ensure /usr/local/go/bin is included...";
		log info "Current \$PATH value: ${PATH}";
	else
		log "Installing Go tools and packages:";
		for p in ${GO_PACKAGES[@]}; do
			log info "+ ${p}";
			go install $p &>> "${DEBUG_LOG}";
			if [[ $? -ne 0 ]]; then log error "Error installing Go package ${p}"; fi
		done
	fi

	log "Manually extracting releases of the older/archived Go packages.";
	wget -qO /tmp/go-GoMapEnum.tar.gz https://github.com/nodauf/GoMapEnum/releases/download/v1.1.0/GoMapEnum_1.1.0_linux_amd64.tar.gz && tar -xzf /tmp/go-GoMapEnum.tar.gz -C /usr/local/bin;
	
	# cleanup
	rm -rf /tmp/go-*;

	if [[ "${DO_WIFI}" == "y" ]]; then
		ript-install-wifi
	fi
}

ript-venv-setup() {
	if [[ -d /opt/tools ]]; then
		log "Iterating Python projects in /opt/tools to setup virtual environments.";
		log info "The output for these operations will be in /root/setup_venv.log";
		for dir in /opt/tools/*/; do
			if find "$dir" -maxdepth 1 -type f -name "*.py" | grep -q .; then
				log info "Attempting venv within ${dir}..." | tee -a /root/setup_venv.log;
				python3 -m venv "${dir}/venv" && source "${dir}/venv/bin/activate" &>> /root/setup_venv.log; 
				
				if [ -f "${dir}/requirements.txt" ]; then
					python3 -m pip install -r "${dir}/requirements.txt" &>> /root/setup_venv.log
				fi

				if [ -f "${dir}/setup.py" ] || [ -f "${dir}/pyproject.toml" ]; then
					python3 -m pip install "${dir}/." &>> /root/setup_venv.log;
				fi

				deactivate;
			fi
		done
	else
		log error "The /opt/tools directory does not exist. Exiting.";
	fi
}

ript-zsh-setup() {
	log "Installing oh-my-zsh";
	apt-get -yqq update --fix-missing && apt-get install -yqq zsh curl git && usermod --shell /bin/zsh root;
	rm -rf /root/.oh-my-zsh;
	rm -rf /root/.zshrc.pre-oh-my-zsh-*;
	RUNZSH='no' /bin/sh -c "$(curl -fsSL https://raw.githubusercontent.com/robbyrussell/oh-my-zsh/master/tools/install.sh)" &>> "${DEBUG_LOG}";
	log "Incorporating custom config and theme file";
	tee /root/.zshrc <<-'EOF' > /dev/null
		export ZSH="$HOME/.oh-my-zsh"
		export EDITOR='nano';
		export GREP_COLORS='1;33';
		DISABLE_AUTO_UPDATE="true";
		ZSH_THEME="default"
		plugins=(git)
		source $ZSH/oh-my-zsh.sh
		export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/go/bin:$HOME/.local/bin:$HOME/go/bin
		alias clear='clear -x'; # move the screen up vs clearing everything
	EOF

	tee /root/.oh-my-zsh/themes/default.zsh-theme  <<-'EOF' > /dev/null
		if [ "$EUID" -eq 0 ]; then 
			SYMBOL="#";
		else
			SYMBOL="\$"
			echo -e "\n\n\033[1;32m[>] You are: $(whoami) \033[0m"
			echo -e "\033[1;34m[+] Please use the root account - elevate your shell with: \033[1;33msudo su - \033[0m"
		fi
		PROMPT='%{$fg_bold[red]%}%D %T %{$reset_color%}%{$fg_bold[white]%}$(hostname -I | cut -d " " -f 1) %{$reset_color%}%{$fg_bold[blue]%}%1~%{$reset_color%} ${SYMBOL} '
		export LSCOLORS="gxfxcxdxbxegedabagacad"
		export LS_COLORS='di=1;34:ln=35;40:so=32;40:pi=33;40:ex=31;40:bd=34;46:cd=34;43:su=0;41:sg=0;46:tw=0;42:ow=0;43:'
	EOF

	cat /root/zshrc-config > /root/.zshrc;
	
	for u in $(ls /home); do
		log "Installing oh-my-zsh for the low-priv user ${u}";
		su - -c "rm -rf /home/${u}/.oh-my-zsh" ${u};
		su - -c "curl -s https://raw.githubusercontent.com/robbyrussell/oh-my-zsh/master/tools/install.sh &> /dev/null | /bin/bash" ${u};
 		cp "/root/.oh-my-zsh/themes/default.zsh-theme" "/home/${u}/.oh-my-zsh/themes/default.zsh-theme";
		cp "/root/.zshrc" "/home/${u}/.zshrc";		
		chown -hR ${u}:${u} "/home/${u}/."
		usermod --shell /bin/zsh ${u};
	done
}

ript-install-tailscale() {
	log "Installing Tailscale.";
	mkdir -p --mode=0755 /usr/share/keyrings;
	curl -fsSL "https://pkgs.tailscale.com/stable/debian/bullseye.noarmor.gpg" > /usr/share/keyrings/tailscale-archive-keyring.gpg
	curl -fsSL "https://pkgs.tailscale.com/stable/debian/bullseye.tailscale-keyring.list" > /etc/apt/sources.list.d/tailscale.list
	apt-get update -yqq &>> "${DEBUG_LOG}" && apt-get install -yqq tailscale tailscale-archive-keyring &>> "${DEBUG_LOG}";
	systemctl enable --now tailscaled
	if [[ $? -ne 0 ]]; then
		log error "Error attempting to install and start Tailscale";
	else
		log "Run 'tailscale up' to login and activate your reverse connection.";
	fi
}

ript-tmux-setup() {

	log "Installing latest Tmux from source.";
	apt-get -yqq remove tmux &>> "${DEBUG_LOG}"
	apt-get -yqq install libevent-dev ncurses-dev build-essential bison pkg-config automake git zsh ruby-full &>> "${DEBUG_LOG}";
	rm -rf /tmp/latest_tmux && git clone -q https://github.com/tmux/tmux.git /tmp/latest_tmux && cd /tmp/latest_tmux;
	sh autogen.sh &>> "${DEBUG_LOG}" && ./configure &>> "${DEBUG_LOG}" && make &>> "${DEBUG_LOG}" && make install &>> "${DEBUG_LOG}";
	if [[ $? -ne 0 ]]; then log error "Error installing Tmux."; fi
	
	log info "Initializing Tmux configuration.";
	cd /root/ && mkdir -p /root/logs/tmux;
	tee /root/.tmux.conf <<-'EOF' > /dev/null
		set-option -g default-shell /bin/zsh
		set -g @plugin 'tmux-plugins/tmux-logging'
		set -g @plugin 'tmux-plugins/tpm'
		set -g @plugin 'tmux-plugins/tmux-sensible'
		set -g history-limit 250000
		set -g allow-rename off
		set -g escape-time 50
		set-window-option -g mode-keys vi
		run '/root/.tmux/plugins/tpm/tpm'
		run '/root/.tmux/plugins/tmux-logging/logging.tmux'
		run '/root/.tmux/plugins/tmux-logging/scripts/toggle_logging.sh'
		bind-key "c" new-window \; run-shell "/root/.tmux/plugins/tmux-logging/scripts/toggle_logging.sh"
		bind-key '"' split-window \; run-shell "/root/.tmux/plugins/tmux-logging/scripts/toggle_logging.sh"
		bind-key "%" split-window -h \; run-shell "/root/.tmux/plugins/tmux-logging/scripts/toggle_logging.sh"
	EOF

	log info "Installing the Tmux Plugin Manager (TPM).";
	rm -rf /root/.tmux/plugins/tpm && git clone -q https://github.com/tmux-plugins/tpm.git /root/.tmux/plugins/tpm;
	/bin/bash /root/.tmux/plugins/tpm/scripts/install_plugins.sh &>> "${DEBUG_LOG}";
	if [[ $? -ne 0 ]]; then log error "Error installing Tmux plugins."; fi

	sed -i 's/default_logging_path="$HOME"/default_logging_path="\/root\/logs\/tmux"/' /root/.tmux/plugins/tmux-logging/scripts/variables.sh;
	tmux new-session -d; # initialize tmux
	tmux source-file /root/.tmux.conf;
	
	log info "Installing tmuxinator.";
	gem install tmuxinator &>> "${DEBUG_LOG}";
	mkdir -p /root/.config/tmuxinator;
	tee /root/.config/tmuxinator/default.yml <<-'EOF' > /dev/null
		name: default
		root: /root/
		windows:
		    - main: tmux source /root/.tmux.conf
		    - msf: msfconsole
	EOF

	log "If you are in a Tmux session, restart it now";
}

ript-configure-services() {

	log info "Enabling PostgreSQL service." && systemctl enable --now postgresql;
	log "Enabling wpa_supplicant service." && systemctl enable --now wpa_supplicant;
	log "Disabling sleep and hiberation." && systemctl mask sleep.target suspend.target hibernate.target hybrid-sleep.target;

	if [[ -d /root/.mozilla/firefox ]]; then
		log "Launching and terminating Firefox to generate a user profile."; 
		firefox-esr --headless 2> /dev/null &
		sleep 3 && pkill firefox-esr && sleep 1;
		if [[ -d "/root/.mozilla/firefox" ]]; then
			tee "/root/.mozilla/firefox/$(ls /root/.mozilla/firefox | grep default-esr)/user.js" <<-'EOF' > /dev/null
				user_pref("app.update.auto", false); // don't auto-update
				user_pref("app.update.enabled", false); // don't even look for updates
				user_pref("browser.casting.enabled", false); // disable SSDP 
				user_pref("browser.newtabbage.enabled", false); // new empty tab is empty
				user_pref("browser.safebrowsing.downloads.enabled", false); // skip safebrowsing
				user_pref("browser.safebrowsing.malware.enabled", false);
				user_pref("browser.safebrowsing.phishing.enabled", false);
				user_pref("browser.search.suggest.enabled", false); // don't send search keystrokes
				user_pref("datareporting.healthreport.uploadEnabled", false);
				user_pref("extensions.blocklist.enabled", false); // don't update blocklist
				user_pref("extensions.getAddons.cache.enabled", false);
				user_pref("extensions.update.autoUpdateDefault", false);
				user_pref("network.captive-portal-service.enabled", false); // no 'detectportal.firefox.com'
				user_pref("network.prefetch-next", false); // don't get what I haven't asked for
				user_pref("privacy.trackingprotection.pbmode.enabled", false);
				user_pref("network.dns.disablePrefetch", true);
				user_pref("browser.startup.page", 0);
				user_pref("network.http.speculative-parallel-limit", 0);
				user_pref("browser.aboutHomeSnippets.updateUrl", "");
				user_pref("browser.safebrowsing.provider.mozilla.updateURL", "");
				user_pref("browser.safebrowsing.provider.mozilla.gethashURL", "");
				user_pref("extensions.webservice.discoverURL", "");
				user_pref("browser.selfsupport.url","");
				user_pref("browser.startup.homepage_override.mstone","ignore");
			EOF
		fi
	fi

	log "Installling Kerberos. Modify '/etc/krb5.conf'. Use 'kinit' to request a ticket.";
	apt-get install -yqq krb5-user &>> "${DEBUG_LOG}";
	tee "/etc/krb5.conf" <<-'EOF' > /dev/null
		[libdefaults]
		default_realm = CONTOSO.LOCAL
		dns_lookup_realm = true
		dns_lookup_kdc = true
		
		[realms]
		CONTOSO.LOCAL = {
		kdc = DC01.CONTOSO.LOCAL
		admin_server = DC01.CONTOSO.LOCAL
		}
	EOF
	
	if [[ -f /opt/tools/responder/Responder.conf ]]; then
		log "Attempting to update the default Responder.conf settings.";
		log info "Updating to: Challenge = 1122334455667788, SMB = Off, HTTP = Off, DontRespondTo = ${PRIVATE_IP}";
		sed -i "s/Challenge *= Random/Challenge = 1122334455667788/" "/opt/tools/responder/Responder.conf";
		sed -i "s/SMB *= On/SMB = Off/g" "/opt/tools/responder/Responder.conf";
		sed -i "s/HTTP *= On/HTTP = Off/" "/opt/tools/responder/Responder.conf";
		sed -i "s/DontRespondTo *= /DontRespondTo = ${PRIVATE_IP}/" "/opt/tools/responder/Responder.conf";
	else
		log info "The configuration file '/opt/tools/responder/Responder.conf' does not exist. Skipping."
	fi
}

ript-install-wifi() {
	log "Installing WiFi assessment tools..."
	apt-get -yqq update && apt-get -yqq install wifite eaphammer airgeddon reaver;
	rm -rf /opt/tools/air-hammer && git clone https://github.com/Wh1t3Rh1n0/air-hammer.git /opt/tools/air-hammer;

	if [ "$(which go >/dev/null; echo $?)" -ne 0 ]; then
		GO_VERSION=$(curl -sL https://golang.org/VERSION\?m\=text | head -n 1)
		if [[ "${IS_ARM}" == true ]]; then 
			curl -sL https://go.dev/dl/$GO_VERSION.linux-arm64.tar.gz -o /tmp/$GO_VERSION.tar.gz && tar -C /usr/local -xzf /tmp/$GO_VERSION.tar.gz;
		else
			curl -sL https://go.dev/dl/$GO_VERSION.linux-amd64.tar.gz -o /tmp/$GO_VERSION.tar.gz && tar -C /usr/local -xzf /tmp/$GO_VERSION.tar.gz;
		fi
	fi

	go install "github.com/bettercap/bettercap@latest";
	if [[ $? -ne 0 ]]; then echo "Error installing bettercap"; fi

	# drivers - purge everything
	log info "Removing all realtek wireless drivers...";
	if [ -d '/opt/tools/rtl8812au' ]; then
		cd '/opt/tools/rtl8812au';
		make clean;
		make uninstall;
		cd -;
		rm -rf '/opt/tools/rtl8812au';
	fi
	dpkg --list | grep realtek | awk '{ print $2}' | xargs apt-get -yqq remove --purge;

	log info "Installing drivers from APT..."
	apt-get -yqq install realtek-rtl88xxau-dkms;
	log "Plug in the WiFi adapter, wait 5 seconds, and reboot the system to begin testing.";
}

log() {	
	msg=$2;
	# if the second arg is blank, use the first as the msg (cyan)
	if [ -z "${msg}" ]; then msg=$1; fi;
	color=$(case $1 in
		("info") echo -n '\033[0;33m  [i]' ;; # yellow
		("notice") echo -n '\033[0;35m' ;; # purple
		("error") echo -n '\033[0;31m[!]' ;; # red
		(*) echo -n '\033[0;36m[+]' ;; # cyan
	esac);
	clear='\033[0m'; # set color back to default
	eval 'echo -e "${color} ${msg} ${clear}"'
}

APT_PACKAGES=(
	"accountsservice"
	"at-spi2-core"
	"apt-transport-https"
	"bc"
	"build-essential"
	"bully"
	"cargo"
	"${CHROME_PKG_NAME}" 			# "chromium-browser" (Ubuntu), "chromium" (Kali/Debian)
	"chromium-driver"
	"cifs-utils"
	"colorized-logs"
	"curl"
	"default-jdk"
	"dkms"
	"dnsutils"
	"docker.io"
	"docker-cli"
	"docker-compose"
	"dos2unix"
	"dsniff"
	"editorconfig"
	"expect"
	"feroxbuster"
	"${FIREFOX_PKG_NAME}"			# "firefox" (Ubuntu), "firefox-esr" (Kali/Debian)
	"ftp"
	"freerdp2-x11"
	"git"
	"gnupg2"
	"grc"
	"grep"
	"hashcat"
	"ifmetric"
	"ike-scan"
	"iptables"
	"jq"
	"libelf-dev"
	"libffi-dev"
	"libldap2-dev"
	"libmariadb-dev"
	"libnetfilter-queue-dev"
	"libpcap-dev"
	"libsqlcipher-dev"
	"libsasl2-dev"
	"libssl-dev"
	"libusb-1.0-0-dev"
	"linux-headers-`uname -r`"
	"macchanger"
	"mimikatz"
	"mitm6"
	"nmap"
	"plocate"
	"moreutils"
	"net-tools"
	"network-manager"
	"nfs-common"
	"nmap"
	"open-vm-tools-desktop"
	"openjdk-11-jdk"
	"openvpn"
	"pipenv"
	"postgresql"
	"proxychains4"
	"python3"
	"python3-apt"
	"python3-dev"
	"python3-ldap"
	"python3-pip"
	"python3-venv"
	"redis-tools"
	"rsync"
	"rsyslog"
	"ruby-full"
	"samba"
	"smbclient"
	"sqlmap"
	"sslscan"
	"tcpdump"
	"telnet"
	"tree"
	"unzip"
	"vim"
	"wget"
	"wireguard"
	"wireless-tools"
	"wpasupplicant"
	"zip"
	"zsh" 
);

PIP_PACKAGES=(
	"ansible"
	"asn1crypto"
	"cryptography>=38.0.0"
	"cython"
	"jmespath"
	"ldapdomaindump"
	"nmaptocsv"
	"pefile" 
	"pipx"
	"pyasn1"
	"pypykatz"
	"python-libpcap"
	"sslyze>=5.0.2"
	"urllib3"
	"virtualenv"
	"wpa_supplicant"
);

GO_PACKAGES=(
	# package must be compatible with `go install <REPO>`
	"github.com/ffuf/ffuf@latest" 
	"github.com/OJ/gobuster@latest" 
	"github.com/ropnop/kerbrute@latest"
	"github.com/sensepost/gowitness@latest"
	"github.com/sensepost/ruler@latest"
);