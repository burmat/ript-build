#!/bin/bash

SCRIPT_VERSION="v1.0"

# ## ---- Global Variables ---- ## #
LOG_FILE="/root/ript-build.log";
START_TIME=$(date "+%Y-%m-%d %H:%M:%S");
OS="DEBIAN";
CHROME_PKG_NAME="chromium"; 			# may be diff depending on OS
FIREFOX_PKG_NAME="firefox-esr";			# may be diff depending on OS
LINUX_FIRMWARE_PKG_NAME="linux-headers" # may be diff depending on OS
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/go/bin:/root/go/bin:$HOME/.local/bin:$HOME/go/bin:$HOME/.cargo/bin;
DEBIAN_FRONTEND=noninteractive;
NEEDRESTART_MODE=a;
DEBIAN_PRIORITY=critical;
RED="\033[0;31m";
YELLOW="\033[0;33m";
PURPLE="\033[0;35m";
CYAN="\033[0;36m";
C="\033[0m";

main() {

	if [ "${EUID}" -ne 0 ]; then
		echo -e "${RED}[!] The included commands must be run as root. ${C}";
		echo -e "${YELLOW}[i] Elevate your shell with: \033[1;31msudo su - ${C}";
		exit 1;
	else
		cd /root && mkdir -p /opt/tools;
	fi

	if [[ $(grep -i "KALI" /etc/os-release &> /dev/null; echo $?;) -ne "0" ]]; then
		echo -e "${RED}[!] Your OS is not currently supported, my apologies. Please use Kali (for now). ${C}";
		exit 1;
	else
		OS="KALI";
		LINUX_FIRMWARE_PKG_NAME="kali-linux-firmware"
		apt-get -yqq update && apt-get install -yqq kali-root-login;
		touch "/root/.hushlogin";
	fi

	## log all output
	exec &> >(tee -i $LOG_FILE);
	echo "${START_TIME}" > date-executed.txt
	echo -e "${CYAN}[+] ${START_TIME} - Executing ript-build.sh script (${SCRIPT_VERSION}) - hold on tight... ${C}";
	echo -e "${YELLOW}[i] Script output will be in ${LOG_FILE} ${C}";
	echo -e "${YELLOW}[i] Host IP address:${PURPLE} $(hostname -I | cut -d ' ' -f 1) ${C}";

	prebuild_tasks;
	install_xfce;
	install_tools;
	install_ohmyzsh;
	configure_tmux;
	configure_services;

	echo -e "\n\n${CYAN}[+] All of this output has been saved to 'ript-build.log' for the output. ${C}";
	echo -e "\n\n${YELLOW}[i] If any errors are detected in the log file, they will print here: ${C}";
	grep "\[\!\]" ${LOG_FILE}
	echo -e "\n\n${YELLOW}[i] Script execution completed! You should probably reboot at this point. ${C}";
}

prebuild_tasks() {

	echo "APT::Install-Recommends \"0\";" > /etc/apt/apt.conf;
	echo "APT::Install-Suggests \"0\";" >> /etc/apt/apt.conf;

	if [[ -f /etc/needrestart/needrestart.conf ]]; then
		sed -i 's/#$nrconf{kernelhints} = -1;/$nrconf{kernelhints} = 0;/' /etc/needrestart/needrestart.conf;
	fi

	apt-get -yqq update --fix-missing
	if [[ $? -ne 0 ]]; then
		echo -e "${RED}[!] There was an error while using APT, so we are going to exit just to be safe. ${C}";
		echo -e "${YELLOW}[i] Is your network connection working? DNS (It's always DNS)? ${C}";
		exit 1;
	fi

	echo -e "${CYAN}[+] Installing 'debconf-utils' to bypass the interactive prompts.. ${C}";
	apt-get -yqq install debconf-utils;
	echo "keyboard-configuration	keyboard-configuration/variant	select	English (US)" | debconf-set-selections &> /dev/null;
	echo "krb5-config	krb5-config/default_realm	string	CONTOSO.LOCAL" | debconf-set-selections &> /dev/null;
	echo "krb5-config	krb5-config/kerberos_servers	string	" | debconf-set-selections &> /dev/null;
	echo "krb5-config	krb5-config/read_conf	boolean	true" | debconf-set-selections &> /dev/null;
	echo "krb5-config	krb5-config/add_servers_realm	string	CONTOSO.LOCAL" | debconf-set-selections &> /dev/null;
	echo "krb5-config	krb5-config/add_servers	boolean	true" | debconf-set-selections &> /dev/null;
	echo "krb5-config	krb5-config/admin_server	string	" | debconf-set-selections &> /dev/null;
	echo "libc6	glibc/restart-services	string	" | debconf-set-selections &> /dev/null;
	echo "libc6:amd64	glibc/restart-services	string	" | debconf-set-selections &> /dev/null;
	echo "libc6	glibc/restart-failed	error	" | debconf-set-selections &> /dev/null;
	echo "libc6:amd64	glibc/restart-failed	error	" | debconf-set-selections &> /dev/null;
	echo "libc6	glibc/disable-screensaver	error	" | debconf-set-selections &> /dev/null;
	echo "libc6:amd64	glibc/disable-screensaver	error	" | debconf-set-selections &> /dev/null;
	echo "libc6	glibc/kernel-not-supported	note	" | debconf-set-selections &> /dev/null;
	echo "libc6:amd64	glibc/kernel-not-supported	note	" | debconf-set-selections &> /dev/null;
	echo "libc6	glibc/kernel-too-old	error	" | debconf-set-selections &> /dev/null;
	echo "libc6:amd64	glibc/kernel-too-old	error	" | debconf-set-selections &> /dev/null;
	echo "libc6	libraries/restart-without-asking	boolean	true" | debconf-set-selections &> /dev/null;
	echo "libc6:amd64	libraries/restart-without-asking	boolean	true" | debconf-set-selections &> /dev/null;
	echo "libc6	glibc/upgrade	boolean	true" | debconf-set-selections &> /dev/null;
	echo "libc6:amd64	glibc/upgrade	boolean	true" | debconf-set-selections &> /dev/null;

	echo -e "${CYAN}[+] Performing an upgrade.. ${C}";
	apt-get -yqq full-upgrade && apt-get -yqq autoremove && apt-get -yqq autoclean;

	echo -e "${CYAN}[+] Installing and enabling SSH... ${C}";
	apt-get install -yqq openssh-server && systemctl enable ssh;
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
		echo -e "${RED}[!] Error installing/enabling SSH. Exiting due to probable underlying issues. ${C}";
		exit 1;
	fi

	echo -e "${CYAN}[+] Disabling password requirements for all users when using 'sudo'... ${C}";
	for u in $(ls /home); do
		apt-get install -yqq sudo && echo "${u} ALL=(ALL) NOPASSWD: ALL" | tee "/etc/sudoers.d/${u}" > /dev/null;
		echo -e "${YELLOW}[i] \"${u}\" is now a privileged user.${C}";
	done
}

install_xfce() {

	echo -e "${CYAN}[+] Attempting to install desktop environment requirements... ${C}";
	apt-get install -yqq xserver-xorg xserver-xorg-core xfonts-base xinit x11-xserver-utils;
	if [[ $? -ne 0 ]]; then
		echo -e "${RED}[!] Error installing graphics packages. ${C}";
	fi

	echo -e "${CYAN}[+] Attempting to install a minimal xfce4 desktop environment... ${C}";
	apt-get install -yqq xfce4 xfce4-terminal xfce4-taskmanager xfce4-appfinder lightdm;
	if [[ $? -ne 0 ]]; then
		echo -e "${RED}[!] Error installing desktop environment. ${C}";
	fi

	# initialize lightdm
	mkdir -p /usr/sbin/lightdm && echo "/usr/sbin/lightdm" > /etc/X11/default-display-manager;
	mkdir -p '/usr/share/backgrounds/xfce';
	echo -n "R0lGODlhAQABAIAAAAUEBAAAACwAAAAAAQABAAACAkQBADs=" | base64 -d > '/usr/share/backgrounds/desktop_background.png';
	echo -n "R0lGODlhAQABAIAAAAUEBAAAACwAAAAAAQABAAACAkQBADs=" | base64 -d > '/usr/share/backgrounds/user_background.png';
	echo -n "R0lGODlhAQABAIAAAAUEBAAAACwAAAAAAQABAAACAkQBADs=" | base64 -d > '/usr/share/backgrounds/xfce/xfce-verticals.png';

	tee "/etc/lightdm/lightdm-gtk-greeter.conf" <<-'EOF' > /dev/null
		[greeter]
		background=/usr/share/backgrounds/desktop_background.png
		default-user-image=/usr/share/backgrounds/user_background.png
	EOF

	tee "/etc/lightdm/lightdm.conf" <<-'EOF' > /dev/null
		[LightDM]
		logind-check-graphical=true

		[Seat:*]

		[XDMCPServer]

		[VNCServer]
	EOF

}

install_tools() {

	# install APT packages
	echo -e "${CYAN}[+] Installing packages we will need...${C}";
	apt-get --allow-releaseinfo-change update -yqq --fix-missing;
	for p in ${APT_PACKAGES[@]}; do
		apt-get install -yqq $p;
		if [[ $? != 0 ]]; then
			echo -e "${RED}[!] Error attempting to install package ${p} ${C}";
		fi
	done

	apt-get -yqq update && apt-get -yqq full-upgrade && apt-get -yqq autoremove && apt-get -yqq autoclean;

	echo -e "${CYAN}[+] Ensuring that pip is upgraded... ${C}";
	python3 -m pip install --upgrade pip --break-system-packages;

	# install pip packages:
	echo -e "${CYAN}[+] Installing Python3 Pip tools...${C}";
	for p in ${PIP_PACKAGES[@]}; do
		echo -e "${CYAN}[+] Installing package ${p} ${C}";
		python3 -m pip install $p --break-system-packages;
		if [ $? -ne 0 ]; then
			echo -e "${RED}[!] Error attempting to install Pip package ${p} ${C}";
		fi
	done
	
	echo -e "${CYAN}[+] Installing hax0r tools... ${C}";
	echo -e "${YELLOW}[i] Check \"/opt/tools/\" for tools not in your \$PATH ${C}";

	# github tools
	echo -e "${CYAN}[+] Cloning Tools GitHub tools. You may have to run installations yourself! ${C}";
	echo -e "${YELLOW}[i] Tools can be found in the \"/opt/tools/\" directory. Pay attention to 'requirements.txt' files in there. ${C}";
	git config --global https.postBuffer 157286400 && git config --global http.postBuffer 157286400;
	rm -rf /opt/tools/BloodHound.py && git clone https://github.com/fox-it/BloodHound.py.git /opt/tools/BloodHound.py;
	rm -rf /opt/tools/EAP_buster && git clone https://github.com/blackarrowsec/EAP_buster.git /opt/tools/EAP_buster;
	rm -rf /opt/tools/eaphammer && git clone https://github.com/s0lst1c3/eaphammer.git /opt/tools/eaphammer;
	rm -rf /opt/tools/enum4linux-ng && git clone https://github.com/cddmp/enum4linux-ng.git /opt/tools/enum4linux-ng;
	rm -rf /opt/tools/EyeWitness && git clone https://github.com/ChrisTruncer/EyeWitness /opt/tools/EyeWitness;
	rm -rf /opt/tools/mitm6 && git clone https://github.com/dirkjanm/mitm6.git /opt/tools/mitm6;
	rm -rf /opt/tools/pcredz && git clone https://github.com/lgandx/PCredz.git /opt/tools/pcredz;
	rm -rf /opt/tools/petitpotam && git clone https://github.com/topotam/PetitPotam.git /opt/tools/petitpotam;
	rm -rf /opt/tools/responder && git clone https://github.com/lgandx/Responder.git /opt/tools/responder;
	rm -rf /opt/tools/rubeus2ccache && git clone https://github.com/curi0usJack/rubeus2ccache.git /opt/tools/rubeus2ccache;
	rm -rf /opt/tools/windapsearch && git clone https://github.com/ropnop/windapsearch.git /opt/tools/windapsearch;
	rm -rf /opt/tools/ldaprelayscan && git clone https://github.com/zyn3rgy/LdapRelayScan.git /opt/tools/ldaprelayscan;
	git config --global --unset https.postBuffer && git config --global --unset http.postBuffer;

	# metasploit framework install. write the settings file
	if [ ! -f /usr/bin/msfconsole ]; then
		echo -e "${CYAN}[+] Installing Metasploit...${C}";
		if [[ $OS == "KALI" ]]; then
			apt-get -yqq install metasploit-framework && msfdb init;
		else
			curl -s https://raw.githubusercontent.com/rapid7/metasploit-omnibus/master/config/templates/metasploit-framework-wrappers/msfupdate.erb > msfinstall && chmod 755 msfinstall && ./msfinstall;
			echo -e "${CYAN}[+] Forcing Metasploit to update...${C}";
			apt-get update -yqq && apt-get install -yqq metasploit-framework;
			echo -e "${YELLOW}[i] Attempting to initialize the database.${C}";
			echo "no" > no && echo "yes" > yes; sudo su -c "msfdb init" postgres < no < yes; rm -rf no yes;
			echo -e "";
			echo -e "${YELLOW}[i] That should have worked  ${C}";
		fi
		mkdir -p /root/.msf4 && mkdir -p /root/logs/msf;
		tee "/root/.msf4/msfconsole.rc" <<-'EOF' > /dev/null
			set PROMPT %bld%red%T %whi%L %blu"s:"%S "j:"%J%clr
			echo "${CYAN}[**] Collect logs by running: ${PURPLE}spool /root/logs/msf/<filename> ${C}\n\n"
		EOF
	fi

	# crackmapexec installation
	if [ "$(which crackmapexec >/dev/null; echo $?)" -ne 0 ]; then
		echo -e "${CYAN}[+] Installing crackmapexec... ${C}";
		rm -rf /opt/tools/crackmapexec && git clone https://github.com/Porchetta-Industries/CrackMapExec.git /opt/tools/crackmapexec;
		curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y; # install Rust using the rustup script
		python3 -m pip install /opt/tools/crackmapexec/. --break-system-packages;
	else
		echo -e "${CYAN}[+] crackmapexec is already installed - skipping installation via this script.${C}";
		echo -e "${CYAN}[+] review the source code on line ~255 to get the installation commands, or re-run this script after you remove it.${C}";
	fi

	# mitm6 installation
	if [ -d "/opt/tools/mitm6" ]; then
		cd /opt/tools/mitm6;
		python3 -m pip install -r requirements.txt --break-system-packages;
		python3 setup.py install;
		cd;
	fi

	# eyewitness
	if [ -d "/opt/tools/EyeWitness" ]; then
		sed -i 's/clear/#clear/' /opt/tools/EyeWitness/Python/setup/setup.sh;
		/bin/bash /opt/tools/EyeWitness/Python/setup/setup.sh;
	fi

	# impacket
	echo -e "${CYAN}[+] Installing fresh copy of Impacket... ${C}";
	apt-get -yqq remove python3-impacket;
	rm -rf /opt/tools/impacket && git clone https://github.com/CoreSecurity/impacket.git /opt/tools/impacket;
	python3 -m pip install /opt/tools/impacket/. --break-system-packages;

	# evilwinrm
	echo -e "${CYAN}[+] Installing evil-winrm... ${C}";
	gem install evil-winrm;

	# golang tools
	echo -e "${CYAN}[+] Installing Go...${C}";
	curl -s https://dl.google.com/go/go1.19.10.linux-amd64.tar.gz -o /tmp/go1.19.10.tar.gz && tar -C /usr/local -xzf /tmp/go1.19.10.tar.gz;
	if [ "$(which go >/dev/null; echo $?)" -ne 0 ]; then
		echo -e "${RED}[!] Error installing Go - Check the \$PATH variable to ensure /usr/local/go/bin is included... ${C}";
		echo -e "${YELLOW}[i] Current \$PATH value: ${PATH} ${C}";
	else
		echo -e "${CYAN}[+] Installing Go tools and packages... ${C}";
		for p in ${GO_PACKAGES[@]}; do
			go install $p;
			if [[ $? -ne 0 ]]; then
				echo -e "${RED}[!] Error attempting to install Go package ${p} ${C}";
			fi
		done
	fi

	echo -e "${CYAN}[+] Manually extracting releases of the older/archived Go packages... ${C}";
	wget -qO /tmp/go-GoMapEnum.tar.gz https://github.com/nodauf/GoMapEnum/releases/download/v1.1.0/GoMapEnum_1.1.0_linux_amd64.tar.gz && tar -xzf /tmp/go-GoMapEnum.tar.gz -C /usr/local/bin;
	wget -qO /tmp/go-aquatone.zip https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_linux_amd64_1.7.0.zip && unzip -o /tmp/go-aquatone.zip -d /usr/local/bin;

	# cleanup dl'ed packages
	rm -rf /tmp/go-*;
}

install_ohmyzsh() {
	echo -e "${CYAN}[+] Installing oh-my-zsh... ${C}";
	usermod --shell /bin/zsh root;
	rm -rf /root/.oh-my-zsh;
	rm -rf /root/.zshrc.pre-oh-my-zsh-*;
	RUNZSH='no' /bin/sh -c "$(curl -fsSL https://raw.githubusercontent.com/robbyrussell/oh-my-zsh/master/tools/install.sh)";
	chsh -s $(which zsh);
	echo -e "${CYAN}[+] Incorporating custom config and theme file... ${C}";
	tee /root/.zshrc <<-'EOF' > /dev/null
		export ZSH="$HOME/.oh-my-zsh"
		ZSH_THEME="default"
		plugins=(git)
		source $ZSH/oh-my-zsh.sh
		export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/usr/local/go/bin:$HOME/.local/bin:$HOME/go/bin
	EOF

	tee /root/.oh-my-zsh/themes/default.zsh-theme  <<-'EOF' > /dev/null
		if [ "$EUID" -eq 0 ]; then 
			SYMBOL="#";
		else
			SYMBOL="\$"
			echo -e "\n\n\033[1;32m[>] You are: $(whoami) ${C}"
			echo -e "\033[1;34m[+] Please use the root account - elevate your shell with: \033[1;33msudo su - ${C}"
		fi
		PROMPT='%{$fg_bold[red]%}%D %T %{$reset_color%}%{$fg_bold[white]%}$(hostname -I | cut -d " " -f 1) %{$reset_color%}%{$fg_bold[blue]%}%1~%{$reset_color%} ${SYMBOL} '
		export LSCOLORS="exfxcxdxbxegedabagacad"
		export LS_COLORS='di=34;40:ln=35;40:so=32;40:pi=33;40:ex=31;40:bd=34;46:cd=34;43:su=0;41:sg=0;46:tw=0;42:ow=0;43:'
	EOF

	for u in $(ls /home); do
		echo -e "${CYAN}[+] Installing oh-my-zsh for the low-priv user ${u}... ${C}";
		su - -c "rm -rf ~/.oh-my-zsh" ${u};
		su - -c "curl -s https://raw.githubusercontent.com/robbyrussell/oh-my-zsh/master/tools/install.sh | /bin/bash" ${u};
 		cp "/root/.oh-my-zsh/themes/default.zsh-theme" "/home/${u}/.oh-my-zsh/themes/default.zsh-theme";
		cp "/root/.zshrc" "/home/${u}/.zshrc";		
		touch "/home/${u}/.hushlogin";
		chown -hR ${u}:${u} "/home/${u}/."
		usermod --shell /bin/zsh ${u};
	done
}

configure_tmux() {

	# install latest from source
	echo -e "${CYAN}[+] Installing latest Tmux from source... ${C}";
	apt-get -yqq remove tmux;
	apt-get -yqq install libevent-dev ncurses-dev build-essential bison pkg-config automake;
	git clone https://github.com/tmux/tmux.git /tmp/latest_tmux && cd /tmp/latest_tmux;
	sh autogen.sh && ./configure && make && sudo make install;
	cd /root/;
	
	echo -e "${CYAN}[+] Initializing Tmux configuration... ${C}";
	mkdir -p /root/logs/tmux;
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

	echo -e "${CYAN}[+] Installing the Tmux Plugin Manager (TPM)... ${C}";
	rm -rf /root/.tmux/plugins/tpm && git clone https://github.com/tmux-plugins/tpm.git /root/.tmux/plugins/tpm;
	/bin/bash /root/.tmux/plugins/tpm/scripts/install_plugins.sh;
	sed -i 's/default_logging_path="$HOME"/default_logging_path="\/root\/logs\/tmux"/' /root/.tmux/plugins/tmux-logging/scripts/variables.sh;
	tmux new-session -d; # initialize tmux
	tmux source-file /root/.tmux.conf;
	gem install tmuxinator;
	mkdir -p /root/.config/tmuxinator;
	tee /root/.config/tmuxinator/default.yml <<-'EOF' > /dev/null
		name: default
		root: ~/
		windows:
		    - main: tmux source /root/.tmux.conf
		    - msf: msfconsole
	EOF
}

configure_services() {

	# enable/start openvpn and postgresql. disable sleep and hibernate settings. enable wpa_supplicant
	/etc/init.d/postgresql start && update-rc.d postgresql enable && echo -e "${YELLOW}[i] PostgreSQL service is enabled at boot. ${C}";
	systemctl mask sleep.target suspend.target hibernate.target hybrid-sleep.target && echo -e "${YELLOW}[i] Sleep and hiberation settings disabled. ${C}";
	systemctl start wpa_supplicant && systemctl enable wpa_supplicant && echo -e "${YELLOW}[i] wpa_supplicant is up and running. ${C}";
	systemctl stop samba && systemctl disable samba && echo -e "${YELLOW}[i] samba is installed but stopped/disabled by default. ${C}";

	# setting up firefox
	if [[ -d /root/.mozilla/firefox ]]; then
		echo -e "${CYAN}[+] Launching and terminating Firefox to generate a user profile... ${C}"; 
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

	# kerberos client with dummy data
	apt-get install -yqq krb5-user;
	if [[ -f /etc/krb5.conf ]]; then
		echo -e "${YELLOW}[i] Modify '/etc/krb5.conf' for your domain and use 'kinit' to request a ticket! ${C}";
		mv /etc/krb5.conf /etc/krb5.conf.bak
		tee "/etc/krb5.conf" <<-'EOF' > /dev/null
			[libdefaults]
			default_realm = CONTOSO.LOCAL
			dns_lookup_realm = true
			dns_lookup_kdc = true
			[libdefaults]
			default_realm = CONTOSO.LOCAL
			[realms]
			CONTOSO.LOCAL = {
			kdc = DC01.CONTOSO.LOCAL
			admin_server = DC01.CONTOSO.LOCAL
			}
		EOF
	fi
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
	"dsniff"
	"editorconfig"
	"expect"
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
	"libnetfilter-queue-dev"
	"libpcap-dev"
	"libsqlcipher-dev"
	"libssl-dev"
	"libusb-1.0-0-dev"
	"linux-headers-`uname -r`"
	"macchanger"
	"mimikatz"
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
	"powershell"
	"proxychains"
	"python3"
	"python3-apt"
	"python3-dev"
	"python3-ldap"
	"python3-pip"
	"python3-venv"
	"reaver"
	"redis-tools"
	"rsync"
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
	"wireless-tools"
	"wpasupplicant"
	"zip"
	"zsh" 
);

PIP_PACKAGES=(
	"ansible"
	"asn1crypto"
	"certipy-ad"
	"coercer"
	"cryptography>=38.0.0"
	"cython"
	"ldapdomaindump"
	"nmaptocsv"
	"pefile" 
	"pipx"
	"pyasn1"
	"pypykatz"
	"python-ldap"
	"python-libpcap"
	"sslyze>=5.0.2"
	"urllib3"
	"virtualenv"
	"wpa_supplicant"
);

GO_PACKAGES=(
	# package must be compatible with `go install <REPO>`
	"github.com/bettercap/bettercap@latest" 
	"github.com/ffuf/ffuf@latest" 
	"github.com/OJ/gobuster@latest" 
	"github.com/ropnop/kerbrute@latest"
	"github.com/sensepost/gowitness@latest"
);

main;
exit 0;
