# RIPT-BUILD
---
## To build a basic assessment system. 
Tested with a "NetInstaller" image of Kali with none of the optional software selected for installation. 

## Execution
- Copy the `ript-build.sh` script to the `/root/` directory
- Load it with `source ript-build.sh`
- Execute by running the command `ript-build` to execute everything. 

Alternatively, you can execute only the things you care about by using the following commands:
- `ript-build`: Execute everything
- `ript-configure-services`: Basic setup of some of the services/apps installed.
- `ript-install-desktop`: Install a basic xfce desktop environment.
- `ript-install-tailscale`: Install Tailscale
- `ript-install-tools`: Download and install a toolbox
- `ript-install-wifi`: Install wifi drivers for wireless assessments
- `ript-prebuild`: Pre-setup stuff
- `ript-tmux-setup`: Configure Tmux 
- `ript-venv-setup`: Iterate cloned tools and auto-create a venv in the directory
- `ript-zsh-setup`: Download, install, and configure zsh