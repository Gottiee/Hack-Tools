# Exegol

## Install exegol

[Installation https](https://exegol.readthedocs.io/en/latest/getting-started/install.html)

```sh
curl -fsSL "https://get.docker.com/" | sh
sudo usermod -aG docker $(id -u -n)
newgrp docker

# REBOOT for add user in user groups
sudo apt update && sudo apt install pipx
sudo apt upgrade
pipx install exegol
pipx ensurepath
exegol install
# Choose Full for image
```

## Cmd

```sh
# START 
exegol start $containerName full -w $shareFolderPath --update-fd
```