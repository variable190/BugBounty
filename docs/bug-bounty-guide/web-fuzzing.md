# Web Fuzzing

## Installing Tools

### Prerequisits

Installing Go, Python and PIPX

```bash
sudo apt update
sudo apt install -y golang
sudo apt install -y python3 python3-pip
sudo apt install pipx
pipx ensurepath
sudo pipx ensurepath --global
```

### Tools

| Tool       | Description                        | Use Cases                          |
|------------|------------------------------------|------------------------------------|
| FFUF       | Fast Go-based web fuzzer for enumeration. | Directory/file enumeration, parameter discovery, brute-force attacks. |
| Gobuster   | Simple, fast web directory fuzzer. | Content discovery, DNS subdomain enumeration, WordPress detection. |
| FeroxBuster| Rust-based recursive content discovery tool. | Recursive scanning, unlinked content discovery, high-performance scans. |
| wfuzz/wenum| Versatile Python fuzzer for parameter testing. | Directory/file enumeration, parameter discovery, brute-force attacks. |

```bash
go install github.com/ffuf/ffuf/v2@latest
go install github.com/OJ/gobuster/v3@latest
curl -sL https://raw.githubusercontent.com/epi052/feroxbuster/main/install-nix.sh | sudo bash -s $HOME/.local/bin
pipx install git+https://github.com/WebFuzzForge/wenum
pipx runpip wenum install setuptools
```

## Fuzzing

| Command | Description |
|---------|-------------|
| `ffuf -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -u http://IP:PORT/FUZZ` | Directory fuzzing |
| `ffuf -w /usr/share/seclists/Discovery/Web-Content/common.txt -u http://IP:PORT/w2ksvrus/FUZZ -e .php,.html,.txt,.bak,.js -v` | File fuzzing |