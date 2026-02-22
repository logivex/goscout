# goscout

fast and clean network reconnaissance tool for bug bounty.

## features

- SYN port scanning
- banner grabbing with CVE link
- reverse DNS lookup
- pipeline friendly

## usage

```bash
# direct
goscout -t example.com --top 1000 --banner --rdns

# pipeline
subfinder -d example.com | goscout --banner -o json

# file
goscout -t targets.txt --top 1000
```

## flags

| flag | default | description |
|------|---------|-------------|
| `-t` | — | target: IP, domain, CIDR, file |
| `--top` | 1000 | top N ports |
| `-p` | — | specific ports: 80,443 |
| `--full` | false | all 65535 ports |
| `--rate` | 500 | packets per second |
| `--timeout` | 800ms | per port timeout |
| `--banner` | false | grab banners |
| `--rdns` | false | reverse DNS |
| `--no-syn` | false | use connect scan instead of SYN |
| `-o` | human | output format: human, json, csv |
| `-f` | — | save output to file |
| `-s` | false | silent mode |
| `-v` | false | verbose |
| `--debug` | false | debug mode |

## requirements

- Linux
- root/sudo for SYN scan

## exit codes

| code | meaning |
|------|---------|
| 0 | open ports found |
| 1 | no open ports |
| 2 | input error |
| 3 | permission error |
| 4 | network error |
