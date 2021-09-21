# Overview
This is a random collection of different recon tools I wrote. They are all not "large enough" to deserve an own repo but I find them quite handy.

## nmap2cherrytree.py
Convert XMLs from `nmap` scans into [cherrytree](https://www.giuspen.com/cherrytree/) files.
### Installation
```bash
python3 -m venv .
source bin/activate
pip install -r requirements.txt
```
### Usage
```
nmap -oX scan scanme.com
python3 nmap2cherrytree.py scan.xml > scan.ctd
```
Then open `scan.ctd` in cherrytree

## redirects.sh
Use [`gau`](https://github.com/lc/gau) and [`httpx`](https://github.com/projectdiscovery/httpx) to find URLs that might be used as open redirects.

### Usage
```bash
Usage: ./redirects.sh [-s|--subs] [-h|--help] [-k|--keep-temp] [-v|--verbose] DOMAIN OUTFILE
```

## spfips.sh
Recursively enumerate all IPs that are allowed to send emails for a certain domain according to the SPF record. Useful to enumerate mailservers or to check your own configuration.

### Usage
```bash
$ ./spfips.sh google.com
google.com:
_spf.google.com:
_netblocks.google.com:
        35.190.247.0/24
        64.233.160.0/19
        66.102.0.0/20
        66.249.80.0/20
        72.14.192.0/18
        74.125.0.0/16
        108.177.8.0/21
        173.194.0.0/16
        209.85.128.0/17
        216.58.192.0/19
        216.239.32.0/19
_netblocks2.google.com:
        2001:4860:4000::/36
        2404:6800:4000::/36
        2607:f8b0:4000::/36
        2800:3f0:4000::/36
        2a00:1450:4000::/36
        2c0f:fb50:4000::/36
_netblocks3.google.com:
        172.217.0.0/19
        172.217.32.0/20
        172.217.128.0/19
        172.217.160.0/20
        172.217.192.0/19
        172.253.56.0/21
        172.253.112.0/20
        108.177.96.0/19
        35.191.0.0/16
        130.211.0.0/22
```

## URL sieve
Filter URLs that only differ in queries while collecting all queries. Example:
```
$ echo "http://google.com/?q=test
  http://google.com/?r=something
  https://example.com/
  http://google.com/?q=something&r=or&s=else" | python3 url_sieve.py
http://google.com/?q=test&r=something&s=else
https://example.com/
```

I find this to be useful when collecting URLs with [gau](https://github.com/lc/gau) or [hakrawler](https://github.com/hakluke/hakrawler)