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
Removed, parsing SPF records with bash is annoying and error prone, hence this script was buggy. Check out [mail-autoaudit's](https://github.com/tav-r/mail-autoaudit) `dns` subcommand.

## collect_js.sh
Use `https://github.com/hakluke/hakrawler` to recursively find javascript files, store them locally in a git repo and search them fore some potentially interesting regex patterns.

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
