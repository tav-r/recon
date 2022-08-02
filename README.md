# Overview
This is a random collection of different recon tools I wrote. They are all not "large enough" to deserve an own repo but I find them quite handy.

## [nmap2cherrytree.py](nmap2cherrytree.py)
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

## [redirects.sh](redirects.sh)
Use [`gau`](https://github.com/lc/gau) and [`httpx`](https://github.com/projectdiscovery/httpx) to find URLs that might be used as open redirects.

### Usage
```bash
Usage: ./redirects.sh [-s|--subs] [-h|--help] [-k|--keep-temp] [-v|--verbose] DOMAIN OUTFILE
```

## spfips.sh
Removed, parsing SPF records with bash is annoying and error prone, hence this script was buggy. Check out [mail-autoaudit's](https://github.com/tav-r/mail-autoaudit) `dns` subcommand.

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

## [schall_und_rauch.py](schall_und_rauch.py)
The script can be used to find domain names using various techniques:
- reverse ip lookup
- SNI extraction
- recursive CNAME resolution

it also can unfold cidr ranges, which is handy when using the tool. Some examples:
```bash
$ echo -n 140.82.121.0/24 | python3 names.py cidr | python3 names.py sni
{
    "140.82.121.10": [
        "*.github.com"
    ],
    "140.82.121.12": [
        "*.github.com"
    ],
    "140.82.121.14": [
        "*.githubusercontent.com"
    ],
    "140.82.121.3": [
        "github.com"
    ],
    "140.82.121.9": [
        "*.github.com"
    ],

  <snip>

}
$ echo -n 140.82.121.0/24 | python3 names.py cidr | python3 names.py reverse
{
    "140.82.121.34": [
        "lb-140-82-121-34-fra.github.com."
    ],
    "140.82.121.36": [
        "lb-140-82-121-36-fra.github.com."
    ],
    "140.82.121.3": [
        "lb-140-82-121-3-fra.github.com."
    ],
    "140.82.121.11": [
        "lb-140-82-121-11-fra.github.com."
    ],
    "140.82.121.14": [
        "lb-140-82-121-14-fra.github.com."
    ],
    "140.82.121.12": [
        "lb-140-82-121-12-fra.github.com."
    ],
    "140.82.121.1": [
        "lb-140-82-121-1-fra.github.com."
    ],
    "140.82.121.19": [
        "lb-140-82-121-19-fra.github.com."
    ],
    "140.82.121.35": [
        "lb-140-82-121-35-fra.github.com."
    ],

    <snip>
    
}
$ subfinder -silent -d tesla.com | python3 names.py cnames | head -n 100
{
    "url4104.tesla.com": [
        "sendgrid.net."
    ],
    "origin-finplat-stg.tesla.com": [
        "clsfins.tesla.com.akadns.net."
    ],
    "wdm.kronos.tesla.com": [
        "kronos-wdm-nlb-0558dc9e908f5182.elb.us-west-2.amazonaws.com."
    ],
    "akamai-apigateway-teslaservice-api.tesla.com": [
        "akamai-apigateway-teslaservice-api.tesla.com.edgekey.net.",
        "e1792.dscx.akamaiedge.net."
    ],
    "url5347.tesla.com": [
        "sendgrid.net."
    ],
    "zta-setup.tesla.com": [
        "eaa-teslazero-cn-rdp.teslamotors.com.srip.net.",
        "srip1555.globalredir.akadns.net.",
        "a1555.srip1.akasrip.net.73c1340d.1.cn.akasripcn.net."
    ],
    "solarbonds.tesla.com": [
        "solarbonds.tesla.com.edgekey.net.",
        "e1792.dscx.akamaiedge.net."
    ],
    "origin-edr.tesla.com": [
        "clsgenp.tesla.com.akadns.net."
    ],
    "akamai-apigateway-prd-global-deliveryopsapi.tesla.com": [
        "akamai-apigateway-deliveryopsapi.tesla.com.edgekey.net.",
        "e1792.dscx.akamaiedge.net."
    ],
    "akamai-apigateway-vendorpartsapi.tesla.com": [
        "akamai-apigateway-vendorpartsapi.tesla.com.edgekey.net.",
        "e1792.dscx.akamaiedge.net."
    ],
 
    <snip>

```