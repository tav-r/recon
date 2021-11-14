# Recon notes
## Domain recon modus operandi
1. Run [amass](https://github.com/OWASP/Amass)
```bash
amass enum -d DOMAIN -oA path/to/outfile
```
2. Get interesting CIDR ranges from `path/to/outfile` (I use `jq` for this):
```bash
jq '.addresses|values[]|[.cidr,.desc]' path/to/outfile.json  # list descriptions
jq '.addresses|values[]|select(.desc | contains("INTERESTING"))|.cidr' path/to/outfile.json | sort -u | tr -d '"' | tee path/to/cidrs.txt
```
3. Reverse lookup CIDR ranges:
```bash
python3 reverse_range.py -t 20 < path/to/cidrs.txt | tee path/to/reverse_lookup.json
```
4. Select interesting domains from reverse lookup:
```bash
jq 'values[][0]' path/to/reverse_lookup.json | tr '[:upper:]' '[:lower:]' | tr -d '"' | tee path/to/reverse_domains.txt
```
5. Combine lists
```bash
sort -u path/to/reverse_domains.txt path/to/outfile.txt > path/to/all_domains.txt
```
