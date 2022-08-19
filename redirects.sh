#!/bin/bash

###### GLOBALS ######
SUBS=false
KEEP_TEMP=false
POSITIONAL=()
REGEX='[\?,&][^&\?]+=(http|/|%2f|%2F)'
SCRIPTNAME=$0
VERBOSE=false
#####################

function print_usage {
    echo "Usage: $SCRIPTNAME [-s|--subs] [-h|--help] [-k|--keep-temp] [-v|--verbose] DOMAIN"
}

function run_gau {
    SUBS=$1  # boolean, search subdomains too

    if [ $SUBS = true ]; then
        CMD="gau --subs $DOMAIN"
    else
        CMD="gau $DOMAIN"
    fi

    eval $CMD
}

function run_waybackurls {
    SUBS=$1  # boolean, search subdomains too

    if [ $SUBS = true ]; then
        CMD="waybackurls $DOMAIN"
    else
        CMD="waybackurls --no-subs $DOMAIN"
    fi

    eval $CMD
}

function main {
    DOMAIN=$1  # string, domain to search

    TMPFILE=$(mktemp)

    UNWANTED_STATUS='(404|403)' 

    $VERBOSE && echo "[*] gathering URLs" >&2

    run_gau $SUBS | sort -u > $TMPFILE
    run_waybackurls $SUBS | sort -u >> $TMPFILE

    $VERBOSE && echo "[*] probing URLs, writing to $OUTFILE" >&2

    cat $TMPFILE | egrep "$REGEX" | httpx -silent -probe -status-code \
        | egrep '.+ .*SUCCESS' | egrep -v ".+ .*$UNWANTED_STATUS" \
        | cut -d' ' -f1

    $KEEP_TEMP && $VERBOSE && echo "[*] Leaving temporary file at '$TMPFILE'" >&2
    $KEEP_TEMP || rm $TMPFILE
}

# Parse options
while [ -n "$1" ]; do
    case "$1" in
        -s|--subs)
            SUBS=true
            shift
        ;;

        -v|--verbose)
            VERBOSE=true
            shift
        ;;

        -k|--keep-temp)
            KEEP_TEMP=true
            shift
        ;;

        -h|--help)
            print_usage
            exit
        ;;

        *)
            POSITIONAL+=("$1")
            shift
        ;;
    esac
done

if (( ${#POSITIONAL[@]} != 1 )); then
    print_usage
    exit 1
elif [ -z $(which gau) ]; then
    echo "'gau' is missing"
    exit 1
elif [ -z $(which waybackurls) ]; then
    echo "'waybackurls' is missing"
    exit 1

elif [ -z $(which httpx) ]; then
    echo "'httpx' is missing"
    exit 1
fi

main "${POSITIONAL[0]}" $VERBOSE

