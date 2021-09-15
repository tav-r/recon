#!/bin/bash

###### GLOBALS ######
SUBS=false
KEEP_TEMP=false
POSITIONAL=()
REGEX='[?,&](back|go|goto|goback|return|returnto|return_to|returnurl|returnuri|return_url|return_path|redi|redirect|redirect_url|redirect_uri|r_url|rurl|locationurl|locationuri|next|dest|destination|checkout_url|continue|url)='
SCRIPTNAME=$0
VERBOSE=false
#####################

function print_usage {
    echo "Usage: $SCRIPTNAME [-s|--subs] [-h|--help] [-k|--keep-temp] [-v|--verbose] DOMAIN OUTFILE"
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

function main {
    DOMAIN=$1  # string, domain to search
    OUTFILE=$2  # string, file to write result to

    TMPFILE="/tmp/$DOMAIN.gau.tmp"

    UNWANTED_STATUS='(404|403)' 

    $VERBOSE && echo "[*] gathering URLs"

    run_gau $SUBS | sort -u > $TMPFILE

    $VERBOSE && echo "[*] probing URLs, writing to $OUTFILE"

    cat $TMPFILE | egrep "$REGEX" | httpx -silent -probe -status-code \
        | egrep '.+ .*SUCCESS' | egrep -v ".+ .*$UNWANTED_STATUS" \
        | cut -d' ' -f1 > $OUTFILE

    if [ $KEEP_TEMP = true ]; then
        $VERBOSE && echo "[*] Leaving temporary file at '$TMPFILE'"
    else
        rm $TMPFILE
    fi
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

if (( ${#POSITIONAL[@]} != 2 )); then
    print_usage
    exit 1
elif [ -z $(which gau) ]; then
    echo "'gau' is missing"
    exit 1
elif [ -z $(which httpx) ]; then
    echo "'httpx' is missing"
    exit 1
fi

main "${POSITIONAL[0]}" "${POSITIONAL[1]}" $VERBOSE

