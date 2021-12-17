#!/bin/bash

URL=$1
PATTERN="(eval\(\w+\)|location\.replace\(\w+\)|\"returnurl\"|\"return_url\"|\"return_uri\"|\"returnuri\"|\"goto\"|\"redirecturl\"|\"redirect_url\"|\"redirecturi\"|\"redirect_uri\"|document.write\(\w+\))"

function check_cmds() {
    for cmd in $@; do
        if ! $(which $cmd &>/dev/null); then
            echo "'$cmd' missing"
            exit 1
        fi
    done
}

if [ ! $1 ]; then
    echo "Usage: $0 URL"
    exit 1
fi

if ! $(curl -s $URL > /dev/null); then
    echo "invalid URL '$1'"
    exit 1
fi

if ! [ -d ./.git ]; then
    echo "This is not a git repo, get your shit together..."
    exit 1
fi

check_cmds tee egrep hakrawler 

#retrieve JS files
hakrawler -d 3 -subs <<<"$URL" | sort -u | egrep '.js$' | tee js_linklist | xargs wget -q --tries 2

# sarch files for interesting patterns
egrep -rn . -ie $PATTERN -o | sort -u

