#!/bin/bash

#########################################################################
# This script recursively enumerates TXT dns entries for a given domain #
# and parses SPF information. It can be used to get an overview of IPs  #
# that are allowed to send mails for a given domain. Use it like:       #
#  $ ./spfips.sh example.com                                            #
#########################################################################

function get_ips {
    includes=()

    args=$1

    for include in $@; do
        printf "$include:\n"
        for entry in $(host -t txt $include | egrep -o '\"v=spf1 [^"]+\"'); do
            if [[ "$entry" == "include:"* ]]; then
                includes+=($(echo $entry | sed 's/include://g'))
            elif [[ "$entry" == "ip4:"* || "$entry" == "ip6:"* ]]; then
                printf "\t$entry\n" | sed 's/ip[4,6]://g'
            fi
        done

        if [ ${#includes[@]} -ne 0 ]; then
            get_ips "${includes[@]}"
        fi
    done
}

which host &>/dev/null || {
    return && echo "'host' command not in path, cannot proceed" >&2 && exit;
}

[[ ! -z $1 ]] || {
    printf "no domain specified.\nUsage: $0 example.com\n" >&2 && exit;
}

host $1 > /dev/null || {
    echo "could not resolve domain $1" >&2 && exit;
}

get_ips "$1"

