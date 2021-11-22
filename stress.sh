#!/bin/bash
AWK_SCRIPT='
{
    if ($1 == "Account" || $1 == "Destination")
    {
        print("{\"command\": \"account_info\", \"account\":\""$2"\"}");
        print("{\"command\": \"account_lines\", \"account\":\""$2"\"}");
        print("{\"command\": \"subscribe\", \"accounts\":[\""$2"\"]}");
    }
    else
    {
        print("{\"command\": \"ledger\", \"ledger_hash\":\""$2"\"}")
    }
}'
echo "$SCRIPT"
./peermon r.ripple.com 51235 no-cls no-stats | grep -E --line-buffered 'LedgerHash|Account|Destination' | 
    tr -d '",:' | awk "$AWK_SCRIPT"
