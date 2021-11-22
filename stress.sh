#!/bin/bash
which wscat > /dev/null 2>/dev/null
if [ "$?" -ne "0" ]
then
    echo 'wscat is required to use this script'
    exit 1
fi

which ./peermon > /dev/null 2> /dev/null
if [ "$?" -ne "0" ]
then
    echo 'Please compile peermon first then run this script from the build directory.'
    exit 1
fi


if [ "$#" -ne "3" ]
then
    echo "rippled stress tester"
    echo "Usage: $0 peer-ip peer-port ws-endpoint"
    echo "Example: $0 r.ripple.com 51235 ws://localhost:6006"
    exit 1
fi

PIPE=$(mktemp -u)


echo "Starting stress tester..."

mkfifo $PIPE
if [ "$?" -ne "0" ];
then
    echo "Failed to create fifo at $PIPE"
    exit 2
fi
echo "Created fifo: $PIPE"

exec 3<>$PIPE
/bin/rm -f $PIPE

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

wscat -c $3 <&3 &
wscat=$?
./peermon $1 $2 no-cls no-stats | grep -E --line-buffered 'LedgerHash|Account|Destination' | 
    tr -d '",:' | awk "$AWK_SCRIPT" >&3
