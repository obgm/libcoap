#!/bin/bash

#
# This script is used to run the oscore interop tests as specified in
# https://core-wg.github.io/oscore/test-spec5.html
#
# By default, this script should be run in the examples directory.
#
# 3 separate servers are set up, listening on different ports (defaults shown)
#  Server B with security context B (interop/b_server.conf) on port 5683
#  Server D with security context D (interop/d_server.conf) on port 5685
#  Server N with No security context on port 5687
#
# The clients are run with security contexts A (interop/a_client.conf) and
# C (interop/c_client.conf), and where appropriate, modifications to the
# appropriate base security contexts (called here E (interop/e_client.conf),
# F (interop/f_client.conf) and G (interop/g_client.conf)).
#
# Ports used can be modified (for listening and sending) using
# the -B, -D and -N options for the respective servers.
#
# Run as
#  ./oscore_testcases.sh [-h remote-target-IP] [-B port-B-OSCORE] \
#                        [-D port-D-OSCORE] [-N port-NO-OSCORE] \
#                        [-s executable-for-interop-server] \
#                        [-c executable-for-client] \
#                        [-P] [-F]
#
# -h remote-target-IP
#  Remote server hosting interop tests if not running the interop server on this host.
#
# -B port-B-OSCORE
#  Port that the server listening on providing B OSCORE security profile
#
# -D port-D-OSCORE
#  Port that the server listening on providing D OSCORE security profile
#
# -N port-N-OSCORE
#  Port that the server listening on providing no security profile
#
# -S
#  Start up the servers only for the different profiles
#
# -s executable-for-interop-server
#  Exectuable to use for the interop server if not the default of ./oscore-interop-server.
#
# -c executable-for-client
#  Exectuable to use for the coap client if not the default of ./coap-client.
#
# -P
#  Output partial client logs
#
# -F
#  Output full client logs
#

INDIR=`dirname $0`

# Defaults

# host running oscore interop server
TARGET_IP=127.0.0.1
# Server with B OSCORE Security
S_PORT_B=5683
# Server with D OSCORE Security
S_PORT_D=5685
# Server with no Security
S_PORT_N=5687
# Client app
CLIENT=$INDIR/coap-client
# SERVER app
SERVER=$INDIR/oscore-interop-server
# Partial Logs
PARTIAL_LOGS=no
# Full Logs
FULL_LOGS=no

while getopts "c:h:s:B:D:FN:PS" OPTION; do
  case $OPTION in
    c)
      CLIENT="$OPTARG"
      ;;
    h)
      TARGET_IP="$OPTARG"
      ;;
    s)
      SERVER="$OPTARG"
      ;;
    B)
      S_PORT_B="$OPTARG"
      ;;
    D)
      S_PORT_D="$OPTARG"
      ;;
    F)
      FULL_LOGS=yes
      ;;
    N)
      S_PORT_N="$OPTARG"
      ;;
    P)
      PARTIAL_LOGS=yes
      ;;
    S)
      SERVERS_ONLY=yes
      ;;
    *)
      echo Error in options detected
      echo Run as
      echo "$0 [-h remote-target-IP] [-B port-B-OSCORE]"
      echo "      [-D port-D-OSCORE] [-N port-NO-OSCORE]"
      echo "      [-S]"
      echo "      [-s executable-for-interop-server]"
      echo "      [-c executable-for-client]"
      echo "      [-P] [-F]"
      exit 1
  esac
done

timecheck () {
  timeout $*
  if [ $? = 124 ] ; then
    echo "****** Timed Out ******"
  fi
}

NO_PASS=0
NO_FAIL=0
# passfail count grep-expression
passfail () {
  PASS=`cat /tmp/client_out | grep -E "$2" | wc -l`
  if [ "$PASS" = "$1" ] ; then
    echo Pass
    let "NO_PASS=$NO_PASS+1"
  else
    echo Fail
    let "NO_FAIL=$NO_FAIL+1"
  fi
  if [ "$FULL_LOGS" = yes ] ; then
    cat /tmp/client_out
  elif [ "$PARTIAL_LOGS" = yes ] ; then
    cat /tmp/client_out | grep -E -v " DEBG | OSC  "
  fi
}

if [ "$TARGET_IP" = "127.0.0.1" -o "$SERVERS_ONLY" = yes ]; then
  killall -9 `basename $SERVER` > /dev/null 2>&1

  $SERVER -E $INDIR/interop/b_server.conf -v8 -p $S_PORT_B > /tmp/server_b 2>&1 &
  $SERVER -E $INDIR/interop/d_server.conf -v8 -p $S_PORT_D > /tmp/server_d 2>&1 &
  $SERVER                                 -v8 -p $S_PORT_N > /tmp/server_n 2>&1 &

  sleep 1
fi

if [ "$SERVERS_ONLY" = yes ] ; then
  echo Servers are running, output in /tmp/server_b, /tmp/server_d, and /tmp/server_n
  ps -ef | grep oscore-interop-server | grep -E -v "grep "
  exit 0
fi

# Reset sequence number counters
rm -f /tmp/client_a
rm -f /tmp/client_c

# Test 0 General checkout
echo -n "Test 0 - "
timecheck 10 $CLIENT -w -v8 coap://$TARGET_IP:$S_PORT_B/oscore/hello/coap 2>&1 | grep -E -v " DEBG | OSC  " > /tmp/client_out
passfail 1 "^Hello World"

# Test 1
echo -n "Test 1 - "
timeout 10 $CLIENT -w -v8 -E $INDIR/interop/a_client.conf,/tmp/client_a coap://$TARGET_IP:$S_PORT_B/oscore/hello/1 > /tmp/client_out 2>&1
passfail 1 "^Hello World"

# Test 2
echo -n "Test 2 - "
timeout 10 $CLIENT -w -v8 -E $INDIR/interop/c_client.conf,/tmp/client_c coap://$TARGET_IP:$S_PORT_D/oscore/hello/1 > /tmp/client_out 2>&1
passfail 1 "^Hello World"

# Test 3
echo -n "Test 3 - "
timeout 10 $CLIENT -w -v8 -E $INDIR/interop/a_client.conf,/tmp/client_a coap://$TARGET_IP:$S_PORT_B/oscore/hello/2?first=1 > /tmp/client_out 2>&1
passfail 1 "^Hello World"

# Test 4
echo -n "Test 4 - "
timeout 10 $CLIENT -w -v8 -E $INDIR/interop/a_client.conf,/tmp/client_a -A 0 coap://$TARGET_IP:$S_PORT_B/oscore/hello/3 > /tmp/client_out 2>&1
passfail 1 "^Hello World"

# Test 5
echo -n "Test 5 - "
timeout 10 $CLIENT -w -v8 -E $INDIR/interop/a_client.conf,/tmp/client_a -s 2 coap://$TARGET_IP:$S_PORT_B/oscore/hello/1 > /tmp/client_out 2>&1
passfail 1 "^Hello World"

# Test 6
echo -n "Test 6 - "
timeout 10 $CLIENT -w -v8 -E $INDIR/interop/a_client.conf,/tmp/client_a -s 4 coap://$TARGET_IP:$S_PORT_B/oscore/observe1 > /tmp/client_out > /tmp/client_out 2>&1
passfail 3 "^one|^two|^5.00 Terminate Observe"

# Test 7
echo -n "Test 7 - "
timeout 10 $CLIENT -w -v8 -E $INDIR/interop/a_client.conf,/tmp/client_a -s 2 coap://$TARGET_IP:$S_PORT_B/oscore/observe2 > /tmp/client_out 2>&1
passfail 3 "^one|^two"

# Test 8
echo -n "Test 8 - "
timeout 10 $CLIENT -w -v8 -E $INDIR/interop/a_client.conf,/tmp/client_a -m post -e "%4a" -t 0 coap://$TARGET_IP:$S_PORT_B/oscore/hello/6 > /tmp/client_out 2>&1
passfail 1 "^J$"

# Test 9
echo -n "Test 9 - "
timeout 10 $CLIENT -w -v8 -E $INDIR/interop/a_client.conf,/tmp/client_a -m put -e "%7a" -t 0 -O 1,0x7b coap://$TARGET_IP:$S_PORT_B/oscore/hello/7 > /tmp/client_out 2>&1
passfail 1 "^z"

# Test 10
echo -n "Test 10 - "
timeout 10 $CLIENT -w -v8 -E $INDIR/interop/a_client.conf,/tmp/client_a -m put -e "%8a" -t 0 -O 5 coap://$TARGET_IP:$S_PORT_B/oscore/hello/7 > /tmp/client_out 2>&1
passfail 1 "^4.12 Precondition Failed"

# Test 11
if [ "$SUPPRESS" = no ] ; then
  echo
fi
echo -n "Test 11 - "
timeout 10 $CLIENT -w -v8 -E $INDIR/interop/a_client.conf,/tmp/client_a -m delete coap://$TARGET_IP:$S_PORT_B/oscore/test > /tmp/client_out 2>&1
passfail 1 "^v:1 t:CON c:2.02 i:"

# Test 12
if [ "$SUPPRESS" = no ] ; then
  echo
fi
echo -n "Test 12 - "
timeout 10 $CLIENT -w -v8 -E $INDIR/interop/e_client.conf,/tmp/client_a coap://$TARGET_IP:$S_PORT_B/oscore/hello/1 > /tmp/client_out 2>&1
passfail 1 "^4.01 Security context not found"

# Test 13
if [ "$SUPPRESS" = no ] ; then
  echo
fi
echo -n "Test 13 - "
timeout 10 $CLIENT -w -v8 -E $INDIR/interop/f_client.conf,/tmp/client_a coap://$TARGET_IP:$S_PORT_B/oscore/hello/1 > /tmp/client_out 2>&1
passfail 1 "^4.00 Decryption failed"

# Test 14
if [ "$SUPPRESS" = no ] ; then
  echo
fi
echo -n "Test 14 - "
timeout 10 $CLIENT -w -v8 -E $INDIR/interop/g_client.conf,/tmp/client_a coap://$TARGET_IP:$S_PORT_B/oscore/hello/1 > /tmp/client_out 2>&1
passfail 1 "WARN OSCORE: Decryption Failure, result code: -5"

# Test 15
if [ "$SUPPRESS" = no ] ; then
  echo
fi
echo -n "Test 15 - "
timeout 10 $CLIENT -w -v8 -E $INDIR/interop/a_client.conf coap://$TARGET_IP:$S_PORT_B/oscore/hello/1 > /tmp/client_out 2>&1
passfail 1 "^4.01 Replay detected"

# Test 16
if [ "$SUPPRESS" = no ] ; then
  echo
fi
echo -n "Test 16 - "
timeout 10 $CLIENT -w -v8 -E $INDIR/interop/e_client.conf,/tmp/client_a coap://$TARGET_IP:$S_PORT_N/oscore/hello/coap > /tmp/client_out 2>&1
passfail 1 "^4.02 Bad Option"

# Test 17
if [ "$SUPPRESS" = no ] ; then
  echo
fi
echo -n "Test 17 - "
timeout 10 $CLIENT -w -v8 coap://$TARGET_IP:$S_PORT_N/oscore/hello/1 > /tmp/client_out 2>&1
passfail 1 "^4.01 Unauthorized"

if [ "$TARGET_IP" = "127.0.0.1" ]; then
  KILL_SERVER=`basename $SERVER`
  if [ ! -z "$KILL_SERVER" ] ; then
    killall $KILL_SERVER
  fi
fi

echo
echo ===============
echo Pass:  $NO_PASS
echo Fail:  $NO_FAIL
#Starts with test 0
echo Total: 18

if [ "$NO_FAIL" != 0 ] ; then
  exit 1
fi
