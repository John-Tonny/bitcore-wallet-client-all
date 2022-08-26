#!/bin/bash

if [ "x${BITCORE_PATH}" == "x" ]; then
  BITCORE_PATH=/root/bitcore
fi

MODULE_PATH=$BITCORE_PATH/packages

cd $MODULE_PATH/bitcore-wallet-service


stop_program ()
{
  pidfile=$1

  if [ -f $pidfile ]; then
    echo "Stopping Process - $pidfile. PID=$(cat $pidfile)"
    kill -9 $(cat $pidfile)
    rm -f $pidfile
  else
    echo "Stopping Process - $pidfile."
  fi
  
}

stop_program pids/bws.pid
stop_program pids/masternodeservice.pid
stop_program pids/fiatrateservice.pid
stop_program pids/emailservice.pid
stop_program pids/bcmonitor.pid
stop_program pids/pushnotificationsservice.pid
stop_program pids/messagebroker.pid

