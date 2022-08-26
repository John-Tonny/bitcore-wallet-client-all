#!/bin/bash

if [ $# -eq 0 ]; then
  echo "无效参数"
  exit -1
fi

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
    rm $pidfile
  else
    echo "Stopping Process - $pidfile."
  fi
  
}

stop_program $1

