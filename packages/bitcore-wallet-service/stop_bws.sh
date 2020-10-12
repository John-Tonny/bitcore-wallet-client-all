#!/bin/bash

if [ $# -eq 0 ]; then
  echo "无效参数"
  exit -1
fi

MODULE_PATH=/home/ubuntu/bitcore/packages
NODE_PATH=/home/ubuntu/.nvm/versions/node/v10.5.0/bin

cd $MODULE_PATH/bitcore-wallet-service


stop_program ()
{
  pidfile=$1

  echo "Stopping Process - $pidfile. PID=$(cat $pidfile)"
  kill -9 $(cat $pidfile)
  rm $pidfile
  
}

stop_program $1

