#!/bin/bash

if [ $# -eq 0 ]; then
  echo "无效参数"
  exit -1
fi

USER_PATH=/mnt/ethereum
MODULE_PATH=$USER_PATH/bitcore/packages
NODE_PATH=$USER_PATH/.nvm/versions/node/v10.5.0/bin

cd $MODULE_PATH/bitcore-wallet-service

stop_program ()
{
  pidfile=$1

  echo "Stopping Process - $pidfile. PID=$(cat $pidfile)"
  kill -9 $(cat $pidfile)
  rm $pidfile
  
}

stop_program $1

