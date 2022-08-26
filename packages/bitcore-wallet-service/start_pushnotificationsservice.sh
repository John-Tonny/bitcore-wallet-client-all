#!/bin/bash

if [ "x${BITCORE_PATH}" == "x" ]; then
  BITCORE_PATH=/root/bitcore
fi

if [ "x${NODE_PATH1}" == "x" ]; then
  NODE_VERSION=`node -v`
  NODE_PATH=$HOME/.nvm/versions/node/$NODE_VERSION/bin
fi

MODULE_PATH=$BITCORE_PATH/packages
LOG_PATH=$BITCORE_PATH/logs

if [ ! -d $LOG_PATH  ]; then
  mkdir $LOG_PATH
fi

cd $MODULE_PATH/bitcore-wallet-service

mkdir -p pids

# run_program (nodefile, pidfile, logfile)
run_program ()
{
  nodefile=$1
  pidfile=$2
  logfile=$3

  if [ -e "$pidfile" ]
  then
    echo "$nodefile is already running. Run 'npm stop' if you wish to restart."
    return 0
  fi

  nohup $NODE_PATH/node $nodefile >> $logfile 2>&1 &
  PID=$!
  if [ $? -eq 0 ]
  then
    echo "Successfully started $nodefile. PID=$PID. Logs are at $logfile"
    echo $PID > $pidfile
    return 0
  else
    echo "Could not start $nodefile - check logs at $logfile"
    exit 1
  fi
}

./stop_bws.sh pids/pushnotificationsservice.pid
run_program ./ts_build/pushnotificationsservice/pushnotificationsservice.js pids/pushnotificationsservice.pid $LOG_PATH/pushnotificationsservice.log

