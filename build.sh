#!/bin/bash

TPWD=`pwd`

cd /deepfs/src/flxsmb
ant clean
ant jar
cp -f /deepfs/src/flxsmb/dist/jcifs-1.3.17-flx.1.jar /deepfs/src/siqsmb/lib/jcifs-1.3.17-flx.1.jar

cd $TPWD
