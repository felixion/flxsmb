#!/bin/sh
PROJECTDIR=`dirname %0`

echo p: $PROJECTDIR

CLASSPATH=$PROJECTDIR/jcifs-1.3.17.jar

java -cp $CLASSPATH flxsmb.cli.ListDirectoryCommand "$@"
