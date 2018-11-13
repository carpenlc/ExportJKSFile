#!/bin/bash
if [ -z ${JAVA_HOME+x} ]; then JAVA_HOME=/usr/java/jdk1.8.0; fi
SCRIPT_DIR=$(dirname `which $0`)
LIB_DIR="${SCRIPT_DIR}/../target/lib/"

for i in ${LIB_DIR}*.jar; do
    CLASSPATH=$CLASSPATH:$i
done

$JAVA_HOME/bin/java -classpath ${CLASSPATH} mil.pki.util.ExportJKSFile $1 $2 $3 $4
