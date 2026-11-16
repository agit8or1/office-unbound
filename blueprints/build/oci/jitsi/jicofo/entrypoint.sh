#!/bin/bash
set -eu
CONF=${JICOFO_CONFIG:-/etc/jitsi/jicofo/jicofo.conf}
[ -r "$CONF" ] || { echo "no $CONF: mount the jicofo configuration" >&2; exit 2; }
export JAVA_SYS_PROPS="-Dconfig.file=$CONF -Dnet.java.sip.communicator.SC_HOME_DIR_LOCATION=/tmp -Dnet.java.sip.communicator.SC_HOME_DIR_NAME=jicofo -Djava.util.logging.config.file=/etc/jitsi/jicofo/logging.properties"
exec /usr/share/jicofo/jicofo.sh
