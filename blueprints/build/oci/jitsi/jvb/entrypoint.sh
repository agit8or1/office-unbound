#!/bin/bash
set -eu
CONF=${JVB_CONFIG:-/etc/jitsi/videobridge/jvb.conf}
[ -r "$CONF" ] || { echo "no $CONF: mount the videobridge configuration" >&2; exit 2; }
# defaults first, the operator's jvb.conf wins (HOCON include of the defaults inside a generated wrapper)
mkdir -p /tmp/jvb
printf 'include file("/etc/jitsi/videobridge/defaults.conf")\ninclude file("%s")\n' "$CONF" > /tmp/jvb/effective.conf
export JAVA_SYS_PROPS="-Dconfig.file=/tmp/jvb/effective.conf -Dnet.java.sip.communicator.SC_HOME_DIR_LOCATION=/tmp -Dnet.java.sip.communicator.SC_HOME_DIR_NAME=jvb -Djava.util.logging.config.file=/etc/jitsi/videobridge/logging.properties"
exec /usr/share/jitsi-videobridge/jvb.sh
