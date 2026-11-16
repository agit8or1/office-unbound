#!/bin/bash
# evo-session.sh <unix-user> <command...> : run a command inside a private D-Bus session of <unix-user> (Evolution Data Server is
# started on demand by D-Bus activation) with an unlocked gnome-keyring (throw-away local password) (Secret Service for EDS credentials).
# Runs inside ou-desk2 as root. No display needed for EDS; DISPLAY=:99 is exported for tools that want one.
U="$1"; shift
exec runuser -u "$U" -- env HOME="/home/$U" XDG_RUNTIME_DIR="/run/user/$(id -u "$U")" DISPLAY=:99 \
  dbus-run-session -- bash -c '
    eval "$(echo -n "labkeyring" | gnome-keyring-daemon --unlock --components=secrets 2>/dev/null)"; export GNOME_KEYRING_CONTROL SSH_AUTH_SOCK
    "$@"; rc=$?
    pkill -u "$(id -u)" -f "evolution-(source-registry|calendar-factory|addressbook-factory|alarm-notify|user-prompter)" 2>/dev/null
    exit $rc' _ "$@"
