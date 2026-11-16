#!/bin/bash
# evo-servers.sh start|stop : (inside ou-desk2, as root) one long-lived Evolution Data Server session per test user
# (evo1 -> ccev1, evo2 -> ccev2) running tests/cc_evo_worker.py in server mode on 127.0.0.1:7001/7002.
# Prerequisite: unix users evo1/evo2 with ~/pw.env (their lab password, 0600) - see README.
case "$1" in
  start)
    for n in 1 2; do
      pkill -u "evo$n" 2>/dev/null
      systemctl stop "evo${n}srv" 2>/dev/null; systemctl reset-failed "evo${n}srv" 2>/dev/null
      systemd-run --quiet --unit="evo${n}srv" -E EWS_DEBUG="${EWS_DEBUG:-0}" /root/cc/evo-session.sh "evo$n" python3 -u /root/cc/cc_evo_worker.py serve "700$n"
    done
    sleep 3; ss -ltn | grep ':700[12]' ;;
  stop)
    for n in 1 2; do systemctl stop "evo${n}srv" 2>/dev/null; pkill -u "evo$n" 2>/dev/null; done ;;
esac
