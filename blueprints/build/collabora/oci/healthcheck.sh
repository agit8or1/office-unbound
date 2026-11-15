#!/bin/sh
exec curl -fsS -o /dev/null --max-time 4 http://127.0.0.1:9980/hosting/discovery
