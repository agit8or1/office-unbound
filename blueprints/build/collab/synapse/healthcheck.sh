#!/bin/sh
exec /opt/synapse/bin/python3 -c 'import urllib.request,sys; sys.exit(0 if urllib.request.urlopen("http://127.0.0.1:8008/health",timeout=4).status==200 else 1)'
