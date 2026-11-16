#!/bin/sh
# Container health = "documents can really be converted through a kit", not just "the web server answers" (ou3).
exec env OU_DOCS_HOSTPORTS="127.0.0.1:9980 ::1:9980" OU_DOCS_PROBE_TIMEOUT=4 /usr/libexec/ou-docs/ou-docs-ready >/dev/null
