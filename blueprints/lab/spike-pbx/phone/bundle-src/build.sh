#!/bin/sh
# Rebuild the pinned JsSIP bundle (esbuild 0.25.4 devDependency; lockfile pinned). Output replaces static/jssip-3.13.9.bundle.min.js
cd "$(dirname "$0")" && npm ci --no-audit --no-fund && ./node_modules/.bin/esbuild node_modules/jssip/lib/JsSIP.js --bundle --minify --format=iife --global-name=JsSIP --legal-comments=none --outfile=../static/jssip-3.13.9.bundle.min.js
