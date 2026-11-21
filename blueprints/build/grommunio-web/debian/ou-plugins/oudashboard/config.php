<?php

/*
 * SPDX-FileCopyrightText: 2026 Office Unbound contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * The portal the Dashboard button returns to is per deployment: the node agent (cfg.gromox, ics/agent/ou_agent/cfghelper.py) writes it to
 * /etc/grommunio-web/ou-dashboard.json as {"url": "https://<portal>/", "label": "Dashboard"}. Without that file the plugin adds nothing.
 */
define('PLUGIN_OUDASHBOARD_CONFIG', '/etc/grommunio-web/ou-dashboard.json');
