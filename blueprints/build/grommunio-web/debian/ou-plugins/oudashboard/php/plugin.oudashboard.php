<?php

/*
 * SPDX-FileCopyrightText: 2026 Office Unbound contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 */

/**
 * Hands the portal URL from PLUGIN_OUDASHBOARD_CONFIG to the client as a sysadmin default (grommunio/v1/plugins/oudashboard),
 * the same way the upstream intranet plugin publishes its URLs.
 */
class Pluginoudashboard extends Plugin {
	public function init() {
		$this->registerHook('server.core.settings.init.before');
	}

	public function execute($eventID, &$data) {
		if ($eventID === 'server.core.settings.init.before') {
			$this->injectPluginSettings($data);
		}
	}

	public function injectPluginSettings(&$data) {
		$url = '';
		$label = 'Dashboard';
		if (is_readable(PLUGIN_OUDASHBOARD_CONFIG)) {
			$cfg = json_decode((string) file_get_contents(PLUGIN_OUDASHBOARD_CONFIG), true);
			if (is_array($cfg) && is_string($cfg['url'] ?? null) && preg_match('#^https://[a-z0-9.-]+/$#', $cfg['url'])) {
				$url = $cfg['url'];
			}
			if (is_array($cfg) && is_string($cfg['label'] ?? null) && preg_match('/^[\p{L}\p{N} ]{1,30}$/u', $cfg['label'])) {
				$label = $cfg['label'];
			}
		}
		$data['settingsObj']->addSysAdminDefaults([
			'grommunio' => ['v1' => ['plugins' => ['oudashboard' => ['enable' => $url !== '', 'url' => $url, 'label' => $label]]]],
		]);
	}
}
