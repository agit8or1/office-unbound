/*
 * SPDX-FileCopyrightText: 2026 Office Unbound contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * The "Dashboard" button at the far left of the main tab bar: back to the Office Unbound user portal in the same tab. Styled by the
 * deployment's /brand/brand.css (.ou-home-btn: the pill every app shows). Plain ES5, no build step (loaded as is in every loader mode).
 */
Ext.namespace('Grommunio.plugins.oudashboard');

Grommunio.plugins.oudashboard.Plugin = Ext.extend(Grommunio.core.Plugin, {
	initPlugin: function() {
		var s = container.getSettingsModel().get('grommunio/v1/plugins/oudashboard', true) || {};
		var url = s.url;
		if (typeof url !== 'string' || !/^https:\/\/[a-z0-9.-]+\/$/.test(url)) {
			return;
		}
		this.registerInsertionPoint('main.maintabbar.left', function() {
			return {
				text: Ext.util.Format.htmlEncode(s.label || 'Dashboard'),
				cls: 'ou-home-btn',
				id: 'mainmenu-button-ou-dashboard',
				tooltip: _('Back to your dashboard'),
				tabOrderIndex: -1,
				handler: function() { window.location.assign(url); }
			};
		}, this);
	}
});

Grommunio.onReady(function() {
	container.registerPlugin(new Grommunio.core.PluginMetaData({
		name: 'oudashboard',
		displayName: 'Dashboard link',
		allowUserDisable: false,
		pluginConstructor: Grommunio.plugins.oudashboard.Plugin
	}));
});
