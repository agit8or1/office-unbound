/*
 * SPDX-FileCopyrightText: 2026 Office Unbound contributors
 * SPDX-License-Identifier: AGPL-3.0-or-later
 *
 * Office Unbound integration of the web client, through upstream's plugin insertion points only:
 * - main.maintabbar.left: the "Dashboard" button at the far left of the main tab bar, back to the Office Unbound user portal in the same
 *   tab. Styled by the deployment's /brand/brand.css (.ou-home-btn: the pill every app shows).
 * - navigation.north: the app's primary action at the top of its side column (docs/design/app-shell.md, "App column"): "New message",
 *   "New event", "New contact", "New task", "New note", one button per context (upstream shows a navigation.north component only while its
 *   navigationContext is active). Each calls the same upstream action as the context's entry in the toolbar's New menu. The buttons are
 *   moved in front of the other north components (the calendar's date picker) before the panel renders, through the container API, so
 *   ExtJS lays them out and measures them itself.
 * Plain ES5, no build step (loaded as is in every loader mode).
 */
Ext.namespace('Grommunio.plugins.oudashboard');

Grommunio.plugins.oudashboard.Plugin = Ext.extend(Grommunio.core.Plugin, {
	initPlugin: function() {
		this.registerInsertionPoint('navigation.north', this.createPrimaryActions, this);
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
	},

	/**
	 * One primary button per context that creates items. Contexts that are disabled (no instance) are skipped.
	 * @param {String} insertionPoint navigation.north
	 * @param {Grommunio.core.ui.NavigationPanel} panel the panel being constructed
	 * @return {Object[]} button configurations
	 */
	createPrimaryActions: function(insertionPoint, panel) {
		var defs = [
			['mail', _('New message'), 'Grommunio.mail.Actions', 'openCreateMailContent'],
			['calendar', _('New event'), 'Grommunio.calendar.Actions', 'openCreateAppointmentContent'],
			['contact', _('New contact'), 'Grommunio.contact.Actions', 'openCreateContactContent'],
			['task', _('New task'), 'Grommunio.task.Actions', 'openCreateTaskContent'],
			['note', _('New note'), 'Grommunio.note.Actions', 'openCreateNoteContent']
		];
		var buttons = [];
		Ext.each(defs, function(d) {
			var context = container.getContextByName(d[0]);
			var actions = window;
			Ext.each(d[2].split('.'), function(n) { actions = actions ? actions[n] : undefined; });
			if (!context || !actions || !Ext.isFunction(actions[d[3]])) {
				return;
			}
			buttons.push({
				xtype: 'button',
				id: 'ou-primary-new-' + d[0],
				cls: 'ou-primary-new',
				text: Ext.util.Format.htmlEncode(d[1]),
				tooltip: d[1],
				height: 36,
				margins: '12 12 6 12',
				navigationContext: context,
				handler: function() { actions[d[3]](context.getModel()); }
			});
		});
		if (panel && buttons.length) {
			panel.on('beforerender', function(p) {
				for (var i = buttons.length - 1; i >= 0; i--) {
					var c = Ext.getCmp(buttons[i].id);
					if (c && c.ownerCt === p) {
						p.insert(0, c);
					}
				}
			}, this, { single: true });
		}
		return buttons;
	}
});

Grommunio.onReady(function() {
	container.registerPlugin(new Grommunio.core.PluginMetaData({
		name: 'oudashboard',
		displayName: 'Office Unbound integration',
		allowUserDisable: false,
		pluginConstructor: Grommunio.plugins.oudashboard.Plugin
	}));
});
