'use strict';
'require view';
'require form';
'require uci';
'require ui';

// Route values that cannot name a server.
const RESERVED = [ 'direct', 'bypass', 'rules' ];

return view.extend({
	load() {
		return uci.load('edup');
	},

	render() {
		const m = new form.Map('edup', _('edup VPN: servers'),
			_('Tunnel servers. Devices and traffic rules choose a server by its name; each server has a tunnel of its own. ' +
			  'All servers use IPv4, or all IPv6. "edup-client credentials" creates a user ID and password for a new user. ' +
			  'Devices and rules that use a disabled server go direct.'));

		const s = m.section(form.GridSection, 'server', _('Servers'),
			_('The name is fixed once the server is added: letters, digits and _.'));
		s.addremove = true;
		s.anonymous = false;
		s.nodescriptions = true;
		s.modaltitle = (section_id) => _('Server %s').format(section_id);
		s.handleAdd = function(ev, name) {
			if (RESERVED.includes(name)) {
				ui.addNotification(null, E('p', _('"%s" is a route, not a server name.').format(name)), 'warning');
				return Promise.resolve();
			}
			if (uci.get('edup', name)) {
				ui.addNotification(null, E('p', _('The name "%s" is already used.').format(name)), 'warning');
				return Promise.resolve();
			}
			return form.GridSection.prototype.handleAdd.apply(this, [ ev, name ]);
		};

		let o = s.option(form.Flag, 'enabled', _('Enabled'));
		o.default = o.enabled;
		o.editable = true;

		o = s.option(form.Value, 'server', _('Address'), _('Address and port, e.g. 192.0.2.1:7777 or [2001:db8::1]:7777.'));
		o.rmempty = false;
		o.validate = (section_id, value) =>
			/^(\[[0-9A-Fa-f:.]+\]|[0-9.]+):[0-9]+$/.test(value) || _('Expecting address:port');

		o = s.option(form.Value, 'user', _('User ID'), _('A signed 64-bit integer.'));
		o.rmempty = false;
		o.validate = (section_id, value) => /^-?[0-9]+$/.test(value) || _('Expecting an integer');

		o = s.option(form.Value, 'password', _('Password'));
		o.password = true;
		o.rmempty = false;
		o.modalonly = true;

		return m.render();
	}
});
