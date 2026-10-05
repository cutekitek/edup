'use strict';
'require view';
'require form';
'require rpc';
'require uci';

const callHostHints = rpc.declare({
	object: 'luci-rpc',
	method: 'getHostHints',
	expect: { '': {} }
});

// Each server, then the traffic rules or no VPN.
function modes(o) {
	uci.sections('edup', 'server').forEach((s) =>
		o.value(s['.name'], _('Always via %s').format(s['.name'])));
	o.value('rules', _('Traffic rules'));
	o.value('direct', _('No VPN'));
}

return view.extend({
	load() {
		return Promise.all([
			L.resolveDefault(callHostHints(), {}),
			uci.load('edup')
		]);
	},

	render([hosts]) {
		const m = new form.Map('edup', _('edup VPN: devices'),
			_('Choose for each device of the local network where its traffic goes: always through one server, as the traffic rules decide, or never through the VPN. ' +
			  'Devices are matched by IPv4 address, so give them a static DHCP lease. ' +
			  'Changes to this page apply without interrupting the tunnels; connections a change moves to another path restart.'));

		let s = m.section(form.NamedSection, 'main', 'edup');
		let o = s.option(form.ListValue, 'lan_mode', _('Other devices'),
			_('Devices of the LAN that are not listed below.'));
		modes(o);
		o.default = 'rules';

		s = m.section(form.GridSection, 'device', _('Devices'),
			_('The first matching entry decides; list single devices before networks.'));
		s.addremove = true;
		s.anonymous = true;
		s.sortable = true;
		s.nodescriptions = true;
		s.modaltitle = _('Device');

		o = s.option(form.Flag, 'enabled', _('Enabled'));
		o.default = o.enabled;
		o.editable = true;

		o = s.option(form.Value, 'name', _('Name'));
		o.rmempty = true;

		const names = {};
		o = s.option(form.Value, 'ip', _('Address'),
			_('An IPv4 address, or a network as address/prefix.'));
		o.datatype = 'or(ip4addr("nomask"),cidr4)';
		o.rmempty = false;
		Object.keys(hosts).sort().forEach((mac) => {
			const host = hosts[mac];
			(host.ipaddrs ?? (host.ipv4 ? [ host.ipv4 ] : [])).forEach((ip) => {
				names[ip] = host.name ?? mac;
				o.value(ip, '%s (%s)'.format(ip, names[ip]));
			});
		});
		// Choosing a known host also fills in an empty name.
		o.onchange = function(ev, section_id, value) {
			const name = this.map.lookupOption('name', section_id)?.[0]?.getUIElement(section_id);
			if (name && !name.getValue() && names[value])
				name.setValue(names[value]);
		};

		o = s.option(form.ListValue, 'mode', _('VPN'));
		modes(o);
		o.default = uci.sections('edup', 'server')[0]?.['.name'] ?? 'rules';
		o.editable = true;

		return m.render();
	}
});
