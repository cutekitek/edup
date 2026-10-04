'use strict';
'require view';
'require form';
'require fs';
'require poll';
'require rpc';
'require uci';
'require ui';

const callServiceList = rpc.declare({
	object: 'service',
	method: 'list',
	params: [ 'name' ],
	expect: { '': {} }
});

const callInitAction = rpc.declare({
	object: 'rc',
	method: 'init',
	params: [ 'name', 'action' ],
	expect: { result: false }
});

function status() {
	return L.resolveDefault(callServiceList('edup'), {}).then((list) => {
		const instance = list?.edup?.instances?.main;
		return instance?.running ? instance.pid : null;
	});
}

function log() {
	return L.resolveDefault(fs.exec_direct('/sbin/logread', [ '-e', 'edup-client' ]), '')
		.then((text) => text.trim().split('\n').slice(-40).join('\n'));
}

function renderStatus(pid) {
	return pid
		? E('span', { 'style': 'color:green' }, _('Running (PID %d)').format(pid))
		: E('span', { 'style': 'color:red' }, _('Not running'));
}

return view.extend({
	load() {
		return Promise.all([ status(), log(), uci.load('edup') ]);
	},

	render([ pid, text ]) {
		const m = new form.Map('edup', _('edup VPN: settings'),
			_('The tunnel runs in eBPF on the WAN interface. LAN devices need masquerading on the WAN zone (the default) and flow offloading must stay off.'));

		let s = m.section(form.NamedSection, 'main', 'edup', _('Service'));
		let o = s.option(form.DummyValue, '_status', _('Status'));
		o.cfgvalue = () => '';
		o.render = function() {
			const node = E('div', { 'id': 'edup-status' }, renderStatus(pid));
			return E('div', { 'class': 'cbi-value' }, [
				E('label', { 'class': 'cbi-value-title' }, _('Status')),
				E('div', { 'class': 'cbi-value-field' }, [
					node, ' ',
					E('button', {
						'class': 'cbi-button cbi-button-action',
						'click': ui.createHandlerFn(this, () =>
							callInitAction('edup', 'restart').then(() => status()).then((pid) =>
								node.replaceChildren(renderStatus(pid))))
					}, _('Restart'))
				])
			]);
		};

		o = s.option(form.Flag, 'enabled', _('Enable'));
		o.rmempty = false;

		o = s.option(form.Value, 'server', _('Server'), _('Address and port, e.g. 192.0.2.1:7777.'));
		o.rmempty = false;
		o.validate = (section_id, value) =>
			/^(\[[0-9A-Fa-f:.]+\]|[0-9.]+):[0-9]+$/.test(value) || _('Expecting address:port');

		o = s.option(form.Value, 'user', _('User ID'), _('A signed 64-bit integer; "edup-client credentials" creates one.'));
		o.rmempty = false;
		o.validate = (section_id, value) => /^-?[0-9]+$/.test(value) || _('Expecting an integer');

		o = s.option(form.Value, 'password', _('Password'));
		o.password = true;
		o.rmempty = false;

		o = s.option(form.Value, 'mtu', _('MTU'),
			_('The WAN MTU minus 27 bytes: 1465 for PPPoE, 1473 for Ethernet.'));
		o.datatype = 'range(576,1500)';
		o.placeholder = '1465';

		o = s.option(form.Value, 'tunnel_ip', _('Tunnel address'), _('Local address of the DNS forwarder.'));
		o.datatype = 'ip4addr("nomask")';
		o.placeholder = '10.66.0.1';

		o = s.option(form.Value, 'keepalive', _('Keepalive (s)'));
		o.datatype = 'range(1,60)';
		o.placeholder = '15';

		o = s.option(form.ListValue, 'xdp_mode', _('XDP mode'),
			_('How Ethernet WAN interfaces receive tunnel packets; interfaces without Ethernet headers, such as PPPoE, use TC.'));
		o.value('auto', _('Automatic'));
		o.value('driver', _('Native'));
		o.value('skb', _('Generic'));
		o.default = 'auto';

		o = s.option(form.Value, 'wan_interface', _('WAN interface'),
			_('The tunnel restarts when this network interface reconnects.'));
		o.placeholder = 'wan';

		o = s.option(form.Value, 'lan_network', _('LAN interface'),
			_('Network whose devices "Other devices" refers to.'));
		o.placeholder = 'lan';

		o = s.option(form.DynamicList, 'dns_server', _('DNS servers'),
			_('Upstream resolvers for domain rules. Default: 1.1.1.1 and 8.8.8.8.'));
		o.datatype = 'or(ipaddr("nomask"),ipaddrport(1))';

		o = s.option(form.Flag, 'dns_proxy', _('Send DNS queries through the VPN'),
			_('The forwarder for domain rules reaches these DNS servers through the tunnel, whatever the traffic rules say. When off, their addresses follow the traffic rules. Servers on local networks are always reached directly.'));
		o.rmempty = false;

		o = s.option(form.Flag, 'dns_set_system', _('Use for dnsmasq'),
			_('With domain rules, dnsmasq forwards every name to the edup DNS forwarder while it runs.'));
		o.default = o.enabled;
		o.rmempty = false;

		return m.render().then((node) => {
			const pre = E('pre', { 'id': 'edup-log', 'style': 'max-height:30em;overflow:auto' }, text || _('No log entries.'));
			node.appendChild(E('div', { 'class': 'cbi-section' }, [ E('h3', _('Log')), pre ]));
			poll.add(() => Promise.all([ status(), log() ]).then(([ pid, text ]) => {
				document.getElementById('edup-status')?.replaceChildren(renderStatus(pid));
				pre.textContent = text || _('No log entries.');
			}), 5);
			return node;
		});
	}
});
