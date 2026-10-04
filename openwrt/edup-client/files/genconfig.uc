#!/usr/bin/ucode
// Writes the edup-client JSON configuration from /etc/config/edup.
//
// usage: genconfig.uc <client.json> <core.json>
// <core.json> is the configuration without "from" rules: when only device
// modes change, the service reloads the client table instead of restarting.
'use strict';

import { cursor } from 'uci';
import { connect } from 'ubus';
import * as fs from 'fs';

const MODES = { all: 'proxy', off: 'bypass', rules: 'rules' };

function list(value) {
	if (type(value) == 'array')
		return value;
	return (value == null || value == '') ? [] : [ value ];
}

function fail(message) {
	warn(`edup: ${message}\n`);
	exit(1);
}

// The subnet of a network interface, as "address/prefix".
function subnet(network) {
	const bus = connect();
	const status = bus?.call(`network.interface.${network}`, 'status', {});
	const address = status?.['ipv4-address']?.[0];
	return address ? `${address.address}/${address.mask}` : null;
}

// EDUP_UCI_DIR: another configuration directory, for tests.
const uci = cursor(getenv('EDUP_UCI_DIR'));
uci.load('edup');
const main = uci.get_all('edup', 'main') ?? {};

if (!match(main.server ?? '', /^(\[[0-9A-Fa-f:.]+\]|[0-9.]+):[0-9]+$/))
	fail('set a server address and port, e.g. 192.0.2.1:7777');
if (!match(main.user ?? '', /^-?[0-9]+$/))
	fail('set the user ID (a signed 64-bit integer)');
if (!length(main.password))
	fail('set the password');

const routes = [];
uci.foreach('edup', 'device', (s) => {
	if (s.enabled == '0' || !length(s.ip))
		return;
	push(routes, { from: s.ip, to: MODES[s.mode] ?? 'rules' });
});
const lan_mode = main.lan_mode ?? 'rules';
if (lan_mode != 'rules') {
	const network = subnet(main.lan_network ?? 'lan');
	if (network)
		push(routes, { from: network, to: MODES[lan_mode] ?? 'rules' });
	else
		warn(`edup: no IPv4 subnet on network ${main.lan_network ?? 'lan'}; "other devices" mode not applied\n`);
}
uci.foreach('edup', 'rule', (s) => {
	if (s.enabled == '0')
		return;
	const rule = {};
	for (let field in [ 'ip', 'domain', 'domain_suffix', 'domain_keyword' ])
		if (length(list(s[field])))
			rule[field] = list(s[field]);
	if (length(list(s.ruleset)))
		rule.rules = list(s.ruleset);
	if (!length(rule)) {
		warn(`edup: skipping traffic rule ${s.name ?? s['.name']} without addresses, domains or rule-sets\n`);
		return;
	}
	rule.to = s.to == 'bypass' ? 'bypass' : 'proxy';
	push(routes, rule);
});

const config = {
	mode: 'xdp',
	xdp_mode: main.xdp_mode ?? 'auto',
	server: main.server,
	user: int(main.user),
	password: main.password,
	tunnel_ip: main.tunnel_ip ?? '10.66.0.1',
	interface: main.interface ?? 'edup0',
	mtu: int(main.mtu ?? 1465),
	keepalive_secs: int(main.keepalive ?? 15),
	routing: {
		default_route: main.default_route == 'bypass' ? 'bypass' : 'proxy',
		routes: routes,
	},
	dns: {
		servers: list(main.dns_server),
		set_system: main.dns_set_system != '0',
		proxy: main.dns_proxy == '1',
		// dnsmasq binds port 53 on every address, the tunnel's too.
		port: int(main.dns_port ?? 10053),
	},
};
const core = { ...config, routing: { ...config.routing, routes: filter(routes, (r) => !r.from) } };

const output = ARGV[0] ?? '/var/etc/edup/client.json';
const core_output = ARGV[1] ?? '/var/etc/edup/core.json';
fs.mkdir('/var/etc/edup');
// The configuration holds the password.
const file = fs.open(output, 'w', 0600);
if (!file)
	fail(`cannot write ${output}: ${fs.error()}`);
file.write(sprintf('%.J\n', config));
file.close();
fs.writefile(core_output, sprintf('%J\n', core));
