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

// Tunnel servers: "config server '<tag>'" sections. Routes name them by tag.
const servers = [];
const disabled = {};
function add_server(tag, s) {
	if (!match(s.server ?? '', /^(\[[0-9A-Fa-f:.]+\]|[0-9.]+):[0-9]+$/))
		fail(`server ${tag}: set an address and port, e.g. 192.0.2.1:7777`);
	if (!match(s.user ?? '', /^-?[0-9]+$/))
		fail(`server ${tag}: set the user ID (a signed 64-bit integer)`);
	if (!length(s.password))
		fail(`server ${tag}: set the password`);
	push(servers, { tag: tag, server: s.server, user: int(s.user), password: s.password });
}
uci.foreach('edup', 'server', (s) => {
	const tag = s['.name'];
	if (tag in [ 'direct', 'bypass', 'rules' ] || !match(tag, /^[A-Za-z0-9_.-]{1,32}$/))
		fail(`server name "${tag}" is not allowed`);
	if (s.enabled == '0')
		disabled[tag] = true;
	else
		add_server(tag, s);
});
// Before servers had sections of their own.
if (!length(servers) && !length(disabled) && length(main.server))
	add_server('vpn', main);
if (!length(servers))
	fail('add a server');

// "direct", "rules" or an enabled server's tag; the values of earlier
// versions name the first server or "direct".
const LEGACY = { proxy: servers[0].tag, all: servers[0].tag, bypass: 'direct', off: 'direct' };
function target(value, where, rules) {
	value = LEGACY[value] ?? value;
	if (value == 'direct' || (rules && value == 'rules'))
		return value;
	if (length(filter(servers, (s) => s.tag == value)))
		return value;
	if (disabled[value]) {
		warn(`edup: ${where} uses the disabled server ${value}; its traffic goes direct\n`);
		return 'direct';
	}
	fail(`${where}: unknown server "${value}"`);
}

const routes = [];
uci.foreach('edup', 'device', (s) => {
	if (s.enabled == '0' || !length(s.ip))
		return;
	push(routes, { from: s.ip, to: target(s.mode ?? 'rules', `device ${s.name ?? s.ip}`, true) });
});
const lan_mode = target(main.lan_mode ?? 'rules', 'other devices', true);
if (lan_mode != 'rules') {
	const network = subnet(main.lan_network ?? 'lan');
	if (network)
		push(routes, { from: network, to: lan_mode });
	else
		warn(`edup: no IPv4 subnet on network ${main.lan_network ?? 'lan'}; "other devices" mode not applied\n`);
}
uci.foreach('edup', 'rule', (s) => {
	if (s.enabled == '0')
		return;
	const name = s.name ?? s['.name'];
	const rule = {};
	for (let field in [ 'ip', 'domain', 'domain_suffix', 'domain_keyword' ])
		if (length(list(s[field])))
			rule[field] = list(s[field]);
	if (length(list(s.ruleset)))
		rule.rules = list(s.ruleset);
	if (!length(rule)) {
		warn(`edup: skipping traffic rule ${name} without addresses, domains or rule-sets\n`);
		return;
	}
	rule.to = target(s.to ?? servers[0].tag, `traffic rule ${name}`, false);
	push(routes, rule);
});

// "0" or empty: the traffic rules decide; "1": the default route's server.
let dns_proxy = main.dns_proxy ?? '0';
if (dns_proxy == '1')
	dns_proxy = true;
else if (dns_proxy == '0' || dns_proxy == '')
	dns_proxy = false;
else if ((dns_proxy = target(dns_proxy, 'DNS', false)) == 'direct')
	dns_proxy = false;

const config = {
	mode: 'xdp',
	xdp_mode: main.xdp_mode ?? 'auto',
	servers: servers,
	tunnel_ip: main.tunnel_ip ?? '10.66.0.1',
	interface: main.interface ?? 'edup0',
	mtu: int(main.mtu ?? 1465),
	keepalive_secs: int(main.keepalive ?? 15),
	routing: {
		default_route: target(main.default_route ?? servers[0].tag, 'everything else', false),
		routes: routes,
	},
	dns: {
		servers: list(main.dns_server),
		set_system: main.dns_set_system != '0',
		proxy: dns_proxy,
		// dnsmasq binds port 53 on every address, the tunnel's too.
		port: int(main.dns_port ?? 10053),
	},
};
const core = { ...config, routing: { ...config.routing, routes: filter(routes, (r) => !r.from) } };

const output = ARGV[0] ?? '/var/etc/edup/client.json';
const core_output = ARGV[1] ?? '/var/etc/edup/core.json';
fs.mkdir('/var/etc/edup');
// Both files hold the passwords.
for (let entry in [ [ output, sprintf('%.J\n', config) ], [ core_output, sprintf('%J\n', core) ] ]) {
	// The mode applies to new files only.
	fs.unlink(entry[0]);
	const file = fs.open(entry[0], 'w', 0600);
	if (!file)
		fail(`cannot write ${entry[0]}: ${fs.error()}`);
	file.write(entry[1]);
	file.close();
}
