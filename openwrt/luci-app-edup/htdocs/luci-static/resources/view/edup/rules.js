'use strict';
'require view';
'require form';
'require fs';
'require request';
'require rpc';
'require uci';
'require ui';

const LISTS = [
	[ 'ip', _('Addresses') ],
	[ 'domain', _('Domains') ],
	[ 'domain_suffix', _('Domain suffixes') ],
	[ 'domain_keyword', _('Domain keywords') ],
	[ 'ruleset', _('Rule-sets') ]
];

// Uploaded rule-sets; kept across firmware upgrades.
const DIR = '/etc/edup/rule-sets';
// edup-client reads at most this much of a rule-set.
const MAX_SIZE = 64 * 1024 * 1024;

function items(section_id, option) {
	const value = uci.get('edup', section_id, option);
	return Array.isArray(value) ? value : (value ? [ value ] : []);
}

// Each server, then direct.
function routes(o) {
	const servers = uci.sections('edup', 'server').map((s) => s['.name']);
	servers.forEach((name) => o.value(name, _('VPN: %s').format(name)));
	o.value('direct', _('Direct'));
	return servers;
}

function listFiles() {
	return L.resolveDefault(fs.list(DIR), []).then((entries) => entries
		.filter((e) => e.type == 'file' && !e.name.startsWith('.'))
		.sort((a, b) => a.name.localeCompare(b.name)));
}

// Names of the rules whose rule-sets include `path`.
function usedBy(path) {
	return uci.sections('edup', 'rule')
		.filter((s) => items(s['.name'], 'ruleset').includes(path))
		.map((s) => s.name ?? s['.name']);
}

// Lets the user pick a .srs file and uploads it into DIR. Resolves to its
// path on the router; stays pending when the user cancels.
function chooseAndUpload() {
	return new Promise((resolve, reject) => {
		const input = E('input', { 'type': 'file', 'accept': '.srs', 'style': 'display:none' });
		input.addEventListener('change', () => {
			input.remove();
			const file = input.files[0];
			if (file)
				upload(file).then(resolve, reject);
		});
		document.body.appendChild(input);
		input.click();
	}).catch((error) => {
		ui.addNotification(null, E('p', _('Upload failed: %s').format(error.message ?? error)), 'error');
		throw error;
	});
}

function upload(file) {
	let name = file.name.replace(/[^A-Za-z0-9._-]/g, '_').replace(/^\.+/, '');
	if (!/\.srs$/i.test(name))
		name += '.srs';
	const path = '%s/%s'.format(DIR, name);
	if (file.size > MAX_SIZE)
		return Promise.reject(new Error(_('%s is larger than 64 MiB').format(file.name)));
	return file.slice(0, 3).arrayBuffer().then((head) => {
		if (String.fromCharCode(...new Uint8Array(head)) != 'SRS')
			throw new Error(_('%s is not a sing-box binary rule-set (.srs)').format(file.name));
		// As ui.uploadFile, without its dialog: the name comes from the file.
		const data = new FormData();
		data.append('sessionid', rpc.getSessionID());
		data.append('filename', path);
		data.append('filedata', file);
		return request.post(L.env.cgi_base + '/cgi-upload', data, { timeout: 0 });
	}).then((res) => {
		let reply = null;
		try { reply = res.json(); } catch (e) {}
		if (!res.ok || reply?.failure)
			throw new Error(reply?.message ?? res.statusText ?? _('HTTP error %d').format(res.status));
		ui.addNotification(null, E('p', _('Uploaded %s. A replaced file takes effect when the service restarts.').format(path)), 'info');
		return path;
	});
}

return view.extend({
	load() {
		return Promise.all([ uci.load('edup'), listFiles() ]);
	},

	renderFiles(files) {
		const rows = files.map((file) => {
			const path = '%s/%s'.format(DIR, file.name);
			const users = usedBy(path);
			return E('tr', { 'class': 'tr' }, [
				E('td', { 'class': 'td' }, path),
				E('td', { 'class': 'td' }, '%1024.1mB'.format(file.size)),
				E('td', { 'class': 'td' }, users.length ? users.join(', ') : _('unused')),
				E('td', { 'class': 'td cbi-section-actions' }, E('button', {
					'class': 'cbi-button cbi-button-remove',
					'disabled': users.length ? '' : null,
					'title': users.length ? _('Remove it from these rules first') : null,
					'click': ui.createHandlerFn(this, () => fs.remove(path)
						.then(() => this.refreshFiles())
						.catch((e) => ui.addNotification(null, E('p', e.message), 'error')))
				}, _('Delete')))
			]);
		});
		return E('table', { 'class': 'table' }, [
			E('tr', { 'class': 'tr table-titles' }, [
				E('th', { 'class': 'th' }, _('File')),
				E('th', { 'class': 'th' }, _('Size')),
				E('th', { 'class': 'th' }, _('Used by')),
				E('th', { 'class': 'th' })
			]),
			...(rows.length ? rows : [ E('tr', { 'class': 'tr placeholder' },
				E('td', { 'class': 'td' }, E('em', _('No files uploaded.')))) ])
		]);
	},

	refreshFiles() {
		return listFiles().then((files) =>
			document.getElementById('edup-rule-sets')?.replaceChildren(this.renderFiles(files)));
	},

	render([ , files ]) {
		const m = new form.Map('edup', _('edup VPN: traffic rules'),
			_('Traffic rules decide by destination for the router itself and for devices set to "Traffic rules": through one of the servers, or direct. ' +
			  'The first rule matching a destination address or name decides; put exceptions before broader rules. ' +
			  'Domain rules work through the router\'s DNS, so devices must use it and not DNS over HTTPS.'));

		let s = m.section(form.NamedSection, 'main', 'edup');
		let o = s.option(form.ListValue, 'default_route', _('Everything else'),
			_('Destinations that no rule matches.'));
		o.default = routes(o)[0] ?? 'direct';
		o.rmempty = false;

		s = m.section(form.GridSection, 'rule', _('Rules'));
		s.addremove = true;
		s.anonymous = true;
		s.sortable = true;
		s.nodescriptions = true;
		s.modaltitle = _('Traffic rule');

		o = s.option(form.Flag, 'enabled', _('Enabled'));
		o.default = o.enabled;
		o.editable = true;

		o = s.option(form.Value, 'name', _('Name'));
		o.rmempty = true;

		o = s.option(form.DummyValue, '_match', _('Matches'));
		o.modalonly = false;
		o.textvalue = function(section_id) {
			const parts = LISTS
				.map(([ option, title ]) => [ title, items(section_id, option).length ])
				.filter(([ , count ]) => count > 0)
				.map(([ title, count ]) => '%s: %d'.format(title, count));
			return parts.length ? parts.join(', ') : _('nothing (ignored)');
		};

		o = s.option(form.ListValue, 'to', _('Route'));
		routes(o);
		o.default = 'direct';
		o.editable = true;

		o = s.option(form.DynamicList, 'ip', _('Addresses'),
			_('Destination addresses or networks, e.g. 203.0.113.0/24.'));
		o.datatype = 'or(ipaddr("nomask"),cidr)';
		o.modalonly = true;

		o = s.option(form.DynamicList, 'domain', _('Domains'),
			_('Exact names, e.g. example.com.'));
		o.datatype = 'hostname';
		o.modalonly = true;

		o = s.option(form.DynamicList, 'domain_suffix', _('Domain suffixes'),
			_('".ru" matches every name ending in .ru; "example.com" also matches the name itself.'));
		o.modalonly = true;

		o = s.option(form.DynamicList, 'domain_keyword', _('Domain keywords'),
			_('Text anywhere in the name.'));
		o.modalonly = true;

		o = s.option(form.DynamicList, 'ruleset', _('Rule-sets'),
			_('sing-box binary rule-sets (.srs), GeoIP or geosite: an http(s) URL, downloaded at every start, or a file on the router, such as one uploaded below.'));
		o.placeholder = 'https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-ru.srs';
		o.modalonly = true;
		files.forEach((file) => o.value('%s/%s'.format(DIR, file.name), file.name));

		o = s.option(form.DummyValue, '_upload', ' ');
		o.modalonly = true;
		o.renderWidget = function(section_id) {
			return E('button', {
				'class': 'cbi-button cbi-button-add',
				'click': (ev) => {
					ev.preventDefault();
					// Adds the uploaded file to this rule's rule-sets.
					chooseAndUpload().then((path) => {
						const list = this.map.lookupOption('ruleset', section_id)?.[0]?.getUIElement(section_id);
						if (list && !list.getValue().includes(path))
							list.setValue([ ...list.getValue(), path ]);
					}, () => {});
				}
			}, _('Upload .srs file…'));
		};

		return m.render().then((node) => {
			const upload = E('button', {
				'class': 'cbi-button cbi-button-add',
				'click': (ev) => {
					ev.preventDefault();
					chooseAndUpload().then(() => this.refreshFiles(), () => {});
				}
			}, _('Upload .srs file…'));
			node.appendChild(E('div', { 'class': 'cbi-section' }, [
				E('h3', _('Rule-set files')),
				E('div', { 'class': 'cbi-section-descr' },
					_('Rule-set files stored on the router in %s, kept across firmware upgrades. Add them to a rule in its Rule-sets.').format(DIR)),
				E('div', { 'id': 'edup-rule-sets' }, this.renderFiles(files)),
				E('div', { 'class': 'cbi-page-actions', 'style': 'text-align:left' }, upload)
			]));
			return node;
		});
	}
});
