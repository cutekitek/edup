'use strict';
'require view';
'require form';
'require uci';

const LISTS = [
	[ 'ip', _('Addresses') ],
	[ 'domain', _('Domains') ],
	[ 'domain_suffix', _('Domain suffixes') ],
	[ 'domain_keyword', _('Domain keywords') ],
	[ 'ruleset', _('Rule-sets') ]
];

function items(section_id, option) {
	const value = uci.get('edup', section_id, option);
	return Array.isArray(value) ? value : (value ? [ value ] : []);
}

return view.extend({
	load() {
		return uci.load('edup');
	},

	render() {
		const m = new form.Map('edup', _('edup VPN: traffic rules'),
			_('Traffic rules decide by destination for the router itself and for devices set to "Traffic rules". ' +
			  'The first rule matching a destination address or name decides; put exceptions before broader rules. ' +
			  'Domain rules work through the router\'s DNS, so devices must use it and not DNS over HTTPS.'));

		let s = m.section(form.NamedSection, 'main', 'edup');
		let o = s.option(form.ListValue, 'default_route', _('Everything else'),
			_('Destinations that no rule matches.'));
		o.value('proxy', _('VPN'));
		o.value('bypass', _('Direct'));
		o.default = 'proxy';

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
		o.value('proxy', _('VPN'));
		o.value('bypass', _('Direct'));
		o.default = 'bypass';
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
			_('sing-box binary rule-sets (.srs), GeoIP or geosite: an http(s) URL, downloaded at every start.'));
		o.placeholder = 'https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-ru.srs';
		o.modalonly = true;

		return m.render();
	}
});
