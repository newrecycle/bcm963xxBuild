--
-- This file is Confidential Information of Cujo LLC.
-- Copyright (c) 2018 CUJO LLC. All rights reserved.
--
local chains = {}
for net in pairs(cujo.config.nets) do
	local chain = cujo.iptables.new{
		net = net, table = cujo.config.chain_table, name = 'FINGERPRINT'}
	for _, mainchain in ipairs{'locin', 'fwdin'} do
		cujo.nf.addrule(net, mainchain, {target = chain})
	end
	chains[net] = chain
end
local set = cujo.ipset.new{name = 'fingerprint', type = 'mac'}
local dhcpparams = {
	ip4 = {
		src = {port = 68},
		dst = {addr = '255.255.255.255', port = 67},
	},
	ip6 = {
		src = {addr = 'fe80::/10', port = 546},
		dst = {port = 547},
	},
}
local mdnschains = {}
for net in pairs(cujo.config.nets) do
	local chain = cujo.iptables.new{net = net, table = cujo.config.chain_table,
		name = 'MDNS'}
	if cujo.config.mdns_fwdin == true then
		cujo.nf.addrule(net, 'fwdin', {target = chain})
	else
		cujo.nf.addrule(net, 'lantolan', {target = chain})
	end
	mdnschains[net] = chain
end

cujo.fingerprint = {
	enable = cujo.util.createenabler(function (self, enable)
		for net in pairs(cujo.config.nets) do
			local chain = chains[net]
			local mdnschain = mdnschains[net]
			chain:flush()
			mdnschain:flush()
			if enable then
				chain:append{{'set', set, 'src'}, target = 'return'}
				local par = dhcpparams[net]
				chain:append{
					{'src', par.src.addr},
					{'dst', par.dst.addr},
					{'udp', src = par.src.port, dst = par.dst.port},
					{'func', 'nf_dhcp'},
				}
				chain:append{{'udp', dst = 53}, {'func', 'nf_dns'}}
				chain:append{{'tcp', flags = {syn = true}}, {'func', 'nf_tcpcap'}}
				chain:append{{'tcp', dst = 80, flags = {psh = true}},
					{'func', 'nf_httpcap'}}

				mdnschain:append{{'set', set, 'src'}, target = 'return'}
				mdnschain:append{{'udp', dst = 5353}, {'func', 'nf_mdns'}}
			end
		end
		self.enabled = enable
	end),
}

function cujo.fingerprint.set(mac, add) set:set(add, mac) end
function cujo.fingerprint.flush() set:flush() end

for _, pub in ipairs{'dhcp', 'dns', 'mdns', 'http', 'tcp'} do
	cujo.fingerprint[pub] = cujo.util.createpublisher()
	cujo.nf.subscribe(pub, cujo.fingerprint[pub])
end
