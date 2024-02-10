--
-- This file is Confidential Information of Cujo LLC.
-- Copyright (c) 2018 CUJO LLC. All rights reserved.
--
local sets = {}
for net in pairs(cujo.config.nets) do
	local set = cujo.ipset.new{name = 'access_' .. net, type = net}
	for chain, dir in pairs{fwdin = 'dst', fwdout = 'src'} do
		cujo.nf.addrule(net, chain, {{'set', set, dir}, target = 'drop'})
	end
	sets[net] = set
end

cujo.access = {}

function cujo.access.set(ip, add)
	local v = cujo.util.ipv(ip)
	if not v then
		return cujo.log:error("access invalid ip '", ip, "'")
	end
	sets['ip' .. v]:set(add, ip)
end

function cujo.access.flush()
	for _, set in ipairs(sets) do set:flush() end
end

cujo.access.flush()
