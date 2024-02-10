--
-- This file is Confidential Information of Cujo LLC.
-- Copyright (c) 2018 CUJO LLC. All rights reserved.
--
local set = cujo.ipset.new{name = 'quarantine', type = 'mac'}

cujo.quarantine = {}

function cujo.quarantine.set(mac, add) set:set(add, mac) end
function cujo.quarantine.flush() set:flush() end

cujo.quarantine.flush()

for chain, dir in pairs{fwdin = 'src', fwdout = 'dst', locin = 'src'} do
	for net in pairs(cujo.config.nets) do
		cujo.nf.addrule(net, chain, {{'set', set, dir}, target = 'drop'})
	end
end
