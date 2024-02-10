--
-- This file is Confidential Information of Cujo LLC.
-- Copyright (c) 2018 CUJO LLC. All rights reserved.
--
local chains = {}
for net in pairs(cujo.config.nets) do
	local chain = cujo.iptables.new{
		net = net, table = cujo.config.chain_table, name = 'APPBLOCK',
	}
	for _, mainchain in ipairs{'fwdin', 'fwdout'} do
		cujo.nf.addrule(net, mainchain, {target = chain})
	end
	chains[net] = chain
end

local prototoint = {tcp = 6, udp = 17}

local function getid(mac, ipv, ip, proto, port)
	return string.pack(ipv == 4 and 'I6Bc4I2' or 'I6Bc16I2',
		tonumber(mac:gsub(':', ''), 16), prototoint[proto],
		cujo.net.iptobin('ipv' .. ipv, ip), port)
end

local function set(name, mac, ip, proto, port, add)
	local ipv = cujo.util.ipv(ip)
	local action = add and 'add' or 'del'
	local id = getid(mac, ipv, ip, proto, port)
	cujo.nf.dostring(string.format('appblock[%q](%q, %q)', action, name, id))
	cujo.log:appblock(action, ' ', mac, ', ', ip, ', ', proto, ', ', port,
		" in set '", name, "'")
end

local function flush(name)
	cujo.nf.dostring(string.format('appblock.flush(%q)', name))
	cujo.log:appblock("flush set '", name, "'")
end

local sets = {'main', 'timed'}
cujo.appblock = {
	enable = cujo.util.createenabler(function (self, enable)
		for _, name in pairs(sets) do flush(name) end
		for _, chain in pairs(chains) do
			chain:flush()
			if enable then
				chain:append{
					{'conntrack', states = {'new'}},
					{'func', 'nf_appblock'},
					target = 'drop'
				}
			end
		end
		self.enabled = enable
	end),
}

for _, name in ipairs(sets) do
	cujo.appblock[name] = {
		set = function (...) set(name, ...) end,
		flush = function ()  flush(name) end,
	}
	flush(name)
end

local timedreset = {}
function cujo.appblock.timed.reset(delay, period)
	event.emitone(timedreset, delay, period)
end

cujo.jobs.spawn(function()
	local delay, period
	while true do
		local ev, newdelay, newperiod = cujo.jobs.wait(delay, timedreset)
		if ev == timedreset then
			delay, period = newdelay, newperiod
			cujo.log:appblock('reset next timed flush in ' .. delay .. 's' ..
			                  ' then, every ' .. period .. 's')
		else
			delay = period
		end
		cujo.jobs.spawn(cujo.appblock.timed.flush)
	end
end)
