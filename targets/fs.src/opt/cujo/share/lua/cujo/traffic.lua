--
-- This file is Confidential Information of Cujo LLC.
-- Copyright (c) 2017 CUJO LLC. All rights reserved.
--
local chains = {}
local setters = {}
local flushers = {}
local trafficprefix = 'nf_traffic_'

for net in pairs(cujo.config.nets) do
	chains[net] = {}

	for _, entries in ipairs{
		{'synonlyin', 'fwdin'},
		{'synonlyout', 'fwdout'},
		{'nonsynin', 'fwdin'},
		{'nonsynout', 'fwdout'},
		{'appdata', 'locout', 'fwdout'},
	} do
		local name = entries[1]
		local chain = cujo.iptables.new{net = net,
			table = cujo.config.chain_table, name = 'TRAFFIC_' .. name:upper()}
		chains[net][name] = chain
		for _, mainchain in ipairs{select(2, table.unpack(entries))} do
			cujo.nf.addrule(net, mainchain, {target = chain})
		end
	end
end

local function appendtcpfuncrule(net, name, flags, funcs)
	for _, dir in ipairs({'in', 'out'}) do
		for _, flag in pairs(flags[dir]) do
			chains[net][name .. dir]:append{
				{'tcp', flags = flag},
				{'func', funcs[dir], target = 'return'},
			}
		end
	end
end

local function appendnewconnrule(net, name, proto)
	for _, dir in pairs({'in', 'out'}) do
		chains[net][name .. dir]:append{
			{proto},
			{'conntrack', states = {'new'}},
			{'func', 'nf_traffic_new'},
		}
	end
end

function setters.synonly(net)
	local name = 'synonly'
	local flags = {}
	local funcs = {}
	flags['out'] = {{syn = true, ack = false}}
	flags['in'] = {{syn = true}}
	funcs['out'] = trafficprefix .. name .. 'out'
	funcs['in'] = trafficprefix .. 'tcp'
	appendnewconnrule(net, name, 'tcp')
	appendtcpfuncrule(net, name, flags, funcs)
end

function setters.nonsyn(net)
	local name = 'nonsyn'
	local flags = {}
	local funcs = {}
	flags['out'] = {{psh = true}, {fin = true}, {rst = true}, {syn = true, ack = true}}
	flags['in'] = {{psh = true}, {fin = true}, {rst = true}}
	funcs['out'] = trafficprefix .. name .. 'out'
	funcs['in'] = trafficprefix .. 'tcp'
	appendnewconnrule(net, name, 'udp')
	appendtcpfuncrule(net, name, flags, funcs)
	chains[net][name .. 'in']:append{
		{'udp'},
		{'func', 'nf_traffic_udp'},
	}
	chains[net][name .. 'out']:append{
		{'udp'},
		{'func', 'nf_traffic_udpout'},
	}
end

function setters.appdata(net)
	chains[net]['appdata']:append{{'udp', src = 53}, {'func', 'nf_dnscache'}}
end

function flushers.synonly(net)
	chains[net]['synonlyin']:flush()
	chains[net]['synonlyout']:flush()
end

function flushers.nonsyn(net)
	chains[net]['nonsynin']:flush()
	chains[net]['nonsynout']:flush()
end

function flushers.appdata(net)
	chains[net]['appdata']:flush()
end

local indexes = {}
local setlevel
do
	local levels = {false, 'synonly', 'nonsyn', 'appdata'}
	for i, level in ipairs(levels) do indexes[level] = i end

	local level = indexes[false]
	function setlevel(newlevel)
		newlevel = assert(indexes[newlevel], 'invalid level')
		for net in pairs(cujo.config.nets) do
			if newlevel > level then
				for i = level + 1, newlevel do
					local level = levels[i]
					setters[level](net)
				end
			else
				for i = level, newlevel + 1, -1 do
					local level = levels[i]
					flushers[level](net)
				end
			end
		end
		level = newlevel
	end
end

local level = 'synonly'
cujo.traffic = {
	flows = cujo.util.createpublisher(),
	enable = cujo.util.createenabler(function (self, enable)
		self.enabled = enable
		setlevel(enable and level)
	end),
}

function cujo.traffic.setlevel(newlevel)
	assert(newlevel and indexes[newlevel], 'invalid level')
	if cujo.traffic.enable:get() then setlevel(newlevel) end
	cujo.nf.dostring(string.format('traffic.setlevel(%q)', newlevel))
	level = newlevel
end

cujo.nf.subscribe('traffic', cujo.traffic.flows)
