--
-- This file is Confidential Information of Cujo LLC.
-- Copyright (c) 2018 CUJO LLC. All rights reserved.
--

conn = {}

local conns = lru.new(config.conn.maxentries)
local pending = setmetatable({}, {__mode = 'v'})

local function setstate(connid, state, data)
	if state == 'allow' then
		conns[connid] = nil
	elseif state == 'pending' then
		assert(type(data) == 'table')
		conns[connid] = data
		data._state = state
	elseif state == 'block' then
		assert(type(conns[connid]) == 'table')
		conns[connid]._state = state
	else
		conns[connid] = state
	end
end

local function getstate(connid)
	local state = conns[connid]
	if type(state) == 'table' then
		return state._state, state
	end
	return state or 'allow'
end

local function flush(connid)
	local state, data = getstate(connid)
	if state ~= 'pending' then return end

	timer.destroy(data.timer)

	local block, reason =
		safebro.filter(data.mac, data.ip, data.domain, data.path)

	if block then
		if #data.packets == 0 then
			data.reason = reason
			setstate(connid, 'block')
			timer.create(config.conn.blockttl, function()
				if getstate(connid) == 'block' then
					setstate(connid, 'drop')
				end
			end)
		else
			data.packets[1]:send(data.blockpage(reason))
			setstate(connid, 'drop')
		end
	else
		for _, packet in ipairs(data.packets) do
			packet:send()
		end
		setstate(connid, 'allow')
	end
end

function conn.filter(mac, ip, domain, path, blockpage)
	local connid = nf.connid()
	if getstate(connid) ~= 'init' then return end

	local block, reason = safebro.filter(mac, ip, domain, path)
	if block then
		nf.reply('tcp', blockpage(reason))
		setstate(connid, 'drop')
	elseif block == nil then
		local pendingref = pending[domain] or {}
		pending[domain] = pendingref
		table.insert(pendingref, connid)
		setstate(connid, 'pending', {
			mac = mac,
			ip = ip,
			domain = domain,
			path = path,
			blockpage = blockpage,
			pendingref = pendingref,
			packets = {},
			timer = timer.create(sbconfig.timeout, function()
				nf.log('safebro lookup timed out on "', domain, '"')
				flush(connid)
			end),
		})
	else
		setstate(connid, 'allow')
	end
end

function conn.cacheupdated(domain)
	local connids = pending[domain]
	if connids then
		for _, connid in ipairs(connids) do
			flush(connid)
		end
	end
end

function nf_conn_new() setstate(nf.connid(), 'init') end

function nf_drop_response(frame, packet)
	local connid = nf.connid()
	local state, data = getstate(connid)
	if state == 'init' or state == 'allow' then return false end

	if state == 'block' then
		nf.getpacket():send(data.blockpage(data.reason))
		setstate(connid, 'drop')
	elseif state == 'pending' then
		if #data.packets < 2 then
			table.insert(data.packets, nf.getpacket())
		end
	end

	return true
end
