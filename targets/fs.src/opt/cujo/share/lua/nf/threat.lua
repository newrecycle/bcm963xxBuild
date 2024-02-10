--
-- This file is Confidential Information of Cujo LLC.
-- Copyright (c) 2017 CUJO LLC. All rights reserved.
--

threat = {}

threat.bypass    = {}
threat.known     = {}
threat.whitelist = lru.new(config.threat.whitelist.maxentries,
                           config.threat.whitelist.ttl)

local cache
local pending

function command(cmd, data)
	local msg = string.format("%s %s", cmd, json.encode(data or '{}'))
	nf.netlink(msg, config.netlink.port)
end

local function extract_domain(uri)
	return string.match(uri, "^https?://([^/]*).*$")
end

function threat.init()
	local warn = extract_domain(sbconfig.warnpage)
	local block = extract_domain(sbconfig.blockpage)

	cache   = lru.new(config.threat.cache.maxentries, sbconfig.ttl)
	pending = lru.new(config.threat.pending.maxentries, config.threat.pending.ttl)
	threat.known[warn] = true
	threat.known[block] = true
end

function threat.key(mac, domain)
	return string.format('%x:%s', mac.src, domain)
end

function threat.lookup(domain, path)
	if threat.known[domain] then return math.maxinteger end

	local entry = cache[domain]
	if not entry then
		if not pending[domain] then
			local ok, err = pcall(command, 'lookup', {domain = domain, path = path})
			if not ok then
				print(string.format("nflua: 'threat.lookup' failed to send netlink msg 'lookup': %s", err))
			end
			pending[domain] = true
		end
		return nil -- miss
	end

	return table.unpack(entry)
end

function threat.notify(message)
	local ok, err = pcall(command, 'notify', message)
	if not ok then
		print(string.format("nflua: 'threat.notify' failed to send netlink msg 'notify': %s", err))
	end
end

function threat.setresponse(domain, entry, cachedomain)
	cache[domain] = entry
	pending[domain] = nil
	conn.cacheupdated(domain)
	if not cachedomain then cache[domain] = nil end
end
