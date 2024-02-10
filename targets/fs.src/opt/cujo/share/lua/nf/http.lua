--
-- This file is Confidential Information of Cujo LLC.
-- Copyright (c) 2017 CUJO LLC. All rights reserved.
--

local blocked = lru.new(config.http.maxentries, config.http.ttl)

http = {}

local function response(page, uri, salt)
	local token = salt and string.format('&token=%08x', salt) or ''
	return string.format('HTTP/1.1 302 Found\r\n' ..
		'Location: %s?url=http://%s%s\r\n' ..
		'Connection: close\r\n' ..
		'Content-Length: 0\r\n\r\n', page, uri, token)
end

local function unblockby(host, key, referer, salt)
	if referer == host and blocked[key] == tonumber(salt, 16) then
		threat.whitelist[key] = true
		blocked[key] = nil
		return true
	end
end

local function unblock(host, hostkey, request)
	local rhost, salt = string.match(request,
		'Referer: ' .. sbconfig.warnpage_escaped ..
		'%?url=http://([^/:]*)[^&]*&token=(%x*)')

	return rhost and unblockby(host, hostkey, rhost, salt)
end

local function makeblockpage(host, path, hostkey)
	return function (reason)
		local salt
		local page = sbconfig.blockpage
		if reason ~= safebro.reasons.parental then
			page = sbconfig.warnpage
			salt = math.random()
			blocked[hostkey] = salt
		end
		local uri = host .. path
		return response(page, uri, salt)
	end
end

local function whitelist(key)
	if threat.whitelist[key] then return true end
end

function http.headerinfo(request)
	return string.match(request, '([A-Z]+) ([^%s]*).-\r?\nHost: ([^\r\n]*)\r?\n')
end

function nf_http(frame, packet)
	local mac = nf.mac(frame)
	local ip = nf.ip(packet)
	local tcp, payload = nf.tcp(ip)

	if not payload or threat.bypass[mac.src] then return end

	local request = tostring(payload)
	local _, path, host = http.headerinfo(request)
	if not host then return end

	local hostkey = threat.key(mac, host)
	if whitelist(hostkey) or unblock(host, hostkey, request) then return end

	local blockpage = makeblockpage(host, path, hostkey)
	conn.filter(mac.src, ip.src, host, path, blockpage)
end
