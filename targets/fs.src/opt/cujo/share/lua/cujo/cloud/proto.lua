--
-- This file is Confidential Information of Cujo LLC.
-- Copyright (c) 2018 CUJO LLC. All rights reserved.
--
local module = {}

function module.status(channel, body)
	cujo.log:warn('agent status ', body.status)
	if body.status == 'ACTIVE' then cujo.cloud.send('resync', {}) end
end

local rules = {}

function module.access(channel, body)
	for _, rule in ipairs(body.add) do
		if rules[rule.id] then
			cujo.log:access('rule id ', rule.id, ' already in set')
		else
			local ip = cujo.util.ispublic(rule.source.ip) or
			           cujo.util.ispublic(rule.destination.ip)
			if not ip then
				cujo.log:access("ip for '", rule.id,
					"' is private and can't be added.")
			else
				cujo.access.set(ip, true)
				rules[rule.id] = ip
			end
		end
	end
	for _, id in ipairs(body.remove) do
		local ip = rules[id]
		if not ip then
			cujo.log:access("'", id, "', did not match any ip.")
		else
			cujo.access.set(ip, false)
		end
		rules[id] = nil
	end
	local ids = {}
	for savedid, _ in pairs(rules) do table.insert(ids, savedid) end
	cujo.cloud.send('access', {rules = ids})
end

local cloudtolog = {
	['']      = 0,
	alert     = 1,
	critical  = 1,
	emergence = 1,
	error     = 1,
	warning   = 2,
	notice    = 3,
	info      = 3,
	debug     = 4,
}

cujo.traffic.flows:subscribe(function (message)
	local flow = {start = message.startsec, startMsec = message.startmsec,
		['end'] = message.endsec, endMsec = message.endmsec}
	local flows = {}
	for _, v in ipairs(message.flows) do
		flow.ipProtocol = v.proto
		flow.gquicUa = v.gquicua
		flow.sslSni = v.sslsni
		flow.httpUserAgent = v.httpuseragent
		flow.httpUrl = v.httpurl
		local function addflow(entry)
			flows[#flows + 1] = tabop.copy(flow, entry)
		end
		local src = {
			ip = v.srcip,
			mac = v.srcmac,
			port = v.srcport,
			name = v.srcname,
		}
		local dst = {
			ip = v.dstip,
			mac = v.dstmac,
			port = v.dstport,
			name = v.dstname,
		}
		addflow{
			source = src,
			destination = dst,
			packets = v.opackets,
			size = v.osize,
			tcpFlags = v.oflags,
			tcpInitiator = v.osnack,
		}
		addflow{
			source = dst,
			destination = src,
			packets = v.ipackets,
			size = v.isize,
			tcpFlags = v.iflags,
			tcpInitiator = v.isnack,
		}
	end
	cujo.cloud.send('traffic-messages', flows)
end)

module['safebro-config'] = function (channel, body)
	cujo.safebro.configure(body)
end

cujo.safebro.threat:subscribe(function (message)
	cujo.cloud.send('threat', message)
end)

function module.scan(channel, body)
	if body.protocol ~= 'ssdp' then
		return cujo.log:error('invalid device scan protocol: ', body.protocol)
	end
	local err = cujo.ssdp.scan(body.timeout or 180,
		body.maxsize or 16 * 4096)
	if err then return cujo.log:error('SSDP scan error: ', err) end
end

cujo.ssdp.reply:subscribe(function (ip, mac, payload)
	cujo.cloud.send('scan', {
		protocol = 'ssdp', payload = payload, ip = ip, mac = mac
	})
end)

function module.hibernate(channel, body)
	cujo.hibernate.sleep(body.duration * 60)
end

function module.status_update(channel, body)
	cujo.log:status_update('mac=', body.mac,
			       ' status=', body.active,
			       ' monitored=', body.monitored,
			       ' secured=', body.secured,
			       ' safebro=', body.safe_browsing,
			       ' fingerprint=', body.fingerprint)
	if not body.mac:match('^%x%x:%x%x:%x%x:%x%x:%x%x:%x%x$') then
		cujo.log:warn('status_update: ignoring invalid mac address ', body.mac)
		return
	end
	if body.mac == '00:00:00:00:00:00' then
		return cujo.log:warn('status_update: ignoring null mac')
	end
	cujo.safebro.setbypass(body.mac, not body.safe_browsing)
	cujo.quarantine.set(body.mac, body.active)
	cujo.fingerprint.set(body.mac, not body.fingerprint)
end

function module.http_fetch(channel, body)
	local data, status, httphdrs = cujo.https.request{
		url = body.url,
		redirect = true,
		create = cujo.https.connector.simple(nil, timeout)
	}
	if not data then
		return cujo.log:warn('http request failed: ', body.url,
			', responded with code ', status, "'")
	end
	body.payload = base64.encode(data)
	body.mimetype = httphdrs['content-type'] or ''
	body.context = body.context or {}
	cujo.cloud.send('http_response', body)
end

module['app-block'] = function (channel, body)
	for _, add in ipairs{true, false} do
		for _, v in ipairs(body[add and 'add' or 'del'] or {}) do
			cujo.appblock[v.expires and 'timed' or 'main'].set(
				body.mac, v.ip, v.protocol, v.port, add)
		end
	end
end

module['app-block-reset'] = function (channel, body)
	assert(body.expirationDelay >= 0,
		'invalid expirationDelay, must be non negative.')
	assert(body.expirationPeriod >= 60,
		'invalid expirationPeriod, must be a minute or larger.')
	cujo.appblock.main.flush()
	cujo.appblock.timed.reset(body.expirationDelay, body.expirationPeriod)
end

for pub, tap in pairs{
	dhcp = 'dhcp', dns = 'dns', mdns = 'mdns', http = 'httpsig', tcp = 'tcpsig',
} do
	cujo.fingerprint[pub]:subscribe(function (msg) cujo.cloud.send(tap, msg) end)
end

return module
