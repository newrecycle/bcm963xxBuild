--
-- This file is Confidential Information of Cujo LLC.
-- Copyright 2018 (C) CUJO LLC. All rights reserved.
--
local flows = {}
local synouts = {}
local entries = 0
local startsec, startmsec
local appdata = lru.new(config.traffic.appdata.maxentries)
local level = 'synonly'

traffic = {}

local function flush(sec, msec, connid)
	local pack = {}
	for k, v in pairs(flows) do
		if v.srcmac and v.dstmac or v.proto == nf.proto.udp then
			pack[#pack + 1] = v
			flows[k] = nil
			entries = entries - 1
		end
	end
	if flows[connid] then
		flows[connid] = nil
		entries = entries - 1
	end
	if entries >= config.traffic.maxentries then
		flows = {}
		entries = 0
	end
	if #pack > 0 then
		local ok, err = pcall(command, 'traffic', {
			flows = pack,
			startsec = startsec,
			startmsec = startmsec,
			endsec = sec,
			endmsec = msec,
		})
		if not ok then
			print(string.format("nflua: 'flush' failed to send netlink msg 'traffic': %s", err))
		end
	end
end

local function checkflush(flow)
	local sec, msec = nf.time()
	if entries >= config.traffic.maxentries or
			sec - startsec >= config.traffic.timeout or
			flow.isize + flow.osize >= config.traffic.maxflowsize then
		flush(sec, msec)
	end
end

local function regflow(proto, frame, ip, dstport, srcport, key, flags, snack)
	local srcip, dstip = ip.src, ip.dst
	local inputdir = srcip > dstip or (srcip == dstip and srcport > dstport)
	local tcpflagsyn = 2
	if inputdir then
		srcip, dstip = dstip, srcip
		srcport, dstport = dstport, srcport
	end

	local flow = flows[key]
	if not flow then
		flow = {
			proto = proto,
			srcname = nf.getdnscache(srcip),
			srcip = nf.toip(srcip),
			srcport = srcport,
			dstip = nf.toip(dstip),
			dstport = dstport,
			dstname = nf.getdnscache(dstip),
			iflags = flags and 0,
			oflags = flags and 0,
			isnack = snack and 0,
			osnack = snack and 0,
			isize = 0,
			osize = 0,
			ipackets = 0,
			opackets = 0,
		}
		if entries == 0 then startsec, startmsec = nf.time() end
		entries = entries + 1
		flows[key] = flow
	end
	if frame then
		local mac = nf.mac(frame)
		local srcmac, dstmac = mac.src, mac.dst
		if inputdir then srcmac, dstmac = dstmac, srcmac end
		flow.dstmac = flow.dstmac or nf.tomac(dstmac)
		flow.srcmac = flow.srcmac or nf.tomac(srcmac)
	end
	if level == 'synonly' and flags ~= tcpflagsyn then
		checkflush(flow)
		return false -- ALLOW
	end

	if appdata[key] then
		flow.sslsni = flow.sslsni or appdata[key].sslsni
		flow.httpurl = flow.httpurl or appdata[key].httpurl
		flow.httpuseragent = flow.httpuseragent or appdata[key].httpua
		flow.gquicua = flow.gquicua or appdata[key].gquicua
	end
	local dir = inputdir and 'i' or 'o'
	local sizef, pktf = dir .. 'size', dir .. 'packets'
	flow[sizef] = flow[sizef] + ip.tot_len
	flow[pktf] = flow[pktf] + 1
	if flags ~= nil then
		local flagsf, snackf = dir .. 'flags', dir .. 'snack'
		flow[flagsf] = flow[flagsf] | flags
		flow[snackf] = flow[snackf] | snack
	end

	checkflush(flow)
	return false -- ALLOW
end

local tcp_app_extract = {}

function tcp_app_extract.sslsni(entry, payload)
	local segpayload = payload:layout(ssl.layout)
	if ssl.is_client_hello(segpayload) then
		entry.sslsni = ssl.extract_hostname(segpayload)
		return true
	end
end

function tcp_app_extract.httpurl(entry, payload)
	local request = tostring(payload)
	local method, path, host = http.headerinfo(request)
	if method == 'GET' and host then
		entry.httpurl = host .. path
		entry.httpua = string.match(request, '.*User%-Agent: *([^\r\n]*)\r?\n')
		return true
	end
end

local function fillgquiccache(key, payload, publicsrc)
	if not payload then return false end
	appdata[key] = appdata[key] or {}
	appdata[key].sslsni, appdata[key].gquicua = gquic.parse(payload, publicsrc)
end

function nf_traffic_new()
	local key = nf.connid()
	local sec, msec = nf.time()
	appdata[key] = nil
	if flows[key] then
		flush(sec, msec, key)
	end
end

function nf_traffic_tcp(frame, packet)
	local ip = nf.ip(packet)
	local tcp, payload = nf.tcp(ip)
	local key = nf.connid()
	if payload and level == 'appdata' then
		local entry = appdata[key]
		if entry == nil then
			entry = {}
			appdata[key] = entry
		end
		for field, extract in pairs(tcp_app_extract) do
			if entry[field] == nil then
				if extract(entry, payload) then break end
			end
		end
	end
	return regflow(nf.proto.tcp, frame, ip, tcp.dport, tcp.sport, key,
		tcp.flags, tcp.syn ~= 0 and tcp.ack == 0 and 1 or 0)
end

function nf_traffic_synonlyout(frame, packet)
	return nf_traffic_tcp(nil, packet)
end

function nf_traffic_nonsynout(frame, packet)
	return nf_traffic_tcp(nil, packet)
end

function nf_traffic_udp(frame, packet)
	local ip = nf.ip(packet)
	local udp, payload = nf.udp(ip)
	local key = nf.connid()
	if level == 'appdata' then
		fillgquiccache(key, payload, nf.ispublic[ip.version](ip.src))
	end
	return regflow(nf.proto.udp, frame, ip, udp.dport, udp.sport, key)
end

function nf_traffic_udpout(frame, packet)
	nf_traffic_udp(nil, packet)
end

function traffic.setlevel(newlevel) level = newlevel end
