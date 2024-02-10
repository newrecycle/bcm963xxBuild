--
-- This file is Confidential Information of Cujo LLC.
-- Copyright (c) 2017-2019 CUJO LLC. All rights reserved.
--
local ssdpaddr4 = '239.255.255.250'
local ssdpaddr6 = 'ff02::c'
local ssdpport = 1900
local remaining
local chains = {}
local sockets = {}
local active = false
cujo.ssdp = {reply = cujo.util.createpublisher()}

for net in pairs(cujo.config.nets) do
	local chain = cujo.iptables.new{
		net = net, table = cujo.config.chain_table, name = 'SSDP'}
	cujo.nf.addrule(net, 'locin', {target = chain})
	chains[net] = chain
end

local function response(msg)
	if not active then return end
	local payload = base64.encode(msg.payload)
	remaining = remaining - #payload
	cujo.log:scan('SSDP reply received from ', msg.ip, ' (', remaining,
		' bytes left)')
	cujo.ssdp.reply(msg.ip, msg.mac, payload)
	if remaining <= 0 then
		cujo.ssdp.cancel()
	end
end

local function getlanips()
	local ips = {}
	for _, iface in pairs(cujo.config.lan_ifaces) do
		local ipv4 = assert(io.popen(cujo.config.ip .. ' -4 a s ' .. iface)):read'a'
		if ipv4 ~= nil then
			ipv4 = ipv4:match'inet (.-)/[0-9]-'
		else
			cujo.log:warn('No IPv4 address on "', iface, '"? Skipping SSDP scan')
		end
		local ipv6 = assert(io.popen(cujo.config.ip .. ' -6 a s ' .. iface)):read'a'
		if ipv6 ~= nil then
			ipv6 = ipv6:match'inet6 (.-)/[0-9]- scope global'
		else
			cujo.log:warn('No IPv6 address on "', iface, '"? Skipping SSDP scan')
		end
		ips[iface] = {ipv4 = ipv4, ipv6 = ipv6}
	end
	return ips
end

local function sendscan(iface, ifaceip, timeout)
	local sock, err, dstaddr, chain
	local ipv6 = ifaceip:find':'
	if ipv6 then
		sock, err = socket.udp6()
		dstaddr = ssdpaddr6
		chain = chains['ip6']
	else
		sock, err = socket.udp()
		dstaddr = ssdpaddr4
		chain = chains['ip4']
	end
	if sock == nil then return err end

	local ok, err = sock:setsockname(ifaceip, 0)
	if not ok then return err end
	local port = select(2, sock:getsockname())
	cujo.log:scan('SSDP reply port is ', port, ' iface is ', iface)
	table.insert(sockets, sock)
	chain:append{{'udp', dst = port}, {'input', iface}, {'func', 'nf_ssdp'},
		target = 'drop'}

	local host = ipv6 and '[' .. dstaddr .. ']' or dstaddr
	local msg = 'M-SEARCH * HTTP/1.1\r\n' ..
	            'HOST: ' .. host .. ':' .. ssdpport .. '\r\n' ..
	            'MAN: "ssdp:discover"\r\n' ..
	            'MX: ' .. timeout .. '\r\n' ..
	            'ST: ssdp:all\r\n\r\n'
	local res, err = sock:sendto(msg, dstaddr, ssdpport)
	if not res then return err end

	cujo.log:scan('SSDP request sent (timeout=', timeout, '), waiting replies')
end

function cujo.ssdp.cancel()
	if not active then return end
	active = false
	for _, chain in pairs(chains) do
		chain:flush()
	end
	for _, sock in ipairs(sockets) do
		sock:close()
	end
	sockets = {}
	event.emitall(cujo.ssdp.cancel)
	cujo.log:scan'done waiting SSDP replies'
end

function cujo.ssdp.scan(timeout, maxsize)
	remaining = maxsize
	cujo.ssdp.cancel()
	active = true
	cujo.jobs.spawn(function()
		for iface, ips in pairs(getlanips()) do
			for _, ip in pairs(ips) do
				if ip ~= nil then
					sendscan(iface, ip, timeout)
				end
			end
		end
		if time.sleep(timeout, cujo.ssdp.cancel) ~= cujo.ssdp.cancel then
			cujo.ssdp.cancel()
		end
	end)
end

cujo.nf.subscribe('ssdp', response)
