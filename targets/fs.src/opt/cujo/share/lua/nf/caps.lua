--
-- This file is Confidential Information of Cujo LLC.
-- Copyright (c) 2018 CUJO LLC. All rights reserved.
--
local function capture(frame, packet, channel)
	local mac = nf.mac(frame)
	local ip = nf.ip(packet)
	local udp, payload = nf.udp(ip)

	local packet = {
		source = {
			port = udp.sport,
			mac = nf.tomac(mac.src),
			ip = nf.toip(ip.src),
		},
		destination = {
			port = udp.dport,
			mac = nf.tomac(mac.dst),
			ip = nf.toip(ip.dst),
		},
		payload = base64.encode(tostring(payload)),
	}

	local ok, err = pcall(command, channel, packet)
	if not ok then
		print(string.format("nflua: 'capture' failed to send netlink msg '%s': %s", channel, err))
	end
	return false
end

for name, proto in pairs{nf_dhcp = 'dhcp', nf_dns = 'dns', nf_mdns = 'mdns'} do
	_G[name] = function (frame, packet) return capture(frame, packet, proto) end
end
