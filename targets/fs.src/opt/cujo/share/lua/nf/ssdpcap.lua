--
-- This file is Confidential Information of Cujo LLC.
-- Copyright (c) 2019 CUJO LLC. All rights reserved.
--

function nf_ssdp(frame, packet)
	local mac = nf.mac(frame)
	local ip = nf.ip(packet)

	if mac.src ~= 0 then
		local udp, payload = nf.udp(ip)
		if payload then
			local payload = tostring(payload)
			local ok, err = pcall(command, 'ssdp', {
				mac = nf.tomac(mac.src),
				ip = nf.toip(ip.src),
				payload = payload,
			})
			if not ok then
				print(string.format("nflua: 'nf_ssdp' failed to send netlink msg 'ssdp': %s", err))
			end
		end
	end

	return true -- DROP
end