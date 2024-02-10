--
-- This file is Confidential Information of Cujo LLC.
-- Copyright (c) 2019 CUJO LLC. All rights reserved.
--

cujo.snoopy = {}

function cujo.snoopy.getdevaddripv6(ifaces)
	local last_non_2000_match = nil
	for _, iface in ipairs(ifaces) do
		local cmd = string.format('ip -6 a s %s | grep "inet6 .* scope global"', iface)
		local cmd_output = assert(io.popen(cmd, 'r'))
		local res = cmd_output:read'a'
		io.close(cmd_output)
		if res ~= nil then
			local match = string.match(res, 'inet6 (2[0-9a-f:/]*)')
			if match ~= nil then
				return match
			end
			match = string.match(res, 'inet6 ([0-9a-f:/]*)')
			if match ~= nil then
				last_non_2000_match = match
			end
		end
	end
	return last_non_2000_match
end
