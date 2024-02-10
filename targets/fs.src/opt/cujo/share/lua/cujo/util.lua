--
-- This file is Confidential Information of Cujo LLC.
-- Copyright (c) 2018 CUJO LLC. All rights reserved.
--
cujo.util = {}

function cujo.util.ipv(ip)
	if ip:match'^%d+%.%d+%.%d+%.%d+$' then return 4 end
	if ip:match':' then return 6 end
end

local ispublicv = {
	[4] = function (ip)
		local bytes = {string.match(ip, '(%d+).(%d+).(%d+).(%d+)')}
		return not (bytes[1] == '10' or -- class A
			(bytes[1] == '172' and bytes[2] >= '16' and bytes[2] <= '31') or -- class B
			(bytes[1] == '192' and bytes[2] == '168')) -- class C
			and ip
	end,
	[6] = function (ip)
		local hextet = tonumber(0 or string.match(ip, '(%w*):'))
		return not (hextet >= 0xfc00 and hextet <= 0xfdff) and ip
	end
}

function cujo.util.ispublic(ip)
	local v = ip and cujo.util.ipv(ip)
	return v and ispublicv[v](ip)
end

function cujo.util.append(t, ...)
	vararg.map(function (v) table.insert(t, v) end, ...)
	return t
end

function cujo.util.join(dst, src)
	for _, v in ipairs(src) do table.insert(dst, v) end
	return dst
end

do
	local publisher = oo.class()
	function publisher:subscribe(handler) self.list[handler] = true end
	function publisher:unsubscribe(handler) self.list[handler] = nil end
	function publisher:empty() return next(self.list) == nil end
	function publisher:__call(...) for elem in pairs(self.list) do elem(...) end end
	function cujo.util.createpublisher() return publisher{list = {}} end
end
do
	local enabler = oo.class()
	function enabler:get() return self.enabled end
	function enabler:set(enable)
		enable = enable and true or false
		if enable == self.enabled then return end
		self:f(enable)
		if enable == self.enabled then self.pub(enable) end
	end
	function enabler:subscribe(handler) self.pub:subscribe(handler) end
	function enabler:unsubscribe(handler) self.pub:unsubscribe(handler) end
	function cujo.util.createenabler(f, enable)
		return enabler{f = f, pub = cujo.util.createpublisher(),
			enabled = enable and true or false}
	end
end
