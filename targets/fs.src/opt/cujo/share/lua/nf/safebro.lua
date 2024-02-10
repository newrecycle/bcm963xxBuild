--
-- This file is Confidential Information of Cujo LLC.
-- Copyright (c) 2016-2018 CUJO LLC. All rights reserved.
--

safebro = {}
safebro.reasons = {
	parental = 0
}

local function wildcarded(domain)
	return string.gsub(domain, '^[^%.]+%.?(.*)', '*.%1')
end

local function islisted(domain, list)
	while #domain > 0 do
		local access = list[domain]
		if access ~= nil then return access end
		domain = wildcarded(domain:sub(3))
	end
end

local function isbad(score)
	return score <= sbconfig.threshold
end

local function isallowed(profile, categories)
	for _, category in ipairs(categories or {}) do
		local access = profile.categories[category]
		if access ~= nil then return access end
	end

	return profile.default
end

function safebro.config(settings)
	collectgarbage()
	collectgarbage('setpause', 100)
	local conf = json.decode(settings)
	sbconfig.load(conf)
	threat.init()
end

function safebro.filter(mac, ip, domain, path)
	if islisted(domain, sbconfig.whitelist) then return false end

	local profile = sbconfig.profiles[mac] or sbconfig.profile

	local score, reason, categories	= 0, safebro.reasons.parental, {}
	local allow = islisted(domain, profile.domains)
	if allow == nil then
		score, reason, categories = threat.lookup(domain, path)
		if not score then return end -- cache miss

		if not isallowed(profile, categories) then
			allow, score, reason, categories = false, 0, safebro.reasons.parental, {}
		else
			allow = not isbad(score)
		end
	end

	if not allow then
		threat.notify{ip = nf.toip(ip), mac = nf.tomac(mac),
			uri = domain .. path, reason = reason, score = score,
			categories = categories}
		return true, reason
	end

	return false
end
