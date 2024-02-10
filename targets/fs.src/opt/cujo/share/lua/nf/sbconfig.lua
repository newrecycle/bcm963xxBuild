--
-- This file is Confidential Information of Cujo LLC.
-- Copyright (c) 2018 CUJO LLC. All rights reserverd.
--

sbconfig = {}

local default = {
	threshold = 25,
	warnpage = 'http://block.getcujo.com/warn',
	blockpage = 'http://block.getcujo.com/block',
	ttl = 24 * 60 * 60,
	timeout = 1200,
	profile = {domains = {}, categories = {}, default = true},
}

setmetatable(sbconfig, {__index = default})

local function frombytes(bytes)
	local n = 0
	for i, byte in ipairs(bytes) do
		byte = tonumber(byte, 16)
		n = (byte << (#bytes - i) * 8) | n
	end
	return n
end

local function toaccess(access)
	return string.lower(access) == 'allow' -- block by default
end

local function load_list(list)
	local set = {}
	for _, element in ipairs(list or {}) do
		set[element] = true
	end
	return set
end

local function load_domains(filter, domains)
	for _, access in ipairs{'allow', 'block'} do
		local list = filter[access .. 'edDomains'] or {}
		for _, domain in ipairs(list) do
			local domain = string.lower(domain)
			domains[domain] = toaccess(access)
		end
	end
end

local function load_categories(filter, categories)
	for _, category in ipairs(filter.categories or {}) do
		categories[category] = filter.access
	end
end

local function load_devices(devices, profiles, profile)
	for _, device in ipairs(devices or {}) do
		local device = frombytes{string.match(device.mac,
			'(%x%x):(%x%x):(%x%x):(%x%x):(%x%x):(%x%x)')}
		profiles[device] = profile
	end
end

local function load_profiles(confs)
	local profiles = {}
	for _, conf in ipairs(confs) do
		local profile = {domains = {}, categories = {}}

		for _, filter in ipairs(conf.filters or {}) do
			load_domains(filter, profile.domains)
			filter.access = toaccess(filter.access)
			load_categories(filter, profile.categories)
		end

		local default = conf.defaultAccess or {}
		profile.default = toaccess(default.access)

		load_devices(conf.devices, profiles, profile)
	end
	return profiles
end

local function escape_url(url)
	return url:gsub("([-.])", "%%%1")
end

function sbconfig.load(settings)
	sbconfig.profiles = load_profiles(settings.profiles or {})
	sbconfig.threshold = settings.threshold
	sbconfig.whitelist = load_list(settings.whitelist)
	sbconfig.warnpage = settings.warnpage
	sbconfig.warnpage_escaped = escape_url(sbconfig.warnpage)
	sbconfig.blockpage = settings.blockpage
	sbconfig.ttl = settings.ttl
end
