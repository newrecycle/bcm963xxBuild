--
-- This file is Confidential Information of Cujo LLC.
-- Copyright (c) 2016-2018 CUJO LLC. All rights reserved.
--
cujo.config = {
	backoff = {
		initial = 5,
		factor = 6,
		range = 0.5,
		max = 15 * 60,
	},
	maxcloudmessages = 30,
	lookupjobs = 4,
	urlcheckertimeout = 3,
	rabidctl = {},
	job = {
		timeout = 5,
		pollingtime = 0,
	},
	warmcache = {
		ttl = 60 * 60 * 24,
		retryinterval = 60 * 5,
	},
	cloudurl = {
		authentication = 'ident',
		routes = {
			'https://agent.cujo.io:9443/environment/redirect/',
		},
	},
	nf = {
		appblock = {maxentries = 1024},
		conn = {maxentries = 512, blockttl = 1000},
		http = {maxentries = 1024, ttl = 2 * 60},
		netlink = {
			port = 1337,
			family = 23,
		},
		threat = {
			cache = {maxentries = 1024},
			pending = {maxentries = 128, ttl = 60},
			whitelist = {maxentries = 1024, ttl = 60 * 60},
		},
		traffic = {
			maxentries = 30,
			timeout = 5,
			maxflowsize = 2 * 1024 * 1024 * 1024,
			appdata = {maxentries = 512},
		},
		dnscache = {maxentries = 256, ttl = 24 * 60 * 60},
	},
	chain_table = 'filter',
	chain_prefix = 'CUJO_',
	set_prefix = 'cujo_',
	lan_ifaces = {},
	nets = {},
}

do
	local mod = 'cujo.config.parameters'
	local path = assert(package.searchpath(mod, package.path))
	local env = setmetatable({config = cujo.config}, {__index = _G})
	assert(loadfile(path, 'bt', env))()
end

local function load_ifaces(env)
	local ifaces_str = os.getenv(env)
	if ifaces_str == nil then
		return nil
	end

	local ifaces = {}
	for iface in string.gmatch(ifaces_str, '%S+') do
		ifaces[#ifaces + 1] = iface
	end
	if #ifaces == 0 then
		cujo.log:warn('invalid ', env, '="', ifaces_str,
			      '", expected whitespace-separated values')
		return nil
	end
	return ifaces
end
local wan_ifaces = load_ifaces('CUJO_WAN_IFACES')
local lan_ifaces = load_ifaces('CUJO_LAN_IFACES')
local cloud_ifaces = load_ifaces('CUJO_CLOUD_IFACE')
if wan_ifaces ~= nil then cujo.config.wan_ifaces = wan_ifaces end
if lan_ifaces ~= nil then cujo.config.lan_ifaces = lan_ifaces end
if cloud_ifaces ~= nil then
	if #cloud_ifaces > 1 then
		cujo.log:error('too many values in CUJO_CLOUD_IFACE, using only the first one')
	end
	cujo.config.cloud_iface = cloud_ifaces[1]
end

local netcfg = cujo.net.newcfg()

if cujo.config.gateway_ip == nil then
	local iface = assert(cujo.config.lan_ifaces[1])
	cujo.config.gateway_ip = assert(netcfg:getdevaddr(iface))
	cujo.config.gateway_mac = assert(netcfg:getdevhwaddr(iface))
end
cujo.log:config('default gateway is ', cujo.config.gateway_ip,
           ' (MAC=', cujo.config.gateway_mac, ')')

if cujo.config.serial == nil then
	cujo.config.serial = string.gsub(cujo.config.gateway_mac, ':', ''):lower()
end
cujo.log:config('identity serial number is ', cujo.config.serial)

function cujo.config.cloudsrcaddr()
	if not cujo.config.cloud_iface then return end
	return assert(netcfg:getdevaddr(cujo.config.cloud_iface))
end

if cujo.config.privileges then
	local permission = require'cujo.permission'
	if cujo.config.privileges.user or cujo.config.privileges.group then
		if cujo.config.privileges.capabilities then
			assert(permission.keepcaps())
		end
		if cujo.config.privileges.group then
			assert(permission.setgroup(cujo.config.privileges.group))
		end
		if cujo.config.privileges.user then
			assert(permission.setuser(cujo.config.privileges.user))
		end
	end
	if cujo.config.privileges.capabilities then
		assert(cujo.config.privileges.capabilities == "process"
		    or cujo.config.privileges.capabilities == "ambient", "illegal capability mode")
		local requiredcaps = { "net_admin", "net_raw", "net_bind_service" }
		assert(permission.setupcaps(table.unpack(requiredcaps)))
		if cujo.config.privileges.capabilities == "ambient" then
			for _, capname in ipairs(requiredcaps) do
				assert(permission.setambientcap(capname))
			end
		end
	end
end
