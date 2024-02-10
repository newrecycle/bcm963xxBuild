--
-- This file is Confidential Information of Cujo LLC.
-- Copyright (c) 2018-2019 CUJO LLC. All rights reserved.
--
local runpath = '/var/run/cujo'
cujo.filesys.mkdir(runpath)

local version = assert(cujo.filesys.readfrom('/proc/version', 'l'))

local prefix_ro = os.getenv'CUJO_HOME'
local cujo_version = assert(cujo.filesys.readfrom(prefix_ro .. '/build_info', 'l'))

config.ipset = prefix_ro .. '/bin/ipset'
config.ip = '/bin/ip'
config.tls = {
	protocol = 'tlsv1_2',
	verify = 'peer',
	cafile = prefix_ro .. '/etc/cujo-aws-root.pem',
}
config.dns_conf_path = '/etc/resolv.conf'
config.hardware_revision = 'Actiontec T3200M'
config.build_version = cujo_version:match'build_version="(.+)"'
config.build_number = 0
config.build_time = 0
config.build_kernel = string.match(version, "%D+(%S+).+")
config.build_arch = 'arm'
config.wan_ifaces = {'eth0.1', 'ewan0.1', 'ewan1.1', 'ptm0.1', 'atm0.1'}
config.lan_ifaces = {'br0'}
config.rabidctl.sockpath = runpath .. '/rabidctl.sock'
config.wan_ipv6addr = cujo.snoopy.getdevaddripv6(config.lan_ifaces)
config.nets = {
	ip4 = {iptables = prefix_ro .. '/bin/cujo-iptables'},
	ip6 = {iptables = prefix_ro .. '/bin/cujo-ip6tables'},
}
config.privileges = nil

-- TODO: implement this on other platforms as well (PS-543)
local routing_url = os.getenv'CUJO_ROUTING_URL'
if routing_url == nil then
	routing_url = 'https://routing-service.telus-prod.hosted.cujo.io/environment/redirect/'
end

-- use non-default partner agent authentication cerificate key?
local paac_key_path = os.getenv'CUJO_PAAC_KEY_PATH'
if paac_key_path == nil then
	paac_key_path = prefix_ro .. '/etc/cujo-test-fw.pem'
end

local cert_key = ''
for l in io.lines(paac_key_path) do
	if string.find(l, 'CERTIFICATE-----') == nil then
		cert_key = cert_key .. l
	end
end

local auth_type = os.getenv'CUJO_PARTNER_AUTH_TYPE'
if auth_type == nil then
	auth_type = 'secret'
end
assert(auth_type == 'secret' or auth_type == 'ident', "Unsupported authentication type")

config.cloudurl = {
	authentication = auth_type,
	routes = {
		routing_url,
	},
	certificate = cert_key
}
