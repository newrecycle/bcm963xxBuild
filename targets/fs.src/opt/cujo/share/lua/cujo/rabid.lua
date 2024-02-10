--
-- This file is Confidential Information of Cujo LLC.
-- Copyright (c) 2016-2017 CUJO LLC. All rights reserved.
--
for k, v in pairs{
	vararg = 'vararg',
	event  = 'coutil.event',
	time   = 'coutil.time',
	socket = 'coutil.socket',
	oo     = 'loop.base',
	tabop  = 'loop.table',
	json   = 'json',
	base64 = 'base64',
} do
	_G[k] = require(v)
end

cujo = {net = require'cujo.net'}
for _, v in ipairs{
	'log', 'filesys', 'snoopy', 'config', 'util', 'jobs',
	'ipset', 'iptables', 'nf', 'https', 'ssdp',
	'access', 'quarantine', 'appblock',
	'safebro', 'traffic', 'fingerprint',
	'hibernate', 'cloud.conn', 'shell.server', 'snoopyjobs',
} do
	local path = assert(package.searchpath('cujo.' .. v, package.path))
	assert(loadfile(path))()
end
