--
-- This file is Confidential Information of Cujo LLC.
-- Copyright (c) 2018 CUJO LLC. All rights reserved.
--
local dnscache = lru.new(config.dnscache.maxentries, config.dnscache.ttl)
local dnsheaderlen = 12
local maxnamelen = 255
local answerlen = 10

local layout = data.layout{
	id      = {     0, 2 * 8},
	flags   = { 2 * 8, 2 * 8},
	qdcount = { 4 * 8, 2 * 8},
	ancount = { 6 * 8, 2 * 8},
	nscount = { 8 * 8, 2 * 8},
	arcount = {10 * 8, 2 * 8},
}

local answer = data.layout{
	type  = {    0, 2 * 8},
	class = {2 * 8, 2 * 8},
	ttl   = {4 * 8, 4 * 8},
	rdlen = {8 * 8, 2 * 8},
	ip4   = {   10,  4, 'string'},
	ip6   = {   10, 16, 'string'},
}

local answertype = {
	[1]  = 'ip4',
	[28] = 'ip6',
}

function nf.flushdnscache()
	dnscache = lru.new(config.dnscache.maxentries, config.dnscache.ttl)
end

function nf.getdnscache(ip)
	return dnscache[ip]
end

local function readbyte(payload, offset)
	local data = nf.segment(payload, data.layout{len = {0, 8}}, offset)
	return data.len
end

local function getdomain(payload)
	local offset = dnsheaderlen
	local maxoffset = offset + maxnamelen + 1
	local labels = {}
	while offset < maxoffset do
		local len = readbyte(payload, offset)
		offset = offset + 1
		if len == 0 then break end
		table.insert(labels, tostring(payload:segment(offset, len)))
		offset = offset + len
	end
	local domain = table.concat(labels, '.') .. '\0'
	return domain, offset + 4
end

local function skipname(payload, offset)
	local maxoffset = offset + maxnamelen + 1
	local pointer = 0xC0
	while offset < maxoffset do
		local len = readbyte(payload, offset)
		if len == 0 then break end
		if (len & pointer) == pointer then
			offset = offset + 2
			break
		end
		offset = offset + len
	end
	return offset
end

function nf_dnscache(frame, packet)
	local ip = nf.ip(packet)
	local udp, payload = nf.udp(ip)
	local dns = nf.segment(payload, layout)
	if dns.ancount == 0 or dns.qdcount ~= 1 then return end
	local domain, offset = getdomain(dns, dns.qdcount)
	for i = 1, dns.ancount do
		offset = skipname(dns, offset)
		local answer = nf.segment(dns, answer, offset)
		local t = answertype[answer.type]
		if t then
			dnscache[answer[t]] = domain
		end
		offset = offset + answerlen + answer.rdlen
	end
end
