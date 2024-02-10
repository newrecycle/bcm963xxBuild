--
-- This file is Confidential Information of Cujo LLC.
-- Copyright (c) 2018 CUJO LLC. All rights reserved.
--
-- Overview: nf_lua match extension for hostname and user-agent extraction,
--    based on wireshark's GQUIC dissector.

gquic = {}

-- tags are coded as ASCII characters
local validtags = {
	[0x50414400] = true,
	[0x534e4900] = true, -- SNI
	[0x56455200] = true,
	[0x43435300] = true,
	[0x55414944] = true, -- UA
	[0X50444d44] = true,
	[0X53544b00] = true,
	[0x534e4f00] = true,
	[0x50524f46] = true,
	[0x53434647] = true,
	[0x5252454a] = true,
	[0x435254ff] = true,
	[0x41454144] = true,
	[0x53434944] = true,
	[0x50554253] = true,
	[0x4b455853] = true,
	[0x4f424954] = true,
	[0x45585059] = true,
	[0x4e4f4e43] = true,
	[0x4d535043] = true,
	[0x54434944] = true,
	[0x53524246] = true,
	[0x4943534c] = true,
	[0x53434c53] = true,
	[0x434f5054] = true,
	[0x43435254] = true,
	[0x49525454] = true,
	[0x43464357] = true,
	[0x53464357] = true,
	[0x43455456] = true,
	[0x584c4354] = true,
	[0x4e4f4e50] = true,
	[0x43534354] = true,
	[0x4354494d] = true,
	[0x4d494453] = true,
	[0x46484f4c] = true,
	[0x5354544c] = true,
	[0x534d484c] = true,
	[0x54424b50] = true,
}

local SNI = 0x534e4900
local UA = 0x55414944

local len = {
	offset = {
		[0] = 0,
		[1] = 2,
		[2] = 3,
		[3] = 4,
		[4] = 5,
		[5] = 6,
		[6] = 7,
		[7] = 8,
	},
	stream = {
		[0] = 1,
		[1] = 2,
		[2] = 3,
		[3] = 4
	},
	packet = {
		[0] = 1,
		[1] = 2,
		[2] = 4,
		[3] = 6,
	},
}

local exttag = data.layout{
	type = {0, 4 * 8},
	offset = {4 * 8, 4 * 8, 'number', 'little'}
}

local frametype = data.layout{
	stream = {0, 1},
	fin = {1, 1},
	datalen = {2, 1},
	offsetsz = {3, 3},
	streamsz = {6, 2},
}

local function stflags(version, sz, offset)
	return {sid = {8, sz * 8, 'number', version > 39 and 'big' or 'little'},
			tag = {offset, 4, 'string'}}
end

local function extract(payload, version)
	local offset = 0 -- bytes

	if not payload then return end
	payload:layout(frametype)
	offset = offset + 1 -- frame type

	if payload.stream ~= 0x1 then return end
	if payload.datalen ~= 0x1 then return end

	local offsetsz = len.offset[payload.offsetsz]
	local streamsz = len.stream[payload.streamsz]
	offset = offset + streamsz + offsetsz + 2 -- (data len)
	payload:layout(stflags(version, streamsz, offset))

	if payload.sid ~= 0x1 then return end
	if payload.tag ~= 'CHLO' then return end

	-- adjust offset to tags section
	offset = offset + 8 -- (tag + tagnum + padding)
	-- segment packet to tags
	local tag = payload:segment(offset)

	local lastoff = 0
	local sni = {}
	local ua = {}

	tag:layout(exttag)
	repeat
		if tag.type == SNI then
			sni.offset = tag.offset
			sni.len = tag.offset - lastoff
		end
		if tag.type == UA then
			ua.offset = tag.offset
			ua.len = tag.offset - lastoff
		end
		lastoff = tag.offset
		-- tags always have a length of 8 bytes
		tag = tag:segment(8)
		tag:layout(exttag)
	until not validtags[tag.type]

	if not sni.offset then return end
	local sni = tag:segment(sni.offset - sni.len, sni.len)
	if not ua.offset then return tostring(sni) end
	local ua = tag:segment(ua.offset - ua.len, ua.len)

	return tostring(sni), tostring(ua)
end

local pubflags = data.layout{
	reserved = {0, 1},
	multipath = {1, 1},
	pnl = {2, 2},
	cid = {4, 1},
	nonce = {5, 1},
	rst = {6, 1},
	verflag = {7, 1},
	version = {10, 3, 'string'}
}

local function validate(payload)
	local offset = 13 -- (public flag + version + cid)
	local version = tonumber(payload.version)

	if not version or version < 20 or version > 49 then return end

	return #payload > 13 and payload.verflag ~= 0 and payload.cid ~= 0,
	        offset, version
end

function gquic.parse(payload, publicsrc)
	payload:layout(pubflags)
	local ok, offset, version = validate(payload)

	if not ok then return end
	if payload.nonce == 0x1 and publicsrc then offset = offset + 32 end

	offset = offset + len.packet[payload.pnl] + 12 -- MAH
	-- private flag in <Q034
	if version < 34 then offset = offset + 1 end

	return extract(payload:segment(offset), version)
end
