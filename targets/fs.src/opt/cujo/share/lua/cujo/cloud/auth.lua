--
-- This file is Confidential Information of Cujo LLC.
-- Copyright (c) 2018 CUJO LLC. All rights reserved.
--
local function getroute()
	for _, route in ipairs(cujo.config.cloudurl.routes) do
		local url = route .. cujo.config.serial
		if cujo.config.firmware_name then
			url = url .. '?firmware_name=' .. cujo.config.firmware_name
		end
		local body, code = cujo.https.request{
			url = url,
			create = cujo.https.connector.simple(
				cujo.config.tls, nil, cujo.config.cloudsrcaddr()),
		}
		if body and code == 200 then return body end
		cujo.log:warn("unable to get cloud route through '", url, "' : ", code)
	end
	return nil, 'unable to route'
end

local serial = 'serial=' .. cujo.config.serial

local auth = {}

function auth.ident() return {serial} end

function auth.challenge(baseurl)
	local reply, code = cujo.https.request{
		url = baseurl .. '/auth',
		multipart = {
			signer = {
				name = 'signer',
				data = assert(cujo.config.cloudurl.signcert),
			},
			device = {
				name = 'device',
				data = assert(cujo.config.cloudurl.devcert),
			},
		},
		create = cujo.https.connector.simple(
			cujo.config.tls, nil, cujo.config.cloudsrcaddr()),
	}
	if not reply then return nil, code end
	if code ~= 200 then
		return nil, string.format('http status %d response %s', code, reply)
	end
	local ok, res = pcall(json.decode, reply)
	if not ok then
		return nil, 'json decode error: ' .. res
	end
	local decodechallenge = assert(cujo.config.cloudurl.decodechallenge)
	local challenge = decodechallenge(base64.decode(res.challenge))
	return {serial, 'challenge=' .. base64.encode(challenge)}
end

function auth.secret(baseurl)
	local reply, code = cujo.https.request{
		url = baseurl .. '/token-auth',
		multipart = {
			serial = cujo.config.serial,
			certificate = assert(cujo.config.cloudurl.certificate),
		},
		create = cujo.https.connector.simple(
			cujo.config.tls, nil, cujo.config.cloudsrcaddr()),
	}
	if not reply then return nil, code end
	if code ~= 200 then
		return nil, string.format('http status %d response %s', code, reply)
	end
	return {'token=' .. reply}
end

local method = assert(auth[cujo.config.cloudurl.authentication],
	'invalid method')

return function ()
	local baseurl, err = getroute()
	if not baseurl then return nil, err end
	local params, err = method(baseurl)
	if not params then return nil, err end
	return baseurl .. '/stomp?' .. table.concat(params, '&')
end
