--
-- This file is Confidential Information of Cujo LLC.
-- Copyright (c) 2017 CUJO LLC. All rights reserved.
--
local chains = {}
for k, v in pairs{input = {'fwdin', 'IN'}, output = {'fwdout', 'OUT'}} do
	local mainchain, name = table.unpack(v)
	local params = {table = cujo.config.chain_table, name = 'SAFEBRO_' .. name}
	chains[k] = {}
	for net in pairs(cujo.config.nets) do
		local chain = cujo.iptables.new(tabop.copy(params, {net = net}))
		cujo.nf.addrule(net, mainchain, {target = chain})
		chains[k][net] = chain
	end
end

local fakeresponse = {
	score = 100,
	reason = 999999999,
	categories = {},
	cachedomain = false
}

local lookupqueue = cujo.jobs.createqueue()

local function setresponse(domain, score, reason, categories, cachedomain)
	local msg = string.format('threat.setresponse(%q,{%d,%d,{%s}},%s)',
		domain, score, reason, table.concat(categories, ','), cachedomain)
	cujo.nf.dostring(msg)
end

cujo.warmcache_state = 'unknown'
local warmcache = {}
function warmcache.stop()
	local current = warmcache.current
	if not current then return end
	warmcache.current = nil
	event.emitone(warmcache)
	if coroutine.status(current) ~= 'dead' then event.awaitany(warmcache) end
end

function warmcache.start(url, token, ttl)
	assert(warmcache.current == nil)
	if not url then	return cujo.log:warmcache'disabled' end

	cujo.jobs.spawn(function ()
		warmcache.current = coroutine.running()
		local jsonpat =
			'{"url": *"([^"]+)", *"score": *(%d+), *"categories": *%[([^%]]*)%]}()'
		local delay = 0
		while true do
			if warmcache.current then cujo.jobs.wait(delay, warmcache) end
			if not warmcache.current  then
				cujo.log:warmcache'terminating'
				event.emitall(warmcache)
				return
			end
			cujo.log:warmcache'loading new cache'
			cujo.warmcache_state = 'loading'
			local left = ''
			local ok, code = cujo.https.request{
				url = url,
				headers = {Authorization = token},
				sink = function (chunk, errmsg)
					if not warmcache.current  then
						return cujo.log:warmcache'cache load interrupted'
					end
					if not chunk then return 1 end
					time.sleep(0) -- yield
					chunk = left .. chunk
					local lastpos
					for url, score, rawcats, pos in string.gmatch(chunk, jsonpat) do
						local categories = {}
						for category in string.gmatch(rawcats, '%s*(%d*)%s*,?') do
							table.insert(categories, tonumber(category))
						end
						setresponse(url, score, fakeresponse.reason, categories, true)
						lastpos = pos
					end
					if lastpos then left = string.sub(chunk, lastpos) end
					return 1
				end,
				create = cujo.https.connector.simple(cujo.config.tls, nil,
								     cujo.config.cloudsrcaddr())
			}
			if not ok then
				delay = cujo.config.warmcache.retryinterval
				cujo.log:error('failed to load cache (HTTP error ', code, ')')
			else
				delay = ttl or cujo.config.warmcache.ttl
				cujo.log:warmcache'cache loaded'
				cujo.warmcache_state = 'loaded'
			end
		end
	end)
end

local config = false
local function reconfigure(self, enable, settings)
	warmcache.stop()
	local active, toactivate = self.enabled and config, enable and settings
	if toactivate then
		cujo.nf.dostring(string.format('safebro.config%q', json.encode(settings)))
		warmcache.start(settings.cacheurl, settings.token, settings.cachettl)
		if not active then
			for net in pairs(cujo.config.nets) do
				for _, v in pairs{{80, 'nf_http'}, {443, 'nf_ssl'}} do
					local port, func = table.unpack(v)
					chains.input[net]:append{
						{'tcp', dst = port},
						{'conntrack', states = {'new'}},
						{'func', 'nf_conn_new'},
					}
					chains.input[net]:append{
						{'tcp', dst = port, flags = {psh = true}},
						{'func', func},
					}
					chains.output[net]:append{
						{'tcp', src = port},
						{'func', 'nf_drop_response'},
						target = 'drop',
					}
				end
			end
		end
	elseif active then
		for net in pairs(cujo.config.nets) do
			for _, v in pairs{'input', 'output'} do chains[v][net]:flush() end
		end
		cujo.nf.dostring'safebro.config"{}"'
	end
	self.enabled, config = enable, settings
end

local mutex = {}
cujo.safebro = {
	threat = cujo.util.createpublisher(),
	enable = cujo.util.createenabler(function (self, enable)
		cujo.jobs.lockedcall(mutex, reconfigure, self, enable, config)
	end),
}

function cujo.safebro.getconfig() return config end
function cujo.safebro.configure(settings)
	cujo.jobs.lockedcall(mutex, reconfigure, cujo.safebro.enable,
		cujo.safebro.enable.enabled, settings)
end

function cujo.safebro.setbypass(mac, add)
	cujo.nf.dostring(string.format('threat.bypass[%d] = %s',
		tonumber(string.gsub(mac, ':', ''), 16), add and true or nil))
end

cujo.nf.subscribe('lookup', function (entry) lookupqueue:enqueue(entry) end)
cujo.nf.subscribe('notify', cujo.safebro.threat)

local connector = tabop.memoize(function ()
	return cujo.https.connector.keepalive(cujo.config.tls,
		cujo.config.urlcheckertimeout, cujo.config.cloudsrcaddr())
end, 'k')

local function lookup(url)
	if not config then
		cujo.log:error'URL lookup while not configured'
		return fakeresponse
	end
	local body, code = cujo.https.request{
		url = string.format('%s?url=%s', config.endpoint, url),
		headers = {Authorization = config.token, Connection = 'keep-alive'},
		create = connector[coroutine.running()]
	}
	if not body or body == '' then
		if body then code = 'no urlchecker response' end
		cujo.log:error('URL lookup error "', url, '" : ', code, ' : ', msg)
		return fakeresponse
	end

	local ok, response = pcall(json.decode, body)
	if not ok then
		cujo.log:error('URL lookup "', url, '" json decode error : ', response)
		return fakeresponse
	end

	if not response.score then
		cujo.log:error('URL lookup "', url, '" bad response : ',  body)
		return fakeresponse
	end

	response.cachedomain = response.nocache ~= true
	response.reason = response.reason or fakeresponse.reason

	if response.score > fakeresponse.score then
		if response.score == 200 then
			cujo.log:status('URL lookup result pending "', url,
				'" score out of range: ', response.score)
		else
			cujo.log:warn('URL lookup "', url, '" score out of range: ', response.score)
		end
		response.score = fakeresponse.score
		response.cachedomain = false
	end
	return response
end

local function lookupjob()
	while true do
		local entry = lookupqueue:dequeue()
		local response = lookup(entry.domain .. entry.path)
		setresponse(entry.domain, response.score, response.reason,
			response.categories or {}, response.cachedomain)
	end
end

for i = 1, cujo.config.lookupjobs do cujo.jobs.spawn(lookupjob) end