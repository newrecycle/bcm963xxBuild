--
-- This file is Confidential Information of Cujo LLC.
-- Copyright (c) 2018 CUJO LLC. All rights reserved.
--
cujo.ipset = {meta = oo.class()}

local types = {
	mac    = {'hash:mac'},
	ip4    = {'hash:ip', 'family', 'inet'},
	ip6    = {'hash:ip', 'family', 'inet6'},
}

function cujo.ipset.meta:set(add, entry)
	assert(cujo.jobs.exec(cujo.config.ipset, {
		add and 'add' or 'del', self.name, tostring(entry), '-exist'}))
end

function cujo.ipset.meta:flush()
	assert(cujo.jobs.exec(cujo.config.ipset, {'flush', self.name}))
end

function cujo.ipset.new(params)
	local name = cujo.config.set_prefix .. params.name

	local args = {'create', name}
	cujo.util.join(args, assert(types[params.type]))
	cujo.util.append(args, '-exist')

	assert(cujo.jobs.exec(cujo.config.ipset, args))
	return cujo.ipset.meta{name = name}
end
