--
-- This file is Confidential Information of Cujo LLC.
-- Copyright (c) 2016-2018 CUJO LLC. All rights reserved.
--
local Viewer = require'loop.debug.Viewer'
local Verbose = require'loop.debug.Verbose'

local viewer = Viewer{
	linebreak = false,
	nolabels = true,
	noindices = true,
	metaonly = true,
	maxdepth = 2,
}

cujo.log = Verbose{
	viewer = viewer,
	groups = {
		-- log levels
		{'error'},
		{'warn'},
		{'config', 'feature', 'status'},
		{'communication', 'features', 'services', 'nflua', 'jobs'},
		-- tag groups
		communication = {
			'cloud',
			'hibernate',
			'stomp',
		},
		features = {
			'access',
			'appblock',
			'rabidctl',
			'scan',
			'status_update',
		},
		services = {
			'warmcache',
		},
	},
}

local loglevel = tonumber(os.getenv("CUJO_LOGLEVEL"))
if loglevel == nil then
    loglevel = 2 
end

cujo.log:settimeformat'%H:%M:%S'
cujo.log.timed = true
cujo.log:level(loglevel)
