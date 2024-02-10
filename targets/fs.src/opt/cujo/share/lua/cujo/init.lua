--
-- This file is Confidential Information of Cujo LLC.
-- Copyright (c) 2016-2017 CUJO LLC. All rights reserved.
--
local function errhandler(err)
	io.stderr:write(string.format('init error: %s\n', debug.traceback(err, 2)))
	os.exit(1)
end

local path = assert(package.searchpath('cujo.rabid', package.path))
require'coutil.spawn'.catch(errhandler, assert(loadfile(path)))
require'coutil.socket'.run()
