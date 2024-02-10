--
-- This file is Confidential Information of Cujo LLC.
-- Copyright (c) 2016-2018 CUJO LLC. All rights reserved.
--
cujo.filesys = {}

function cujo.filesys.mkdir(path) os.execute('mkdir -p ' .. path) end

function cujo.filesys.readfrom(path, what)
	local file, err = io.open(path)
	if file == nil then return nil, err end
	local contents, err = file:read(what or 'l')
	file:close()
	return contents, err
end
