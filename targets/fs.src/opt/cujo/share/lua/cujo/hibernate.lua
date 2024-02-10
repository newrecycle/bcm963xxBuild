--
-- This file is Confidential Information of Cujo LLC.
-- Copyright (c) 2018 CUJO LLC. All rights reserved.
--
cujo.hibernate = {}

local function wakeup(reason) event.emitall(wakeup, reason) end

function cujo.hibernate.wakeup() wakeup'API' end

function cujo.hibernate.sleep(duration)
	cujo.hibernate.wakeup'hibernate'
	if cujo.traffic.enable:get() then
		cujo.log:hibernate'ignored hibernation because traffic monitoring is on'
		return 'traffic'
	end
	cujo.log:hibernate('hibernating for ', duration / 60, ' minutes')
	cujo.cloud.disconnect()
	local ev, reason = time.sleep(duration, wakeup)
	if ev ~= wakeup then reason = 'timeout' end
	cujo.log:hibernate('ending, ', reason, ' woke us')
	if reason ~= 'hibernate' then cujo.cloud.connect() end
	return reason
end

cujo.safebro.threat:subscribe(function () wakeup'threat' end)
cujo.fingerprint.dhcp:subscribe(function () wakeup'dhcp' end)
cujo.traffic.enable:subscribe(function (enable)
	if enable then wakeup'traffic' end
end)
