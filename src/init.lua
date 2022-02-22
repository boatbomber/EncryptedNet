local RunService = game:GetService("RunService")
local IsServer = RunService:IsServer()

if IsServer then
	-- Server side
	return require(script.server)
else
	-- Client side
	return require(script.client)
end
