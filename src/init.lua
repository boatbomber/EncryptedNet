if game:GetService("RunService"):IsServer() then
	-- Server side
	return require(script.server)
else
	-- Client side
	return require(script.client)
end
