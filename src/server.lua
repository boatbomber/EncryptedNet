local Players = game:GetService("Players")
local HttpService = game:GetService("HttpService")

local ECC = require(script.Parent.EllipticCurveCryptography)

local PlayerData = {}

local HandshakeRemote = Instance.new("RemoteFunction")
HandshakeRemote.Name = "Handshake"
HandshakeRemote.Parent = script.Parent

function HandshakeRemote.OnServerInvoke(Player, clientPublic)
	local serverPrivate, serverPublic = ECC.keypair(ECC.random.random())

	PlayerData[Player] = {
		clientPublic = clientPublic,
		serverPublic = serverPublic,
		serverPrivate = serverPrivate,
		sharedSecret = ECC.exchange(serverPrivate, clientPublic),
	}

	return serverPublic
end

Players.PlayerRemoving:Connect(function(Player)
	PlayerData[Player] = nil
end)

local function getPlayerData(Player, shouldYield)
	local playerData = PlayerData[Player]
	if shouldYield and playerData == nil then
		-- Perhaps they're in middle of the handshake?
		-- Poll for half a second
		for _=1, 15 do
			task.wait(1/30)
			playerData = PlayerData[Player]
			if playerData then
				break
			end
		end
	end

	return playerData
end

return function(Remote)
	local Wrapper = setmetatable({}, { __index = Remote })

	-- Event

	function Wrapper:Connect(callback)
		Remote:Connect(function(Player, encryptedData, signature)
			local playerData = getPlayerData(Player, false) -- No yield since they can't have sent valid data without a handshake first
			if not playerData then
				return
			end

			local secret = playerData.sharedSecret
			local clientPublic = playerData.clientPublic

			-- Metatables get lost in transit
			setmetatable(encryptedData, ECC._byteMetatable)
			setmetatable(signature, ECC._byteMetatable)

			local data = ECC.decrypt(encryptedData, secret)
			local verified = ECC.verify(clientPublic, data, signature)

			if not verified then
				warn("Could not verify signature", Remote.instance.Name)
				return
			end

			local args = HttpService:JSONDecode(tostring(data))
			callback(Player, table.unpack(args))
		end)
	end

	function Wrapper:SendToPlayer(Player, ...)
		local playerData = getPlayerData(Player, true) -- Yield in case we're sending before they're ready
		if not playerData then
			return
		end
		local secret = playerData.sharedSecret
		local private = playerData.serverPrivate

		local args = table.pack(...)
		local data = HttpService:JSONEncode(args)

		local encryptedData = ECC.encrypt(data, secret)
		local signature = ECC.sign(private, data)

		Remote:SendToPlayer(Player, encryptedData, signature)
	end

	function Wrapper:SendToPlayers(Allowlist, ...)
		for _, Player in ipairs(Players:GetPlayers()) do
			if not table.find(Allowlist, Player) then
				continue
			end

			task.spawn(Wrapper.SendToPlayer, Wrapper, Player, ...)
		end
	end

	function Wrapper:SendToAllPlayers(...)
		for _, Player in ipairs(Players:GetPlayers()) do
			task.spawn(Wrapper.SendToPlayer, Wrapper, Player, ...)
		end
	end

	function Wrapper:SendToAllPlayersExcept(Ignorelist, ...)
		for _, Player in ipairs(Players:GetPlayers()) do
			if Ignorelist == Player then
				continue
			end
			if type(Ignorelist) == "table" and table.find(Ignorelist, Player) then
				continue
			end

			task.spawn(Wrapper.SendToPlayer, Wrapper, Player, ...)
		end
	end

	-- AsyncFunction

	function Wrapper:CallPlayerAsync(Player, ...)
		local playerData = getPlayerData(Player, true) -- Yield in case we're calling before they're ready
		if not playerData then
			return
		end
		local secret = playerData.sharedSecret
		local private = playerData.serverPrivate

		local args = table.pack(...)
		local data = HttpService:JSONEncode(args)

		local encryptedData = ECC.encrypt(data, secret)
		local signature = ECC.sign(private, data)

		return Remote:CallPlayerAsync(Player, encryptedData, signature)
	end

	function Wrapper:SetCallback(callback)
		Remote:SetCallback(function(Player, encryptedData, signature)
			local playerData = getPlayerData(Player, false) -- No yield since they can't have sent valid data without a handshake first
			if not playerData then
				return
			end
			local secret = playerData.sharedSecret
			local clientPublic = playerData.clientPublic

			-- Metatables get lost in transit
			setmetatable(encryptedData, ECC._byteMetatable)
			setmetatable(signature, ECC._byteMetatable)

			local data = ECC.decrypt(encryptedData, secret)
			local verified = ECC.verify(clientPublic, data, signature)

			if not verified then
				warn("Could not verify signature", Remote.instance.Name)
				return
			end

			local args = HttpService:JSONDecode(tostring(data))
			local success, response = pcall(callback, Player, table.unpack(args))

			if not success then
				warn("Error in callback", Remote.instance.Name, response)
				return
			end

			return response
		end)
	end

	return Wrapper
end
