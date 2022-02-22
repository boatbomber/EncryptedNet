local HttpService = game:GetService("HttpService")

local ECC = require(script.Parent.EllipticCurveCryptography)

local HandshakeRemote = script.Parent:WaitForChild("Handshake")

local clientPrivate, clientPublic = ECC.keypair(ECC.random.random())
local serverPublic = HandshakeRemote:InvokeServer(clientPublic)
local sharedSecret = ECC.exchange(clientPrivate, serverPublic)

return function(Remote)
	local Wrapper = setmetatable({}, { __index = Remote })

	-- Event

	function Wrapper:SendToServer(...)
		local args = table.pack(...)
		local data = HttpService:JSONEncode(args)

		local encryptedData = ECC.encrypt(data, sharedSecret)
		local signature = ECC.sign(clientPrivate, data)

		return Remote:SendToServer(encryptedData, signature)
	end

	function Wrapper:Connect(callback)
		Remote:Connect(function(encryptedData, signature)
			-- Metatables get lost in transit
			setmetatable(encryptedData, ECC._byteMetatable)
			setmetatable(signature, ECC._byteMetatable)

			local data = ECC.decrypt(encryptedData, sharedSecret)
			local verified = ECC.verify(serverPublic, data, signature)

			if not verified then
				warn("Could not verify signature", Remote.instance.Name)
				return
			end

			local args = HttpService:JSONDecode(tostring(data))
			callback(table.unpack(args))
		end)
	end

	-- AsyncFunction

	function Wrapper:CallServerAsync(...)
		local args = table.pack(...)
		local data = HttpService:JSONEncode(args)

		local encryptedData = ECC.encrypt(data, sharedSecret)
		local signature = ECC.sign(clientPrivate, data)

		return Remote:CallServerAsync(encryptedData, signature)
	end

	function Wrapper:SetCallback(callback)
		Remote:SetCallback(function(encryptedData, signature)
			-- Metatables get lost in transit
			setmetatable(encryptedData, ECC._byteMetatable)
			setmetatable(signature, ECC._byteMetatable)

			local data = ECC.decrypt(encryptedData, sharedSecret)
			local verified = ECC.verify(serverPublic, data, signature)

			if not verified then
				warn("Could not verify signature", Remote.instance.Name)
				return
			end

			local args = HttpService:JSONDecode(tostring(data))
			local success, response = pcall(callback, table.unpack(args))

			if not success then
				warn("Error in callback", Remote.instance.Name, response)
				return
			end

			return response
		end)
	end

	return Wrapper
end
