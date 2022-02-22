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
        sharedSecret = ECC.exchange(serverPrivate, clientPublic)
    }

    return serverPublic
end

-- You can uncomment these to run a quick test and benchmark
-- task.defer(require, script.EllipticCurveCryptography.testing)
-- task.delay(8, require, script.EllipticCurveCryptography.benchmark)

return function(Remote)
    local RemoteType = tostring(getmetatable(Remote))
    --print(RemoteType, Remote)

    local Wrapper = setmetatable({}, {__index = Remote})
    if RemoteType == "ServerAsyncFunction" then
        function Wrapper:SetCallback(callback)
            Remote:SetCallback(function(Player, encryptedData, signature)
                local secret = PlayerData[Player].sharedSecret
                local clientPublic = PlayerData[Player].clientPublic

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
    end

    return Wrapper
end