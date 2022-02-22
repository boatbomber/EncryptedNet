local HttpService = game:GetService("HttpService")

local ECC = require(script.Parent.EllipticCurveCryptography)

local HandshakeRemote = script.Parent:WaitForChild("Handshake")

local clientPrivate, clientPublic = ECC.keypair(ECC.random.random())
local serverPublic = HandshakeRemote:InvokeServer(clientPublic)
local sharedSecret = ECC.exchange(clientPrivate, serverPublic)

return function(Remote)
    local RemoteType = tostring(getmetatable(Remote))
    --print(RemoteType, Remote)

    local Wrapper = setmetatable({}, {__index = Remote})

    if RemoteType == "ClientAsyncFunction" then
        function Wrapper:CallServerAsync(...)
            local args = table.pack(...)
            local data = HttpService:JSONEncode(args)

            local encryptedData = ECC.encrypt(data, sharedSecret)
            local signature = ECC.sign(clientPrivate, data)

            return Remote:CallServerAsync(encryptedData, signature)
        end
    end

    return Wrapper
end