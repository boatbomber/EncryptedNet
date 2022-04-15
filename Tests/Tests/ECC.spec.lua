local BoatTEST = require(workspace.DevPackages.BoatTEST)
local this = BoatTEST.this

local ECC = require(workspace.ECC)

return {
	["Server and Client keys should not be the same"] = function(skip)
		-- Generate tokens
		local serverPrivate, serverPublic = ECC.keypair(ECC.random.random())
		local clientPrivate, clientPublic = ECC.keypair(ECC.random.random())

		-- Check for overlap
		this(serverPrivate:isEqual(clientPrivate)).equals(false)
		this(serverPublic:isEqual(clientPublic)).equals(false)
	end,
}
