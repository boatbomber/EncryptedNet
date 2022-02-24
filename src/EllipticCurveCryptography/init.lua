-- Elliptic Curve Cryptography in Computercraft
local util = require(script.util)
local sha256 = require(script.sha256)
local chacha20 = require(script.chacha20)
local random = require(script.random)
local modq = require(script.modq)
local curve = require(script.curve)

local function getNonceFromEpoch()
	local nonce = table.create(12)
	local epoch = DateTime.now().UnixTimestampMillis
	for i = 1, 12 do
		nonce[i] = epoch % 256
		epoch = math.floor(epoch / 256)
	end

	return nonce
end

local function encrypt(data, key)
	local encKey = sha256.hmac("encKey", key)
	local macKey = sha256.hmac("macKey", key)
	local nonce = getNonceFromEpoch()

	local ciphertext = chacha20.crypt(data, encKey, nonce)

	local result = nonce
	for _, value in ipairs(ciphertext) do
		table.insert(result, value)
	end

	local mac = sha256.hmac(result, macKey)
	for _, value in ipairs(mac) do
		table.insert(result, value)
	end

	return setmetatable(result, util.byteTableMT)
end

local function decrypt(data, key)
	local actualData = type(data) == "table" and { table.unpack(data) } or { string.byte(tostring(data), 1, -1) }
	local encKey = sha256.hmac("encKey", key)
	local macKey = sha256.hmac("macKey", key)
	local mac = sha256.hmac({ table.unpack(actualData, 1, #actualData - 32) }, macKey)
	local messageMac = { table.unpack(actualData, #actualData - 31) }
	assert(mac:isEqual(messageMac), "invalid mac")
	local nonce = { table.unpack(actualData, 1, 12) }
	local ciphertext = { table.unpack(actualData, 13, #actualData - 32) }
	local result = chacha20.crypt(ciphertext, encKey, nonce)

	return setmetatable(result, util.byteTableMT)
end

local function keypair(seed)
	local x
	if seed then
		x = modq.hashModQ(seed)
	else
		x = modq.randomModQ()
	end

	local Y = curve.G * x

	local privateKey = x:encode()
	local publicKey = Y:encode()

	return privateKey, publicKey
end

local function exchange(privateKey, publicKey)
	local x = modq.decodeModQ(privateKey)
	local Y = curve.pointDecode(publicKey)
	local Z = Y * x

	local sharedSecret = sha256.digest(Z:encode())

	return sharedSecret
end

local function sign(privateKey, message)
	local actualMessage = type(message) == "table" and string.char(table.unpack(message)) or tostring(message)
	local actualPrivateKey = type(privateKey) == "table" and string.char(table.unpack(privateKey))
		or tostring(privateKey)

	local x = modq.decodeModQ(actualPrivateKey)
	local k = modq.randomModQ()
	local R = curve.G * k
	local e = modq.hashModQ(actualMessage .. tostring(R))
	local s = k - x * e

	e = e:encode()
	s = s:encode()

	local result, result_len = e, #e
	for index, value in ipairs(s) do
		result[result_len + index] = value
	end

	return setmetatable(result, util.byteTableMT)
end

local function verify(publicKey, message, signature)
	local actualMessage = type(message) == "table" and string.char(table.unpack(message)) or tostring(message)
	local sigLen = #signature
	local Y = curve.pointDecode(publicKey)
	local e = modq.decodeModQ({ table.unpack(signature, 1, sigLen / 2) })
	local s = modq.decodeModQ({ table.unpack(signature, sigLen / 2 + 1) })
	local Rv = curve.G * s + Y * e
	local ev = modq.hashModQ(actualMessage .. tostring(Rv))

	return ev == e
end

return {
	chacha20 = chacha20,
	sha256 = sha256,
	random = random,
	encrypt = encrypt,
	decrypt = decrypt,
	keypair = keypair,
	exchange = exchange,
	sign = sign,
	verify = verify,
	_byteMetatable = util.byteTableMT,
}
