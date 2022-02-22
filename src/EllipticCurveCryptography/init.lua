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
		epoch = epoch / 256
		epoch = epoch - epoch % 1
	end

	return nonce
end

local function encrypt(data, key)
	local encKey = sha256.hmac("encKey", key)
	local macKey = sha256.hmac("macKey", key)
	local nonce = getNonceFromEpoch()

	local ciphertext = chacha20.crypt(data, encKey, nonce)

	local result = nonce
	for i = 1, #ciphertext do
		table.insert(result, ciphertext[i])
	end

	local mac = sha256.hmac(result, macKey)
	for i = 1, #mac do
		table.insert(result, mac[i])
	end

	return setmetatable(result, util.byteTableMT)
end

local function decrypt(data, key)
	local data = type(data) == "table" and { unpack(data) } or { tostring(data):byte(1, -1) }
	local encKey = sha256.hmac("encKey", key)
	local macKey = sha256.hmac("macKey", key)
	local mac = sha256.hmac({ unpack(data, 1, #data - 32) }, macKey)
	local messageMac = { unpack(data, #data - 31) }
	assert(mac:isEqual(messageMac), "invalid mac")
	local nonce = { unpack(data, 1, 12) }
	local ciphertext = { unpack(data, 13, #data - 32) }
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
	local message = type(message) == "table" and string.char(unpack(message)) or tostring(message)
	local privateKey = type(privateKey) == "table" and string.char(unpack(privateKey)) or tostring(privateKey)
	local x = modq.decodeModQ(privateKey)
	local k = modq.randomModQ()
	local R = curve.G * k
	local e = modq.hashModQ(message .. tostring(R))
	local s = k - x * e

	e = e:encode()
	s = s:encode()

	local result, result_len = e, #e
	for i = 1, #s do
		result[result_len + i] = s[i]
	end

	return setmetatable(result, util.byteTableMT)
end

local function verify(publicKey, message, signature)
	local message = type(message) == "table" and string.char(unpack(message)) or tostring(message)
	local sigLen = #signature
	local Y = curve.pointDecode(publicKey)
	local e = modq.decodeModQ({ unpack(signature, 1, sigLen / 2) })
	local s = modq.decodeModQ({ unpack(signature, sigLen / 2 + 1) })
	local Rv = curve.G * s + Y * e
	local ev = modq.hashModQ(message .. tostring(Rv))

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
