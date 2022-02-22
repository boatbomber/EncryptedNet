local util = {}

util.byteTableMT = {
	__tostring = function(a)
		return string.char(table.unpack(a))
	end,
	__index = {
		toHex = function(self)
			return ("%02x"):rep(#self):format(table.unpack(self))
		end,
		isEqual = function(self, t)
			if type(t) ~= "table" then
				return false
			end
			if #self ~= #t then
				return false
			end
			local ret = 0
			for i = 1, #self do
				ret = bit32.bor(ret, bit32.bxor(self[i], t[i]))
			end
			return ret == 0
		end,
	},
}

function util.stringToByteArray(str)
	if type(str) ~= "string" then
		return {}
	end

	if #str < 7000 then
		return table.pack(str:byte(1, -1))
	end

	local arr = table.create(#str)
	for i = 1, #str do
		arr[i] = string.byte(str, i)
	end
	return arr
end

return util
