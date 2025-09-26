--[[ serializer.lua
    - features:
        pack_u16(values)           : pack array of unsigned 16-bit integers
        unpack_u16(buf)            : unpack array of unsigned 16-bit integers
        pack_i16(values)           : pack array of signed 16-bit integers
        unpack_i16(buf)            : unpack array of signed 16-bit integers
        pack_u32(values)           : pack array of unsigned 32-bit integers
        unpack_u32(buf)            : unpack array of unsigned 32-bit integers
        pack_i32(values)           : pack array of signed 32-bit integers
        unpack_i32(buf)            : unpack array of signed 32-bit integers
        pack_u64(values)           : pack array of unsigned 64-bit integers (as {hi, lo} pairs)
        unpack_u64(buf)            : unpack array of unsigned 64-bit integers (as {hi, lo} pairs)
        pack_i64(values)           : pack array of signed 64-bit integers (as {hi, lo} pairs)
        unpack_i64(buf)            : unpack array of signed 64-bit integers (as {hi, lo} pairs)
        pack_f32(values)           : pack array of 32-bit floats
        unpack_f32(buf)            : unpack array of 32-bit floats
        pack_f64(values)           : pack array of 64-bit floats
        unpack_f64(buf)            : unpack array of 64-bit floats
        pack_bytes(values)         : pack array of bytes (0-255)
        unpack_bytes(buf)          : unpack array of bytes
        pack_string_nt(str)        : pack null-terminated string
        unpack_string_nt(buf, offset) : unpack null-terminated string, returns string and new offset
        pack_string_fixed(str, length) : pack fixed-length string, padding with 0
        unpack_string_fixed(buf, length, offset) : unpack fixed-length string, returns string and new offset
        pack_string_array(arr)     : pack array of null-terminated strings
        unpack_string_array(buf)   : unpack array of null-terminated strings
        pack_vector(v)             : pack Vector2/Vector3/UDim/UDim2/etc as null-terminated tostring
        unpack_vector(buf, offset, type_name) : unpack vector/udim types from string
        pack_table(tbl)            : pack mixed table (auto-detect common Roblox types)
        unpack_table(buf, types)   : unpack mixed buffer given type schema (types = {"i32","string","Vector3",...})
        scramble(buf,key)          : XOR each byte with key
        unscramble(buf,key)        : reverse of scramble (same as scramble)
        obfuscate(buf,shift)       : circular shift of buffer bytes by shift
        unobfuscate(buf,shift)     : reverse circular shift
]]

local function shift_buffer(buf, shift)
	local n = buffer.len(buf)
	if n == 0 then return buffer.create(0) end
	shift = (math.floor(shift or 0) % n)
	local out = buffer.create(n)
	for i = 0, n - 1 do
		local src = (i - shift) % n
		buffer.writeu8(out, i, buffer.readu8(buf, src))
	end
	return out
end

local serializer = {}

function serializer.pack_u16(values)
	local n = #values
	local out = buffer.create(n * 2)
	for i = 1, n do
		buffer.writeu16(out, (i - 1) * 2, values[i])
	end
	return out
end

function serializer.unpack_u16(buf)
	local n = buffer.len(buf) // 2
	local out = {}
	for i = 0, n - 1 do
		out[i + 1] = buffer.readu16(buf, i * 2)
	end
	return out
end

function serializer.pack_i16(values)
	local n = #values
	local out = buffer.create(n * 2)
	for i = 1, n do
		local v = values[i]
		if v < 0 then v = 0x10000 + v end
		buffer.writeu16(out, (i - 1) * 2, v)
	end
	return out
end

function serializer.unpack_i16(buf)
	local n = buffer.len(buf) // 2
	local out = {}
	for i = 0, n - 1 do
		local v = buffer.readu16(buf, i * 2)
		if v > 0x7FFF then v = v - 0x10000 end
		out[i + 1] = v
	end
	return out
end

function serializer.pack_u32(values)
	local n = #values
	local out = buffer.create(n * 4)
	for i = 1, n do
		buffer.writeu32(out, (i - 1) * 4, values[i])
	end
	return out
end

function serializer.unpack_u32(buf)
	local n = buffer.len(buf) // 4
	local out = {}
	for i = 0, n - 1 do
		out[i + 1] = buffer.readu32(buf, i * 4)
	end
	return out
end

function serializer.pack_i32(values)
	local n = #values
	local out = buffer.create(n * 4)
	for i = 1, n do
		local v = values[i]
		if v < 0 then v = 0x100000000 + v end
		buffer.writeu32(out, (i - 1) * 4, v)
	end
	return out
end

function serializer.unpack_i32(buf)
	local n = buffer.len(buf) // 4
	local out = {}
	for i = 0, n - 1 do
		local v = buffer.readu32(buf, i * 4)
		if v > 0x7FFFFFFF then v = v - 0x100000000 end
		out[i + 1] = v
	end
	return out
end

function serializer.pack_u64(values)
	local n = #values
	local out = buffer.create(n * 8)
	for i = 1, n do
		local pair = values[i]
		buffer.writeu32(out, (i - 1) * 8, pair[1])
		buffer.writeu32(out, (i - 1) * 8 + 4, pair[2])
	end
	return out
end

function serializer.unpack_u64(buf)
	local n = buffer.len(buf) // 8
	local out = {}
	for i = 0, n - 1 do
		out[i + 1] = {buffer.readu32(buf, i * 8), buffer.readu32(buf, i * 8 + 4)}
	end
	return out
end

function serializer.pack_i64(values)
	local n = #values
	local out = buffer.create(n * 8)
	for i = 1, n do
		local hi, lo = values[i][1], values[i][2]
		if hi < 0 then hi = 0x100000000 + hi end
		if lo < 0 then lo = 0x100000000 + lo end
		buffer.writeu32(out, (i - 1) * 8, hi)
		buffer.writeu32(out, (i - 1) * 8 + 4, lo)
	end
	return out
end

function serializer.unpack_i64(buf)
	local n = buffer.len(buf) // 8
	local out = {}
	for i = 0, n - 1 do
		local hi = buffer.readu32(buf, i * 8)
		local lo = buffer.readu32(buf, i * 8 + 4)
		if hi > 0x7FFFFFFF then hi = hi - 0x100000000 end
		if lo > 0x7FFFFFFF then lo = lo - 0x100000000 end
		out[i + 1] = {hi, lo}
	end
	return out
end

function serializer.pack_f32(values)
	local n = #values
	local out = buffer.create(n * 4)
	for i = 1, n do
		buffer.writef32(out, (i - 1) * 4, values[i])
	end
	return out
end

function serializer.unpack_f32(buf)
	local n = buffer.len(buf) // 4
	local out = {}
	for i = 0, n - 1 do
		out[i + 1] = buffer.readf32(buf, i * 4)
	end
	return out
end

function serializer.pack_f64(values)
	local n = #values
	local out = buffer.create(n * 8)
	for i = 1, n do
		buffer.writef64(out, (i - 1) * 8, values[i])
	end
	return out
end

function serializer.unpack_f64(buf)
	local n = buffer.len(buf) // 8
	local out = {}
	for i = 0, n - 1 do
		out[i + 1] = buffer.readf64(buf, i * 8)
	end
	return out
end

function serializer.pack_bytes(values)
	local n = #values
	local out = buffer.create(n)
	for i = 1, n do
		buffer.writeu8(out, i - 1, values[i])
	end
	return out
end

function serializer.unpack_bytes(buf)
	local n = buffer.len(buf)
	local out = {}
	for i = 0, n - 1 do
		out[i + 1] = buffer.readu8(buf, i)
	end
	return out
end

function serializer.pack_string_nt(str)
	local len = #str
	local out = buffer.create(len + 1)
	for i = 1, len do
		buffer.writeu8(out, i - 1, string.byte(str, i))
	end
	buffer.writeu8(out, len, 0)
	return out
end

function serializer.unpack_string_nt(buf, offset)
	offset = offset or 0
	local chars = {}
	local i = 0
	while true do
		local b = buffer.readu8(buf, offset + i)
		if b == 0 then break end
		chars[i + 1] = string.char(b)
		i = i + 1
	end
	return table.concat(chars), offset + i + 1
end

function serializer.pack_string_fixed(str, length)
	local out = buffer.create(length)
	local n = #str
	for i = 1, length do
		local b = 0
		if i <= n then b = string.byte(str, i) end
		buffer.writeu8(out, i - 1, b)
	end
	return out
end

function serializer.unpack_string_fixed(buf, length, offset)
	offset = offset or 0
	local chars = {}
	for i = 0, length - 1 do
		chars[i + 1] = string.char(buffer.readu8(buf, offset + i))
	end
	return table.concat(chars), offset + length
end

function serializer.pack_string_array(arr)
	local n = #arr
	local total_len = 0
	for i = 1, n do
		total_len = total_len + #arr[i] + 1
	end
	local out = buffer.create(total_len)
	local pos = 0
	for i = 1, n do
		local str = arr[i]
		local len = #str
		for j = 1, len do
			buffer.writeu8(out, pos, string.byte(str, j))
			pos = pos + 1
		end
		buffer.writeu8(out, pos, 0)
		pos = pos + 1
	end
	return out
end

function serializer.unpack_string_array(buf)
	local out = {}
	local offset = 0
	local len = buffer.len(buf)
	local idx = 1
	while offset < len do
		local chars = {}
		local i = 0
		while true do
			local b = buffer.readu8(buf, offset + i)
			if b == 0 then break end
			chars[i + 1] = string.char(b)
			i = i + 1
		end
		out[idx] = table.concat(chars)
		idx = idx + 1
		offset = offset + i + 1
	end
	return out
end

function serializer.pack_vector(v)
	return serializer.pack_string_nt(tostring(v))
end

local function read_u16_at(buf, offset)
	local val = buffer.readu16(buf, offset)
	return val, offset + 2
end

local function read_i16_at(buf, offset)
	local v = buffer.readu16(buf, offset)
	if v > 0x7FFF then v = v - 0x10000 end
	return v, offset + 2
end

local function read_u32_at(buf, offset)
	local val = buffer.readu32(buf, offset)
	return val, offset + 4
end

local function read_i32_at(buf, offset)
	local v = buffer.readu32(buf, offset)
	if v > 0x7FFFFFFF then v = v - 0x100000000 end
	return v, offset + 4
end

local function read_u64_at(buf, offset)
	local hi = buffer.readu32(buf, offset)
	local lo = buffer.readu32(buf, offset + 4)
	return {hi, lo}, offset + 8
end

local function read_i64_at(buf, offset)
	local hi = buffer.readu32(buf, offset)
	local lo = buffer.readu32(buf, offset + 4)
	if hi > 0x7FFFFFFF then hi = hi - 0x100000000 end
	if lo > 0x7FFFFFFF then lo = lo - 0x100000000 end
	return {hi, lo}, offset + 8
end

local function read_f32_at(buf, offset)
	local v = buffer.readf32(buf, offset)
	return v, offset + 4
end

local function read_f64_at(buf, offset)
	local v = buffer.readf64(buf, offset)
	return v, offset + 8
end

local function read_byte_at(buf, offset)
	local v = buffer.readu8(buf, offset)
	return v, offset + 1
end

local function read_string_nt_at(buf, offset)
	return serializer.unpack_string_nt(buf, offset)
end

local readers = {
	i16 = read_i16_at,
	u16 = read_u16_at,
	i32 = read_i32_at,
	u32 = read_u32_at,
	i64 = read_i64_at,
	u64 = read_u64_at,
	f32 = read_f32_at,
	f64 = read_f64_at,
	number = read_f64_at,
	byte = read_byte_at,
	u8 = read_byte_at,
	string = read_string_nt_at,
	Vector2 = function(b, o) return serializer.unpack_vector(b, o, "Vector2") end,
	Vector3 = function(b, o) return serializer.unpack_vector(b, o, "Vector3") end,
	Vector2int16 = function(b, o) return serializer.unpack_vector(b, o, "Vector2int16") end,
	Vector3int16 = function(b, o) return serializer.unpack_vector(b, o, "Vector3int16") end,
	UDim = function(b, o) return serializer.unpack_vector(b, o, "UDim") end,
	UDim2 = function(b, o) return serializer.unpack_vector(b, o, "UDim2") end,
	boolean = function(b, o) local v, no = read_byte_at(b, o) return (v ~= 0), no end,
}


function serializer.unpack_vector(buf, offset, t)
	offset = offset or 0
	local str, no = serializer.unpack_string_nt(buf, offset)
	if t:find("Vector2") then
		local x, y = str:match("%(([^,]+),([^,]+)%)")
		return Vector2.new(tonumber(x), tonumber(y)), no
	elseif t:find("Vector3") then
		local x, y, z = str:match("%(([^,]+),([^,]+),([^,]+)%)")
		return Vector3.new(tonumber(x), tonumber(y), tonumber(z)), no
	elseif t == "UDim" then
		local scale, offset_val = str:match("UDim%s*%(([^,]+),([^,]+)%)")
		return UDim.new(tonumber(scale), tonumber(offset_val)), no
	elseif t == "UDim2" then
		local xscale, xoffset, yscale, yoffset = str:match("UDim2%s*%(([^,]+),([^,]+),([^,]+),([^,]+)%)")
		return UDim2.new(tonumber(xscale), tonumber(xoffset), tonumber(yscale), tonumber(yoffset)), no
	else
		return str, no
	end
end

function serializer.unpack_value(buf, offset, t)
	offset = offset or 0
	local reader = readers[t]
	if not reader then error("unsupported type: " .. tostring(t)) end
	return reader(buf, offset)
end


function serializer.pack_table(tbl)
	local buffers = {}
	local total_len = 0
	for i = 1, #tbl do
		local v = tbl[i]
		local t = typeof(v)
		local b
		if t == "number" then
			if math.floor(v) == v then
				b = serializer.pack_i32({v})
			else
				b = serializer.pack_f64({v})
			end
		elseif t == "string" then
			b = serializer.pack_string_nt(v)
		elseif t == "table" then
			if #v == 2 and type(v[1]) == "number" and type(v[2]) == "number" then
				b = serializer.pack_i64({v})
			else
				error("unsupported table format")
			end
		elseif t:find("Vector") or t:find("UDim") then
			b = serializer.pack_vector(v)
		elseif t == "boolean" then
			b = serializer.pack_bytes({v and 1 or 0})
		else
			error("unsupported type: " .. tostring(t))
		end
		buffers[#buffers + 1] = b
		total_len = total_len + buffer.len(b)
	end
	local out = buffer.create(total_len)
	local pos = 0
	for i = 1, #buffers do
		local b = buffers[i]
		local bl = buffer.len(b)
		for j = 0, bl - 1 do
			buffer.writeu8(out, pos, buffer.readu8(b, j))
			pos = pos + 1
		end
	end
	return out
end

function serializer.unpack_table(buf, types)
	if not types then error("types schema required for unpack_table") end
	local out = {}
	local offset = 0
	for i = 1, #types do
		local v, no = serializer.unpack_value(buf, offset, types[i])
		out[i] = v
		offset = no
	end
	return out
end

function serializer.scramble(buf, key)
	local n = buffer.len(buf)
	local out = buffer.create(n)
	for i = 0, n - 1 do
		local b = buffer.readu8(buf, i)
		buffer.writeu8(out, i, bit32.bxor(b, key))
	end
	return out
end

function serializer.unscramble(buf, key)
	return serializer.scramble(buf, key)
end

function serializer.obfuscate(buf, shift)
	return shift_buffer(buf, shift)
end

function serializer.unobfuscate(buf, shift)
	return shift_buffer(buf, -shift)
end

return serializer
