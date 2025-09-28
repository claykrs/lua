local serializer = {
	_endln_seperator = 0xF000,
	_serializable_types = {
		string  = 0xF001,
		number  = 0xF002,
		boolean = 0xF003,
		table   = 0xF00A
	},
	_key = 0xAA
}

for name, id in serializer._serializable_types do
	serializer._serializable_types[id] = name
end

local function resolve(v)
	local types = serializer._serializable_types
	return types[v] or types[typeof(v)] or error("unsupported type")
end

local function obf_u8(val)
	return bit32.bxor(val, serializer._key)
end

local function deobf_u8(val)
	return bit32.bxor(val, serializer._key)
end

local function write_obf_u16(buf, offset, val)
	local high = bit32.band(bit32.rshift(val, 8), 0xFF)
	local low = bit32.band(val, 0xFF)
	buffer.writeu8(buf, offset, obf_u8(high))
	buffer.writeu8(buf, offset + 1, obf_u8(low))
end

local function read_obf_u16(buf, offset)
	local high = deobf_u8(buffer.readu8(buf, offset))
	local low = deobf_u8(buffer.readu8(buf, offset + 1))
	return high * 256 + low
end

local function write_obf_f64(buf, offset, val)
	local tmp = buffer.create(8)
	buffer.writef64(tmp, 0, val)
	for i = 0, 7 do
		local b = buffer.readu8(tmp, i)
		buffer.writeu8(buf, offset + i, obf_u8(b))
	end
end

local function read_obf_f64(buf, offset)
	local tmp = buffer.create(8)
	for i = 0, 7 do
		local b = buffer.readu8(buf, offset + i)
		buffer.writeu8(tmp, i, deobf_u8(b))
	end
	return buffer.readf64(tmp, 0)
end

local function sizeof(v)
	local t = typeof(v)
	local size = 2

	if t == "string" then
		size += #v
	elseif t == "number" then
		size += 8
	elseif t == "boolean" then
		size += 1
	elseif t == "table" then
		local nested_buf = serializer.pack(v)
		size += buffer.len(nested_buf)
	end

	size += 2
	return size
end

function serializer.pack(tbl)
	local size = 0
	for _, v in tbl do
		size += sizeof(v)
	end
	
	local buf = buffer.create(size)
	local offset = 0

	for _, v in tbl do
		write_obf_u16(buf, offset, resolve(v))
		offset += 2
		local t = typeof(v)
		if t == "string" then
			for i = 1, #v do
				buffer.writeu8(buf, offset, obf_u8(v:byte(i)))
				offset += 1
			end
		elseif t == "number" then
			write_obf_f64(buf, offset, v)
			offset += 8
		elseif t == "boolean" then
			buffer.writeu8(buf, offset, obf_u8(v and 1 or 0))
			offset += 1
		elseif t == "table" then
			local nested_buf = serializer.pack(v)
			buffer.copy(buf, offset, nested_buf)
			offset += buffer.len(nested_buf)
		end
		write_obf_u16(buf, offset, serializer._endln_seperator)
		offset += 2
	end

	return buf
end

function serializer.unpack(buf, offset)
	offset = offset or 0
	local tbl = {}
	local len = buffer.len(buf)

	while offset < len do
		if offset + 1 > len then break end
		local id = read_obf_u16(buf, offset)
		offset += 2
		local t = resolve(id)
		if t == "string" then
			local chars = {}
			while offset < len - 1 do
				local next_two = read_obf_u16(buf, offset)
				if next_two == serializer._endln_seperator then
					offset += 2
					break
				end
				local b = buffer.readu8(buf, offset)
				offset += 1
				table.insert(chars, string.char(deobf_u8(b)))
			end
			table.insert(tbl, table.concat(chars))
		elseif t == "number" then
			if offset + 8 > len then break end
			local n = read_obf_f64(buf, offset)
			offset += 8
			if offset + 1 <= len then
				local next_two = read_obf_u16(buf, offset)
				if next_two == serializer._endln_seperator then offset += 2 end
			end
			table.insert(tbl, n)
		elseif t == "boolean" then
			local b = deobf_u8(buffer.readu8(buf, offset)) ~= 0
			offset += 1
			if offset + 1 <= len then
				local next_two = read_obf_u16(buf, offset)
				if next_two == serializer._endln_seperator then offset += 2 end
			end
			table.insert(tbl, b)
		elseif t == "table" then
			local nested_tbl, new_offset = serializer.unpack(buf, offset)
			table.insert(tbl, nested_tbl)
			offset = new_offset
			if offset + 1 <= len then
				local next_two = read_obf_u16(buf, offset)
				if next_two == serializer._endln_seperator then offset += 2 end
			end
		end
	end

	return tbl, offset
end

function serializer.encode(buf)
	local n = buffer.len(buf)
	local out = buffer.create(n)
	for i = 0, n - 1 do
		local b = buffer.readu8(buf, i)
		buffer.writeu8(out, i, obf_u8(b))
	end
	return out
end

function serializer.decode(buf)
	local n = buffer.len(buf)
	local out = buffer.create(n)
	for i = 0, n - 1 do
		local b = buffer.readu8(buf, i)
		buffer.writeu8(out, i, deobf_u8(b))
	end
	return out
end

return serializer
