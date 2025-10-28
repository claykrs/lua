--!optimize 2
--!native

local create = buffer.create
local len = buffer.len
local copy = buffer.copy
local fromstring = buffer.fromstring
local readstring = buffer.readstring
local writeu8 = buffer.writeu8
local readu8 = buffer.readu8
local writeu32 = buffer.writeu32
local readu32 = buffer.readu32
local writef64 = buffer.writef64
local readf64 = buffer.readf64

local band = bit32.band
local rshift = bit32.rshift
local lshift = bit32.lshift

local function from_u32(n)
	local a = rshift(n, 24)
	local b = band(rshift(n,16), 0xFF)
	local c = band(rshift(n,8), 0xFF)
	local d = band(n, 0xFF)
	return a,b,c,d
end

local function to_u32(a,b,c,d)
	return a * 16777216 + b * 65536 + c * 256 + d
end

local function write_len32(buf, offset, n)
	local a,b,c,d = from_u32(n)
	writeu8(buf, offset, a); offset += 1
	writeu8(buf, offset, b); offset += 1
	writeu8(buf, offset, c); offset += 1
	writeu8(buf, offset, d); offset += 1
	return offset
end 

local function read_len32(buf, offset, total_len)
	if offset + 4 > total_len then
		error("truncated")
	end 
	local a = readu8(buf, offset); offset += 1
	local b = readu8(buf, offset); offset += 1
	local c = readu8(buf, offset); offset += 1
	local d = readu8(buf, offset); offset += 1
	return to_u32(a,b,c,d), offset
end

local type_registry = {}

type_registry.number = {
	write = function(buf, offset, num)
		writef64(buf, offset, num)
		return offset + 8
	end,
	read = function(buf, offset)
		local v = readf64(buf, offset)
		return v, offset + 8
	end
}

type_registry.boolean = {
	write = function(buf, offset, b)
		writeu8(buf, offset, b and 1 or 0)
		return offset + 1
	end,
	read = function(buf, offset)
		return readu8(buf, offset) ~= 0, offset + 1
	end
}

type_registry["nil"] = {
	write = function(_buf, offset, _)
		return offset
	end,
	read = function(_buf, offset)
		return nil, offset
	end
}

type_registry.string = {
	write = function(buf, offset, s)
		local slen = #s
		offset = write_len32(buf, offset, slen)
		if slen > 0 then
			local sb = fromstring(s)
			copy(buf, offset, sb, 0, slen)
			offset = offset + slen
		end
		return offset
	end,
	read = function(buf, offset)
		local slen
		slen, offset = read_len32(buf, offset)
		if slen == 0 then
			return "", offset
		end
		local s = readstring(buf, offset, slen)
		return s, offset + slen
	end
}

type_registry.buffer = {
	write = function(buf, offset, b)
		local blen = len(b)
		offset = write_len32(buf, offset, blen)
		if blen > 0 then
			copy(buf, offset, b, 0, blen)
			offset = offset + blen
		end
		return offset
	end,
	read = function(buf, offset)
		local blen
		blen, offset = read_len32(buf, offset)
		if blen == 0 then
			return create(0), offset
		end
		local out = create(blen)
		copy(out, 0, buf, offset, blen)
		return out, offset + blen
	end
}

type_registry.Vector3 = {
	write = function(buf, offset, v)
		writef64(buf, offset, v.X); offset = offset + 8
		writef64(buf, offset, v.Y); offset = offset + 8
		writef64(buf, offset, v.Z); offset = offset + 8
		return offset
	end,
	read = function(buf, offset)
		local x = readf64(buf, offset); offset = offset + 8
		local y = readf64(buf, offset); offset = offset + 8
		local z = readf64(buf, offset); offset = offset + 8
		return Vector3.new(x, y, z), offset
	end
}

type_registry.Vector2 = {
	write = function(buf, offset, v)
		writef64(buf, offset, v.X); offset = offset + 8
		writef64(buf, offset, v.Y); offset = offset + 8
		return offset
	end,
	read = function(buf, offset)
		local x = readf64(buf, offset); offset = offset + 8
		local y = readf64(buf, offset); offset = offset + 8
		return Vector2.new(x, y), offset
	end
}

type_registry.CFrame = {
	write = function(buf, offset, cf)
		local vectors = { cf.Position, cf.XVector, cf.YVector, cf.ZVector }
		for i = 1, 4 do
			local vec = vectors[i]
			writef64(buf, offset, vec.X); offset = offset + 8
			writef64(buf, offset, vec.Y); offset = offset + 8
			writef64(buf, offset, vec.Z); offset = offset + 8
		end
		return offset
	end,
	read = function(buf, offset)
		local p = Vector3.new(readf64(buf, offset), readf64(buf, offset + 8), readf64(buf, offset + 16))
		local x = Vector3.new(readf64(buf, offset + 24), readf64(buf, offset + 32), readf64(buf, offset + 40))
		local y = Vector3.new(readf64(buf, offset + 48), readf64(buf, offset + 56), readf64(buf, offset + 64))
		local z = Vector3.new(readf64(buf, offset + 72), readf64(buf, offset + 80), readf64(buf, offset + 88))
		return CFrame.fromMatrix(p, x, y, z), offset + 96
	end
}

type_registry.UDim = {
	write = function(buf, offset, u)
		offset = type_registry.number.write(buf, offset, u.Scale)
		offset = type_registry.number.write(buf, offset, u.Offset)
		return offset
	end,
	read = function(buf, offset)
		local s; s, offset = type_registry.number.read(buf, offset)
		local o; o, offset = type_registry.number.read(buf, offset)
		return UDim.new(s, o), offset
	end
}

type_registry.UDim2 = {
	write = function(buf, offset, u)
		offset = type_registry.UDim.write(buf, offset, u.X)
		offset = type_registry.UDim.write(buf, offset, u.Y)
		return offset
	end,
	read = function(buf, offset)
		local x; x, offset = type_registry.UDim.read(buf, offset)
		local y; y, offset = type_registry.UDim.read(buf, offset)
		return UDim2.new(x, y), offset
	end
}

type_registry.Instance = {
	write = function(buf, offset, inst)
		local ok, path = pcall(function() return inst:GetFullName() end)
		if not ok or type(path) ~= "string" then
			path = tostring(inst)
		end
		return type_registry.string.write(buf, offset, path)
	end,
	read = function(buf, offset)
		local path
		path, offset = type_registry.string.read(buf, offset)

		local node = game
		for part in string.gmatch(path, "[^%.]+") do
			if type(node.FindFirstChild) ~= "function" then
				node = nil
				break
			end
			node = node:FindFirstChild(part)
			if not node then break end
		end

		if node then
			return node, offset
		end

		return path, offset
	end
}

type_registry.EnumItem = {
	write = function(buf, offset, e)
		local s = tostring(e)
		return type_registry.string.write(buf, offset, s)
	end,
	read = function(buf, offset)
		local s; s, offset = type_registry.string.read(buf, offset)
		return s, offset
	end
}

type_registry._unsupported_type = {
	write = function(buf, offset, v)
		local s = typeof(v) .. " " .. tostring(v)
		return type_registry.string.write(buf, offset, s)
	end,
	read = function(buf, offset)
		return type_registry.string.read(buf, offset)
	end
}

local types = type_registry
	-- combined from 2 files into 1

local type_order = {
	"nil",
	"number","boolean","string","buffer","table",
	"Vector3","Vector2","CFrame","UDim","UDim2",
	"Instance","EnumItem","_unsupported_type"
}

local type_to_id = {}
local id_to_type = {}
for i, name in ipairs(type_order) do
	type_to_id[name] = i
	id_to_type[i] = name
end

local reg = types

local function write_table(buf, offset, tbl, seen)
	if seen[tbl] then error("cycle detected") end
	seen[tbl] = true

	local count = 0
	for _ in tbl do count += 1 end
	offset = write_len32(buf, offset, count)

	for k, v in tbl do
		local kt = typeof(k)
		local kid = type_to_id[kt] or type_to_id._unsupported_type
		writeu8(buf, offset, kid); offset += 1
		if kt == "table" then
			offset = write_table(buf, offset, k, seen)
		elseif reg[kt] and reg[kt].write then
			offset = reg[kt].write(buf, offset, k)
		else
			offset = reg._unsupported_type.write(buf, offset, k)
		end

		local vt = typeof(v)
		local vid = type_to_id[vt] or type_to_id._unsupported_type
		writeu8(buf, offset, vid); offset += 1
		if vt == "table" then
			offset = write_table(buf, offset, v, seen)
		elseif reg[vt] and reg[vt].write then
			offset = reg[vt].write(buf, offset, v)
		else
			offset = reg._unsupported_type.write(buf, offset, v)
		end
	end

	seen[tbl] = nil
	return offset
end

local function read_table(buf, offset, total_len)
	local count
	count, offset = read_len32(buf, offset, total_len)
	local out = {}
	for i = 1, count do
		local kid = readu8(buf, offset); offset += 1
		local ktype = id_to_type[kid] or "_unsupported_type"
		local key
		if ktype == "table" then
			key, offset = read_table(buf, offset, total_len)
		elseif ktype == "nil" then
			key = nil
		else
			local reader = (reg[ktype] and reg[ktype].read) or reg._unsupported_type.read
			key, offset = reader(buf, offset)
		end

		local vid = readu8(buf, offset); offset += 1
		local vtype = id_to_type[vid] or "_unsupported_type"
		local val
		if vtype == "table" then
			val, offset = read_table(buf, offset, total_len)
		elseif vtype == "nil" then
			val = nil
		else
			local reader = (reg[vtype] and reg[vtype].read) or reg._unsupported_type.read
			val, offset = reader(buf, offset)
		end

		out[key] = val
	end
	return out, offset
end

local function write_any(buf, offset, v, seen)
	local t = typeof(v)
	local id = type_to_id[t] or type_to_id._unsupported_type
	writeu8(buf, offset, id); offset += 1

	if t == "nil" then
		return offset
	elseif t == "table" then
		return write_table(buf, offset, v, seen)
	else
		local writer = (reg[t] and reg[t].write) or reg._unsupported_type.write
		return writer(buf, offset, v)
	end
end

local function read_any(buf, offset, total_len)
	local id = readu8(buf, offset); offset += 1
	local t = id_to_type[id] or "_unsupported_type"

	if t == "nil" then
		return nil, offset
	elseif t == "table" then
		return read_table(buf, offset, total_len)
	else
		local reader = (reg[t] and reg[t].read) or reg._unsupported_type.read
		return reader(buf, offset)
	end
end

return {
	pack = function(value)
		local scratch = create(8192)
		local offset = write_any(scratch, 0, value, {})
		local out = create(offset)
		copy(out, 0, scratch, 0, offset)
		return out
	end,
	unpack = function(buf)
		local total_len = len(buf)
		local v, _ = read_any(buf, 0, total_len)
		return v
	end
}
