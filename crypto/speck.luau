--!optimize 2
--!native

local speck = {}

local function pad_buffer(buf)
	local len_ = buffer.len(buf)
	local amount = 8 - (len_ % 8)
	local padded = buffer.create(len_ + amount)
	buffer.copy(padded, 0, buf, 0, len_)

	if amount == 8 then
		buffer.writeu32(padded, len_, 0x08080808)
		buffer.writeu32(padded, len_ + 4, 0x08080808)
	elseif amount == 4 then
		buffer.writeu32(padded, len_, amount * 0x01010101)
	else
		for i = len_, len_ + amount - 1 do
			buffer.writeu8(padded, i, amount)
		end
	end

	return padded
end

local function unpad_buffer(buf)
	local len_ = buffer.len(buf)
	if len_ == 0 then return buf end
	local amount = buffer.readu8(buf, len_ - 1)
	local unpadded = buffer.create(len_ - amount)
	buffer.copy(unpadded, 0, buf, 0, len_ - amount)
	return unpadded
end

local function pad_key(key)
	local len_ = buffer.len(key)
	local out = buffer.create(8)
	if len_ >= 8 then
		buffer.writeu32(out, 0, buffer.readu32(key, 0))
		buffer.writeu32(out, 4, buffer.readu32(key, 4))
	else
		buffer.copy(out, 0, key, 0, len_)
		for i = len_, 7 do
			buffer.writeu8(out, i, 0)
		end
	end
	return out
end

local function expand_key(key)
	local b = buffer.readu32(key, 0)
	local a = buffer.readu32(key, 4)
	local round_keys = buffer.create(128)
	buffer.writeu32(round_keys, 0, b)

	for round = 0, 29, 2 do
		a = bit32.bxor(bit32.rrotate(a, 8) + b, round)
		b = bit32.bxor(bit32.lrotate(b, 3), a)
		buffer.writeu32(round_keys, (round + 1) * 4, b)

		a = bit32.bxor(bit32.rrotate(a, 8) + b, round + 1)
		b = bit32.bxor(bit32.lrotate(b, 3), a)
		buffer.writeu32(round_keys, (round + 2) * 4, b)
	end

	a = bit32.bxor(bit32.rrotate(a, 8) + b, 30)
	b = bit32.bxor(bit32.lrotate(b, 3), a)
	buffer.writeu32(round_keys, 124, b)

	return round_keys
end

local function encrypt_blocks(out, data, key, len_)
	for off = 0, len_ - 1, 8 do
		local y = buffer.readu32(data, off)
		local x = buffer.readu32(data, off + 4)
		local b = buffer.readu32(key, 0)
		local a = buffer.readu32(key, 4)

		x = bit32.bxor(bit32.rrotate(x, 8) + y, b)
		y = bit32.bxor(bit32.lrotate(y, 3), x)

		for round = 0, 27, 4 do
			for i = 0, 3 do
				a = bit32.bxor(bit32.rrotate(a, 8) + b, round + i)
				b = bit32.bxor(bit32.lrotate(b, 3), a)
				x = bit32.bxor(bit32.rrotate(x, 8) + y, b)
				y = bit32.bxor(bit32.lrotate(y, 3), x)
			end
		end

		a = bit32.bxor(bit32.rrotate(a, 8) + b, 28)
		b = bit32.bxor(bit32.lrotate(b, 3), a)
		x = bit32.bxor(bit32.rrotate(x, 8) + y, b)
		y = bit32.bxor(bit32.lrotate(y, 3), x)

		a = bit32.bxor(bit32.rrotate(a, 8) + b, 29)
		b = bit32.bxor(bit32.lrotate(b, 3), a)
		x = bit32.bxor(bit32.rrotate(x, 8) + y, b)
		y = bit32.bxor(bit32.lrotate(y, 3), x)

		a = bit32.bxor(bit32.rrotate(a, 8) + b, 30)
		b = bit32.bxor(bit32.lrotate(b, 3), a)
		x = bit32.bxor(bit32.rrotate(x, 8) + y, b)
		y = bit32.bxor(bit32.lrotate(y, 3), x)

		buffer.writeu32(out, off, y)
		buffer.writeu32(out, off + 4, x)
	end
end

local function decrypt_blocks(out, data, round_keys, len_)
	for off = 0, len_ - 1, 8 do
		local y = buffer.readu32(data, off)
		local x = buffer.readu32(data, off + 4)

		for round = 27, 0, -4 do
			for i = 3, 0, -1 do
				y = bit32.rrotate(bit32.bxor(y, x), 3)
				x = bit32.lrotate(bit32.bxor(x, buffer.readu32(round_keys, (round + i + 1) * 4)) - y, 8)
			end
		end

		y = bit32.rrotate(bit32.bxor(y, x), 3)
		x = bit32.lrotate(bit32.bxor(x, buffer.readu32(round_keys, 12)) - y, 8)
		y = bit32.rrotate(bit32.bxor(y, x), 3)
		x = bit32.lrotate(bit32.bxor(x, buffer.readu32(round_keys, 8)) - y, 8)
		y = bit32.rrotate(bit32.bxor(y, x), 3)
		x = bit32.lrotate(bit32.bxor(x, buffer.readu32(round_keys, 4)) - y, 8)
		y = bit32.rrotate(bit32.bxor(y, x), 3)
		x = bit32.lrotate(bit32.bxor(x, buffer.readu32(round_keys, 0)) - y, 8)

		buffer.writeu32(out, off, y)
		buffer.writeu32(out, off + 4, x)
	end
end

function speck.encrypt(data, key)
	local data = pad_buffer(data)
	local key = pad_key(key)
	local len_ = buffer.len(data)
	local out = buffer.create(len_)
	encrypt_blocks(out, data, key, len_)
	return out
end

function speck.decrypt(data, key)
	local key = pad_key(key)
	local round_keys = expand_key(key)
	local len_ = buffer.len(data)
	local out = buffer.create(len_)
	decrypt_blocks(out, data, round_keys, len_)
	return unpad_buffer(out)
end

return speck
