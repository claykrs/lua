--!native
--!optimize 2

local format_string = string.rep("%08x", 8)
local constants = buffer.create(256) do
	local round_constants = {
		0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
		0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
		0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
		0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
		0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
		0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
		0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
		0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
	}

	for i, k in ipairs(round_constants) do
		buffer.writeu32(constants, (i - 1) * 4, k)
	end
end

local function preprocess(contents)
	local content_len = buffer.len(contents)
	local padding = -(content_len + 9) % 64

	local new_len = content_len + 1 + padding + 8
	local new_content = buffer.create(new_len)

	buffer.copy(new_content, 0, contents)
	buffer.writeu8(new_content, content_len, 128)

	local length8 = content_len * 8
	for i = 7, 0, -1 do
		local rem = length8 % 256
		buffer.writeu8(new_content, i + content_len + 1 + padding, rem)
		length8 = (length8 - rem) / 256
	end

	return new_content, new_len
end

local offsets = buffer.create(256)

local function digest_blocks(blocks, length)
	local a, b, c, d = 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a
	local e, f, g, h = 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19

	local consts = constants
	local w = offsets

	for off = 0, length - 1, 64 do
		for bi = 0, 60, 4 do
			buffer.writeu32(w, bi, bit32.byteswap(buffer.readu32(blocks, off + bi)))
		end

		for i = 64, 252, 4 do
			local sub15 = buffer.readu32(w, i - 60)
			local s0 = bit32.bxor(bit32.rrotate(sub15, 7), bit32.rrotate(sub15, 18), bit32.rshift(sub15, 3))

			local sub2 = buffer.readu32(w, i - 8)
			local s1 = bit32.bxor(bit32.rrotate(sub2, 17), bit32.rrotate(sub2, 19), bit32.rshift(sub2, 10))

			local sub7 = buffer.readu32(w, i - 28)
			local sub16 = buffer.readu32(w, i - 64)
			buffer.writeu32(w, i, (sub16 + s0 + sub7 + s1))
		end

		local old_a, old_b, old_c, old_d = a, b, c, d
		local old_e, old_f, old_g, old_h = e, f, g, h

		for bi = 0, 252, 4 do
			local s1 = bit32.bxor(bit32.rrotate(e, 6), bit32.rrotate(e, 11), bit32.rrotate(e, 25))
			local ch = bit32.bxor(bit32.band(e, f), bit32.band(bit32.bnot(e), g))
			local temp1 = h + s1 + ch + buffer.readu32(consts, bi) + buffer.readu32(w, bi)
			h, g, f, e, d = g, f, e, d + temp1, c

			local s0 = bit32.bxor(bit32.rrotate(a, 2), bit32.rrotate(a, 13), bit32.rrotate(a, 22))
			local maj = bit32.bxor(bit32.band(a, b), bit32.band(a, c), bit32.band(b, c))
			c, b, a = b, a, temp1 + s0 + maj
		end

		a = bit32.bor(a + old_a, 0)
		b = bit32.bor(b + old_b, 0)
		c = bit32.bor(c + old_c, 0)
		d = bit32.bor(d + old_d, 0)
		e = bit32.bor(e + old_e, 0)
		f = bit32.bor(f + old_f, 0)
		g = bit32.bor(g + old_g, 0)
		h = bit32.bor(h + old_h, 0)
	end

	return a, b, c, d, e, f, g, h
end

local function sha256(message, salt)
	if salt and buffer.len(salt) > 0 then
		local with_salt = buffer.create(buffer.len(message) + buffer.len(salt))
		buffer.copy(with_salt, 0, message)
		buffer.copy(with_salt, buffer.len(message), salt)
		message = with_salt
	end

	local processed, length = preprocess(message)
	local a, b, c, d, e, f, g, h = digest_blocks(processed, length)

	local digest = buffer.create(32)
	buffer.writeu32(digest, 0, a)
	buffer.writeu32(digest, 4, b)
	buffer.writeu32(digest, 8, c)
	buffer.writeu32(digest, 12, d)
	buffer.writeu32(digest, 16, e)
	buffer.writeu32(digest, 20, f)
	buffer.writeu32(digest, 24, g)
	buffer.writeu32(digest, 28, h)

	return string.format(format_string, a, b, c, d, e, f, g, h), digest
end

return sha256
