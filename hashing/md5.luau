--!native
--!optimize 2

local format_string = string.rep("%08x", 4)
local block_size = 64

local constants = {
	0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee, 0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
	0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be, 0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
	0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa, 0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
	0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed, 0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
	0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c, 0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
	0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05, 0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
	0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039, 0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
	0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1, 0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391
}

local shifts = {
	7,12,17,22,7,12,17,22,7,12,17,22,7,12,17,22,
	5,9,14,20,5,9,14,20,5,9,14,20,5,9,14,20,
	4,11,16,23,4,11,16,23,4,11,16,23,4,11,16,23,
	6,10,15,21,6,10,15,21,6,10,15,21,6,10,15,21
}

local offsets = table.create(64)

local function preprocess(msg)
	local len = buffer.len(msg)
	local bit_len = len * 8
	local pad_len = (56 - ((len + 1) % 64)) % 64
	local new_len = len + 1 + pad_len + 8
	local new_msg = buffer.create(new_len)

	buffer.copy(new_msg, 0, msg)
	buffer.writeu8(new_msg, len, 0x80)

	local len_offset = len + 1 + pad_len
	for i = 0, 7 do
		buffer.writeu8(new_msg, len_offset + i, bit_len % 256)
		bit_len = bit32.rshift(bit_len, 8)
	end

	return new_msg, new_len
end

local function digest_blocks(blocks, length)
	local a,b,c,d = 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476

	for off = 0, length - 1, 64 do
		for i = 0, 15 do
			offsets[i + 1] = buffer.readu32(blocks, off + i*4)
		end

		local old_a, old_b, old_c, old_d = a, b, c, d
		local temp, func = 0, 0

		for r = 0, 15 do
			local chunk = offsets[r + 1]
			func = bit32.bxor(old_d, bit32.band(old_b, bit32.bxor(old_c, old_d)))
			temp = old_d; old_d = old_c; old_c = old_b
			old_b = old_b + bit32.lrotate(old_a + func + constants[r + 1] + chunk, shifts[r + 1])
			old_a = temp
		end

		for r = 16, 31 do
			local chunk = offsets[(5*r + 1) % 16 + 1]
			func = bit32.bxor(old_c, bit32.band(old_d, bit32.bxor(old_b, old_c)))
			temp = old_d; old_d = old_c; old_c = old_b
			old_b = old_b + bit32.lrotate(old_a + func + constants[r + 1] + chunk, shifts[r + 1])
			old_a = temp
		end

		for r = 32, 47 do
			local chunk = offsets[(3*r + 5) % 16 + 1]
			func = bit32.bxor(old_b, old_c, old_d)
			temp = old_d; old_d = old_c; old_c = old_b
			old_b = old_b + bit32.lrotate(old_a + func + constants[r + 1] + chunk, shifts[r + 1])
			old_a = temp
		end

		for r = 48, 63 do
			local chunk = offsets[(7*r) % 16 + 1]
			func = bit32.bxor(old_c, bit32.bor(old_b, bit32.bnot(old_d)))
			temp = old_d; old_d = old_c; old_c = old_b
			old_b = old_b + bit32.lrotate(old_a + func + constants[r + 1] + chunk, shifts[r + 1])
			old_a = temp
		end

		a = bit32.bor(old_a + a, 0)
		b = bit32.bor(old_b + b, 0)
		c = bit32.bor(old_c + c, 0)
		d = bit32.bor(old_d + d, 0)
	end

	return bit32.byteswap(a), bit32.byteswap(b), bit32.byteswap(c), bit32.byteswap(d)
end

local function md5(msg, salt)
	if salt and buffer.len(salt) > 0 then
		local combined = buffer.create(buffer.len(msg) + buffer.len(salt))
		buffer.copy(combined, 0, msg)
		buffer.copy(combined, buffer.len(msg), salt)
		msg = combined
	end

	local processed, length = preprocess(msg)
	local a, b, c, d = digest_blocks(processed, length)
	local digest = buffer.create(16)

	buffer.writeu32(digest, 0, a)
	buffer.writeu32(digest, 4, b)
	buffer.writeu32(digest, 8, c)
	buffer.writeu32(digest, 12, d)

	return string.format(format_string, a, b, c, d), digest
end

return md5
