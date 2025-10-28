--!native
--!optimize 2

local aes = {}

local sbox_16bit = buffer.create(131072)
local smix_table0 = buffer.create(65536)
local smix_table1 = buffer.create(65536)

local invs_xor_table = buffer.create(65536)
local invmix_table0 = buffer.create(65536)
local invmix_table1 = buffer.create(65536)

local key_configs = {
	[16] = {expanded_length = 176, material_length = 128},
	[24] = {expanded_length = 208, material_length = 160},
	[32] = {expanded_length = 240, material_length = 192}
}

local substitution_box, inverse_substitution_box = buffer.create(256), buffer.create(256) do
	local gmul3, gmul9, gmul11 = buffer.create(256), buffer.create(256), buffer.create(256)

	local function galois_field_multiply(a, b)
		local prod = 0
		for _ = 0, 7 do
			if b % 2 == 1 then
				prod = bit32.bxor(prod, a)
			end
			a = a >= 128 and bit32.bxor((a * 2) % 256, 27) or (a * 2) % 256
			b = math.floor(b / 2)
		end
		return prod
	end

	local p = 1
	local q = 1
	buffer.writeu8(substitution_box, 0, 99)

	for _ = 1, 255 do
		p = bit32.bxor(p, p * 2, p < 128 and 0 or 27) % 256
		q = bit32.bxor(q, q * 2)
		q = bit32.bxor(q, q * 4)
		q = bit32.bxor(q, q * 16) % 256
		if q >= 128 then
			q = bit32.bxor(q, 9)
		end

		local temp = bit32.bxor(
			q,
			q % 128 * 2 + q / 128,
			q % 64 * 4 + q / 64,
			q % 32 * 8 + q / 32,
			q % 16 * 16 + q / 16,
			99
		)

		buffer.writeu8(substitution_box, p, temp)
		buffer.writeu8(inverse_substitution_box, temp, p)
		buffer.writeu8(gmul3, p, galois_field_multiply(3, p))
		buffer.writeu8(gmul9, p, galois_field_multiply(9, p))
		buffer.writeu8(gmul11, p, galois_field_multiply(11, p))
	end

	local tbl_index = 0
	for outer = 0, 255 do
		local pval = buffer.readu8(substitution_box, outer)
		local pbytes = pval * 256
		local g2 = galois_field_multiply(2, pval)
		local g13 = galois_field_multiply(13, outer)
		local g14 = galois_field_multiply(14, outer)

		for inner = 0, 255 do
			local qval = buffer.readu8(substitution_box, inner)

			buffer.writeu16(sbox_16bit, tbl_index * 2, pbytes + qval)
			buffer.writeu8(invs_xor_table, tbl_index, buffer.readu8(inverse_substitution_box, bit32.bxor(outer, inner)))
			buffer.writeu8(smix_table0, tbl_index, bit32.bxor(g2, buffer.readu8(gmul3, qval)))
			buffer.writeu8(smix_table1, tbl_index, bit32.bxor(pval, qval))
			buffer.writeu8(invmix_table0, tbl_index, bit32.bxor(g14, buffer.readu8(gmul11, inner)))
			buffer.writeu8(invmix_table1, tbl_index, bit32.bxor(g13, buffer.readu8(gmul9, inner)))
			tbl_index += 1
		end
	end
end

local function expand_key_schedule(key, key_len, out_buf)
	buffer.copy(out_buf, 0, key, 0, key_len)

	local word = bit32.rrotate(buffer.readu32(out_buf, key_len - 4), 8)
	local round_constant = 0.5
	local sbox16 = sbox_16bit

	if key_len == 32 then
		for ko = 32, 192, 32 do
			round_constant = round_constant * 2 % 229
			local sbox_lookup = buffer.readu16(sbox16, math.floor(word / 65536) * 2) * 65536 + buffer.readu16(sbox16, (word % 65536) * 2)
			word = bit32.bxor(buffer.readu32(out_buf, ko - 32), sbox_lookup, round_constant)
			buffer.writeu32(out_buf, ko, word)

			local w1 = bit32.bxor(buffer.readu32(out_buf, ko - 28), word)
			buffer.writeu32(out_buf, ko + 4, w1)
			local w2 = bit32.bxor(buffer.readu32(out_buf, ko - 24), w1)
			buffer.writeu32(out_buf, ko + 8, w2)
			local w3 = bit32.bxor(buffer.readu32(out_buf, ko - 20), w2)
			buffer.writeu32(out_buf, ko + 12, w3)

			sbox_lookup = buffer.readu16(sbox16, math.floor(w3 / 65536) * 2) * 65536 + buffer.readu16(sbox16, (w3 % 65536) * 2)
			word = bit32.bxor(buffer.readu32(out_buf, ko - 16), sbox_lookup)
			buffer.writeu32(out_buf, ko + 16, word)

			w1 = bit32.bxor(buffer.readu32(out_buf, ko - 12), word)
			buffer.writeu32(out_buf, ko + 20, w1)
			w2 = bit32.bxor(buffer.readu32(out_buf, ko - 8), w1)
			buffer.writeu32(out_buf, ko + 24, w2)
			word = bit32.bxor(buffer.readu32(out_buf, ko - 4), w2)
			buffer.writeu32(out_buf, ko + 28, word)
			word = bit32.rrotate(word, 8)
		end

		local sbox_lookup = buffer.readu16(sbox16, math.floor(word / 65536) * 2) * 65536 + buffer.readu16(sbox16, (word % 65536) * 2)
		word = bit32.bxor(buffer.readu32(out_buf, 192), sbox_lookup, 64)
		buffer.writeu32(out_buf, 224, word)

		local w1 = bit32.bxor(buffer.readu32(out_buf, 196), word)
		buffer.writeu32(out_buf, 228, w1)
		local w2 = bit32.bxor(buffer.readu32(out_buf, 200), w1)
		buffer.writeu32(out_buf, 232, w2)
		buffer.writeu32(out_buf, 236, bit32.bxor(buffer.readu32(out_buf, 204), w2))

	elseif key_len == 24 then
		for ko = 24, 168, 24 do
			round_constant = round_constant * 2 % 229
			local sbox_lookup = buffer.readu16(sbox16, math.floor(word / 65536) * 2) * 65536 + buffer.readu16(sbox16, (word % 65536) * 2)
			word = bit32.bxor(buffer.readu32(out_buf, ko - 24), sbox_lookup, round_constant)
			buffer.writeu32(out_buf, ko, word)

			local w1 = bit32.bxor(buffer.readu32(out_buf, ko - 20), word)
			buffer.writeu32(out_buf, ko + 4, w1)
			local w2 = bit32.bxor(buffer.readu32(out_buf, ko - 16), w1)
			buffer.writeu32(out_buf, ko + 8, w2)
			local w3 = bit32.bxor(buffer.readu32(out_buf, ko - 12), w2)
			buffer.writeu32(out_buf, ko + 12, w3)
			local w4 = bit32.bxor(buffer.readu32(out_buf, ko - 8), w3)
			buffer.writeu32(out_buf, ko + 16, w4)
			word = bit32.bxor(buffer.readu32(out_buf, ko - 4), w4)
			buffer.writeu32(out_buf, ko + 20, word)
			word = bit32.rrotate(word, 8)
		end

		local sbox_lookup = buffer.readu16(sbox16, math.floor(word / 65536) * 2) * 65536 + buffer.readu16(sbox16, (word % 65536) * 2)
		word = bit32.bxor(buffer.readu32(out_buf, 168), sbox_lookup, 128)
		buffer.writeu32(out_buf, 192, word)

		local w1 = bit32.bxor(buffer.readu32(out_buf, 172), word)
		buffer.writeu32(out_buf, 196, w1)
		local w2 = bit32.bxor(buffer.readu32(out_buf, 176), w1)
		buffer.writeu32(out_buf, 200, w2)
		buffer.writeu32(out_buf, 204, bit32.bxor(buffer.readu32(out_buf, 180), w2))
	else
		for ko = 16, 144, 16 do
			round_constant = round_constant * 2 % 229
			local sbox_lookup = buffer.readu16(sbox16, math.floor(word / 65536) * 2) * 65536 + buffer.readu16(sbox16, (word % 65536) * 2)
			word = bit32.bxor(buffer.readu32(out_buf, ko - 16), sbox_lookup, round_constant)
			buffer.writeu32(out_buf, ko, word)

			local w1 = bit32.bxor(buffer.readu32(out_buf, ko - 12), word)
			buffer.writeu32(out_buf, ko + 4, w1)
			local w2 = bit32.bxor(buffer.readu32(out_buf, ko - 8), w1)
			buffer.writeu32(out_buf, ko + 8, w2)
			word = bit32.bxor(buffer.readu32(out_buf, ko - 4), w2)
			buffer.writeu32(out_buf, ko + 12, word)
			word = bit32.rrotate(word, 8)
		end

		local sbox_lookup = buffer.readu16(sbox16, math.floor(word / 65536) * 2) * 65536 + buffer.readu16(sbox16, (word % 65536) * 2)
		word = bit32.bxor(buffer.readu32(out_buf, 144), sbox_lookup, 54)
		buffer.writeu32(out_buf, 160, word)

		local w1 = bit32.bxor(buffer.readu32(out_buf, 148), word)
		buffer.writeu32(out_buf, 164, w1)
		local w2 = bit32.bxor(buffer.readu32(out_buf, 152), w1)
		buffer.writeu32(out_buf, 168, w2)
		buffer.writeu32(out_buf, 172, bit32.bxor(buffer.readu32(out_buf, 156), w2))
	end

	return out_buf
end

local a0, a1, a2, a3, a4, a5, a6, a7, a8, a9, a10, a11, a12, a13, a14, a15
local function encrypt_block(round_keys, material_len, plaintext, pt_offset, output, out_offset)
	a0 = bit32.bxor(buffer.readu8(plaintext, pt_offset), buffer.readu8(round_keys, 0))
	a1 = bit32.bxor(buffer.readu8(plaintext, pt_offset + 1), buffer.readu8(round_keys, 1))
	a2 = bit32.bxor(buffer.readu8(plaintext, pt_offset + 2), buffer.readu8(round_keys, 2))
	a3 = bit32.bxor(buffer.readu8(plaintext, pt_offset + 3), buffer.readu8(round_keys, 3))
	a4 = bit32.bxor(buffer.readu8(plaintext, pt_offset + 4), buffer.readu8(round_keys, 4))
	a5 = bit32.bxor(buffer.readu8(plaintext, pt_offset + 5), buffer.readu8(round_keys, 5))
	a6 = bit32.bxor(buffer.readu8(plaintext, pt_offset + 6), buffer.readu8(round_keys, 6))
	a7 = bit32.bxor(buffer.readu8(plaintext, pt_offset + 7), buffer.readu8(round_keys, 7))
	a8 = bit32.bxor(buffer.readu8(plaintext, pt_offset + 8), buffer.readu8(round_keys, 8))
	a9 = bit32.bxor(buffer.readu8(plaintext, pt_offset + 9), buffer.readu8(round_keys, 9))
	a10 = bit32.bxor(buffer.readu8(plaintext, pt_offset + 10), buffer.readu8(round_keys, 10))
	a11 = bit32.bxor(buffer.readu8(plaintext, pt_offset + 11), buffer.readu8(round_keys, 11))
	a12 = bit32.bxor(buffer.readu8(plaintext, pt_offset + 12), buffer.readu8(round_keys, 12))
	a13 = bit32.bxor(buffer.readu8(plaintext, pt_offset + 13), buffer.readu8(round_keys, 13))
	a14 = bit32.bxor(buffer.readu8(plaintext, pt_offset + 14), buffer.readu8(round_keys, 14))
	a15 = bit32.bxor(buffer.readu8(plaintext, pt_offset + 15), buffer.readu8(round_keys, 15))

	local b0,b1,b2,b3,b4,b5,b6,b7,b8,b9,b10,b11,b12,b13,b14,b15
		= a0,a1,a2,a3,a4,a5,a6,a7,a8,a9,a10,a11,a12,a13,a14,a15

	local i0 = b0 * 256 + b5; local i1 = b5 * 256 + b10; local i2 = b10 * 256 + b15; local i3 = b15 * 256 + b0
	local i4 = b4 * 256 + b9; local i5 = b9 * 256 + b14; local i6 = b14 * 256 + b3; local i7 = b3 * 256 + b4
	local i8 = b8 * 256 + b13; local i9 = b13 * 256 + b2; local i10 = b2 * 256 + b7; local i11 = b7 * 256 + b8
	local i12 = b12 * 256 + b1; local i13 = b1 * 256 + b6; local i14 = b6 * 256 + b11; local i15 = b11 * 256 + b12

	local tbl0, tbl1 = smix_table0, smix_table1
	for round_off = 16, material_len, 16 do
		b0 = bit32.bxor(buffer.readu8(tbl0, i0), buffer.readu8(tbl1, i2), buffer.readu8(round_keys, round_off))
		b1 = bit32.bxor(buffer.readu8(tbl0, i1), buffer.readu8(tbl1, i3), buffer.readu8(round_keys, round_off + 1))
		b2 = bit32.bxor(buffer.readu8(tbl0, i2), buffer.readu8(tbl1, i0), buffer.readu8(round_keys, round_off + 2))
		b3 = bit32.bxor(buffer.readu8(tbl0, i3), buffer.readu8(tbl1, i1), buffer.readu8(round_keys, round_off + 3))
		b4 = bit32.bxor(buffer.readu8(tbl0, i4), buffer.readu8(tbl1, i6), buffer.readu8(round_keys, round_off + 4))
		b5 = bit32.bxor(buffer.readu8(tbl0, i5), buffer.readu8(tbl1, i7), buffer.readu8(round_keys, round_off + 5))
		b6 = bit32.bxor(buffer.readu8(tbl0, i6), buffer.readu8(tbl1, i4), buffer.readu8(round_keys, round_off + 6))
		b7 = bit32.bxor(buffer.readu8(tbl0, i7), buffer.readu8(tbl1, i5), buffer.readu8(round_keys, round_off + 7))
		b8 = bit32.bxor(buffer.readu8(tbl0, i8), buffer.readu8(tbl1, i10), buffer.readu8(round_keys, round_off + 8))
		b9 = bit32.bxor(buffer.readu8(tbl0, i9), buffer.readu8(tbl1, i11), buffer.readu8(round_keys, round_off + 9))
		b10 = bit32.bxor(buffer.readu8(tbl0, i10), buffer.readu8(tbl1, i8), buffer.readu8(round_keys, round_off + 10))
		b11 = bit32.bxor(buffer.readu8(tbl0, i11), buffer.readu8(tbl1, i9), buffer.readu8(round_keys, round_off + 11))
		b12 = bit32.bxor(buffer.readu8(tbl0, i12), buffer.readu8(tbl1, i14), buffer.readu8(round_keys, round_off + 12))
		b13 = bit32.bxor(buffer.readu8(tbl0, i13), buffer.readu8(tbl1, i15), buffer.readu8(round_keys, round_off + 13))
		b14 = bit32.bxor(buffer.readu8(tbl0, i14), buffer.readu8(tbl1, i12), buffer.readu8(round_keys, round_off + 14))
		b15 = bit32.bxor(buffer.readu8(tbl0, i15), buffer.readu8(tbl1, i13), buffer.readu8(round_keys, round_off + 15))

		i0, i1, i2, i3 = b0 * 256 + b5, b5 * 256 + b10, b10 * 256 + b15, b15 * 256 + b0
		i4, i5, i6, i7 = b4 * 256 + b9, b9 * 256 + b14, b14 * 256 + b3, b3 * 256 + b4
		i8, i9, i10, i11 = b8 * 256 + b13, b13 * 256 + b2, b2 * 256 + b7, b7 * 256 + b8
		i12, i13, i14, i15 = b12 * 256 + b1, b1 * 256 + b6, b6 * 256 + b11, b11 * 256 + b12
	end

	buffer.writeu32(output, out_offset, bit32.bxor(
		buffer.readu16(sbox_16bit, bit32.bxor(buffer.readu8(tbl0, i15), buffer.readu8(smix_table1, i13), buffer.readu8(round_keys, material_len + 31)) * 512 +
			bit32.bxor(buffer.readu8(tbl0, i10), buffer.readu8(smix_table1, i8), buffer.readu8(round_keys, material_len + 26)) * 2) * 65536 +
			buffer.readu16(sbox_16bit, bit32.bxor(buffer.readu8(tbl0, i5), buffer.readu8(smix_table1, i7), buffer.readu8(round_keys, material_len + 21)) * 512 +
				bit32.bxor(buffer.readu8(tbl0, i0), buffer.readu8(smix_table1, i2), buffer.readu8(round_keys, material_len + 16)) * 2),
		buffer.readu32(round_keys, material_len + 32)
		))

	buffer.writeu32(output, out_offset + 4, bit32.bxor(
		buffer.readu16(sbox_16bit, bit32.bxor(buffer.readu8(tbl0, i3), buffer.readu8(smix_table1, i1), buffer.readu8(round_keys, material_len + 19)) * 512 +
			bit32.bxor(buffer.readu8(tbl0, i14), buffer.readu8(smix_table1, i12), buffer.readu8(round_keys, material_len + 30)) * 2) * 65536 +
			buffer.readu16(sbox_16bit, bit32.bxor(buffer.readu8(tbl0, i9), buffer.readu8(smix_table1, i11), buffer.readu8(round_keys, material_len + 25)) * 512 +
				bit32.bxor(buffer.readu8(tbl0, i4), buffer.readu8(smix_table1, i6), buffer.readu8(round_keys, material_len + 20)) * 2),
		buffer.readu32(round_keys, material_len + 36)
		))

	buffer.writeu32(output, out_offset + 8, bit32.bxor(
		buffer.readu16(sbox_16bit, bit32.bxor(buffer.readu8(tbl0, i7), buffer.readu8(smix_table1, i5), buffer.readu8(round_keys, material_len + 23)) * 512 +
			bit32.bxor(buffer.readu8(tbl0, i2), buffer.readu8(smix_table1, i0), buffer.readu8(round_keys, material_len + 18)) * 2) * 65536 +
			buffer.readu16(sbox_16bit, bit32.bxor(buffer.readu8(tbl0, i13), buffer.readu8(smix_table1, i15), buffer.readu8(round_keys, material_len + 29)) * 512 +
				bit32.bxor(buffer.readu8(tbl0, i8), buffer.readu8(smix_table1, i10), buffer.readu8(round_keys, material_len + 24)) * 2),
		buffer.readu32(round_keys, material_len + 40)
		))

	buffer.writeu32(output, out_offset + 12, bit32.bxor(
		buffer.readu16(sbox_16bit, bit32.bxor(buffer.readu8(tbl0, i11), buffer.readu8(smix_table1, i9), buffer.readu8(round_keys, material_len + 27)) * 512 +
			bit32.bxor(buffer.readu8(tbl0, i6), buffer.readu8(smix_table1, i4), buffer.readu8(round_keys, material_len + 22)) * 2) * 65536 +
			buffer.readu16(sbox_16bit, bit32.bxor(buffer.readu8(tbl0, i1), buffer.readu8(smix_table1, i3), buffer.readu8(round_keys, material_len + 17)) * 512 +
				bit32.bxor(buffer.readu8(tbl0, i12), buffer.readu8(smix_table1, i14), buffer.readu8(round_keys, material_len + 28)) * 2),
		buffer.readu32(round_keys, material_len + 44)
		))
end

local function constant_time_equals(b1, b2, len)
	local r = 0
	for i = 0, len - 1 do
		local x = buffer.readu8(b1, i)
		local y = buffer.readu8(b2, i)
		r = bit32.bor(r, bit32.bxor(x, y))
	end
	return r == 0
end

local function gf_mult(x, y, z)
	local v = buffer.create(16)

	buffer.writeu32(z, 0, 0)
	buffer.writeu32(z, 4, 0)
	buffer.writeu32(z, 8, 0)
	buffer.writeu32(z, 12, 0)

	buffer.writeu32(v, 0, buffer.readu32(y, 0))
	buffer.writeu32(v, 4, buffer.readu32(y, 4))
	buffer.writeu32(v, 8, buffer.readu32(y, 8))
	buffer.writeu32(v, 12, buffer.readu32(y, 12))

	for i = 0, 15 do
		for j = 0, 7 do
			if bit32.band(buffer.readu8(x, i), bit32.lshift(1, 7 - j)) ~= 0 then
				buffer.writeu32(z, 0, bit32.bxor(buffer.readu32(z, 0), buffer.readu32(v, 0)))
				buffer.writeu32(z, 4, bit32.bxor(buffer.readu32(z, 4), buffer.readu32(v, 4)))
				buffer.writeu32(z, 8, bit32.bxor(buffer.readu32(z, 8), buffer.readu32(v, 8)))
				buffer.writeu32(z, 12, bit32.bxor(buffer.readu32(z, 12), buffer.readu32(v, 12)))
			end

			if buffer.readu8(v, 15) % 2 == 1 then
				local val = 0

				val = bit32.byteswap(buffer.readu32(v, 12))
				val = bit32.rshift(val, 1)
				if bit32.band(buffer.readu8(v, 11), 0x01) ~= 0 then val = bit32.bor(val, 0x80000000) end
				buffer.writeu32(v, 12, bit32.byteswap(val))

				val = bit32.byteswap(buffer.readu32(v, 8))
				val = bit32.rshift(val, 1)
				if bit32.band(buffer.readu8(v, 7), 0x01) ~= 0 then val = bit32.bor(val, 0x80000000) end
				buffer.writeu32(v, 8, bit32.byteswap(val))

				val = bit32.byteswap(buffer.readu32(v, 4))
				val = bit32.rshift(val, 1)
				if bit32.band(buffer.readu8(v, 3), 0x01) ~= 0 then val = bit32.bor(val, 0x80000000) end
				buffer.writeu32(v, 4, bit32.byteswap(val))

				val = bit32.byteswap(buffer.readu32(v, 0))
				val = bit32.rshift(val, 1)
				buffer.writeu32(v, 0, bit32.byteswap(val))

				buffer.writeu8(v, 0, bit32.bxor(buffer.readu8(v, 0), 0xE1))
			else
				local val = 0

				val = bit32.byteswap(buffer.readu32(v, 12))
				val = bit32.rshift(val, 1)
				if bit32.band(buffer.readu8(v, 11), 0x01) ~= 0 then val = bit32.bor(val, 0x80000000) end
				buffer.writeu32(v, 12, bit32.byteswap(val))

				val = bit32.byteswap(buffer.readu32(v, 8))
				val = bit32.rshift(val, 1)
				if bit32.band(buffer.readu8(v, 7), 0x01) ~= 0 then val = bit32.bor(val, 0x80000000) end
				buffer.writeu32(v, 8, bit32.byteswap(val))

				val = bit32.byteswap(buffer.readu32(v, 4))
				val = bit32.rshift(val, 1)
				if bit32.band(buffer.readu8(v, 3), 0x01) ~= 0 then val = bit32.bor(val, 0x80000000) end
				buffer.writeu32(v, 4, bit32.byteswap(val))

				val = bit32.byteswap(buffer.readu32(v, 0))
				val = bit32.rshift(val, 1)
				buffer.writeu32(v, 0, bit32.byteswap(val))
			end
		end
	end
end

local function ghash(h, x, xlen, y)
	local m = math.floor(xlen / 16)
	local xpos = 0
	local tmp = buffer.create(16)

	for i = 0, m - 1 do
		buffer.writeu32(y, 0, bit32.bxor(buffer.readu32(y, 0), buffer.readu32(x, xpos)))
		buffer.writeu32(y, 4, bit32.bxor(buffer.readu32(y, 4), buffer.readu32(x, xpos + 4)))
		buffer.writeu32(y, 8, bit32.bxor(buffer.readu32(y, 8), buffer.readu32(x, xpos + 8)))
		buffer.writeu32(y, 12, bit32.bxor(buffer.readu32(y, 12), buffer.readu32(x, xpos + 12)))
		xpos += 16

		gf_mult(y, h, tmp)
		buffer.writeu32(y, 0, buffer.readu32(tmp, 0))
		buffer.writeu32(y, 4, buffer.readu32(tmp, 4))
		buffer.writeu32(y, 8, buffer.readu32(tmp, 8))
		buffer.writeu32(y, 12, buffer.readu32(tmp, 12))
	end

	if xpos < xlen then
		local last = xlen - xpos
		buffer.writeu32(tmp, 0, 0)
		buffer.writeu32(tmp, 4, 0)
		buffer.writeu32(tmp, 8, 0)
		buffer.writeu32(tmp, 12, 0)

		for i = 0, last - 1 do
			buffer.writeu8(tmp, i, buffer.readu8(x, xpos + i))
		end

		buffer.writeu32(y, 0, bit32.bxor(buffer.readu32(y, 0), buffer.readu32(tmp, 0)))
		buffer.writeu32(y, 4, bit32.bxor(buffer.readu32(y, 4), buffer.readu32(tmp, 4)))
		buffer.writeu32(y, 8, bit32.bxor(buffer.readu32(y, 8), buffer.readu32(tmp, 8)))
		buffer.writeu32(y, 12, bit32.bxor(buffer.readu32(y, 12), buffer.readu32(tmp, 12)))

		gf_mult(y, h, tmp)

		buffer.writeu32(y, 0, buffer.readu32(tmp, 0))
		buffer.writeu32(y, 4, buffer.readu32(tmp, 4))
		buffer.writeu32(y, 8, buffer.readu32(tmp, 8))
		buffer.writeu32(y, 12, buffer.readu32(tmp, 12))
	end
end

local function gctr(enc_proc, icb, x, xlen, y)
	if xlen == 0 then return end

	local n = math.floor(xlen / 16)
	local cb = buffer.create(16)
	local tmp = buffer.create(16)
	local xpos = 0
	local ypos = 0

	buffer.writeu32(cb, 0, buffer.readu32(icb, 0))
	buffer.writeu32(cb, 4, buffer.readu32(icb, 4))
	buffer.writeu32(cb, 8, buffer.readu32(icb, 8))
	buffer.writeu32(cb, 12, buffer.readu32(icb, 12))

	for i = 0, n - 1 do
		enc_proc(cb, 0, tmp, 0)

		buffer.writeu32(y, ypos + 0, bit32.bxor(buffer.readu32(x, xpos + 0), buffer.readu32(tmp, 0)))
		buffer.writeu32(y, ypos + 4, bit32.bxor(buffer.readu32(x, xpos + 4), buffer.readu32(tmp, 4)))
		buffer.writeu32(y, ypos + 8, bit32.bxor(buffer.readu32(x, xpos + 8), buffer.readu32(tmp, 8)))
		buffer.writeu32(y, ypos + 12, bit32.bxor(buffer.readu32(x, xpos + 12), buffer.readu32(tmp, 12)))

		xpos += 16
		ypos += 16

		local v = bit32.byteswap(buffer.readu32(cb, 12))
		v = (v + 1) % 0x100000000
		buffer.writeu32(cb, 12, bit32.byteswap(v))
	end

	local last = xlen - xpos
	if last > 0 then
		enc_proc(cb, 0, tmp, 0)
		for i = 0, last - 1 do
			local xb = buffer.readu8(x, xpos + i)
			local tb = buffer.readu8(tmp, i)
			buffer.writeu8(y, ypos + i, bit32.bxor(xb, tb))
		end
	end
end

local function prepare_j0(iv, ivlen, h, j0)
	if ivlen == 12 then
		buffer.writeu32(j0, 0, buffer.readu32(iv, 0))
		buffer.writeu32(j0, 4, buffer.readu32(iv, 4))
		buffer.writeu32(j0, 8, buffer.readu32(iv, 8))
		buffer.writeu32(j0, 12, 0x01000000)
	else
		buffer.writeu32(j0, 0, 0)
		buffer.writeu32(j0, 4, 0)
		buffer.writeu32(j0, 8, 0)
		buffer.writeu32(j0, 12, 0)

		ghash(h, iv, ivlen, j0)

		local lenbuf = buffer.create(16)
		local ivlen_bits = ivlen * 8

		buffer.writeu32(lenbuf, 0, 0)
		buffer.writeu32(lenbuf, 4, 0)
		buffer.writeu32(lenbuf, 8, 0)
		buffer.writeu32(lenbuf, 12, ivlen_bits)

		ghash(h, lenbuf, 16, j0)
	end
end

local function gcm_gctr(enc_proc, j0, input, len, output)
	if len == 0 then return end

	local j0inc = buffer.create(16)
	buffer.writeu32(j0inc, 0, buffer.readu32(j0, 0))
	buffer.writeu32(j0inc, 4, buffer.readu32(j0, 4))
	buffer.writeu32(j0inc, 8, buffer.readu32(j0, 8))
	buffer.writeu32(j0inc, 12, buffer.readu32(j0, 12))

	local v = bit32.byteswap(buffer.readu32(j0inc, 12))
	v = (v + 1) % 0x100000000
	buffer.writeu32(j0inc, 12, bit32.byteswap(v))

	gctr(enc_proc, j0inc, input, len, output)
end

local function gcm_hash(h, aad, aadlen, crypt, cryptlen, s)
	local lenbuf = buffer.create(16)

	buffer.writeu32(s, 0, 0)
	buffer.writeu32(s, 4, 0)
	buffer.writeu32(s, 8, 0)
	buffer.writeu32(s, 12, 0)

	local m = math.floor(aadlen / 16)
	local xpos = 0
	local tmp = buffer.create(16)

	for i = 0, m - 1 do
		buffer.writeu32(s, 0, bit32.bxor(buffer.readu32(s, 0), buffer.readu32(aad, xpos)))
		buffer.writeu32(s, 4, bit32.bxor(buffer.readu32(s, 4), buffer.readu32(aad, xpos + 4)))
		buffer.writeu32(s, 8, bit32.bxor(buffer.readu32(s, 8), buffer.readu32(aad, xpos + 8)))
		buffer.writeu32(s, 12, bit32.bxor(buffer.readu32(s, 12), buffer.readu32(aad, xpos + 12)))
		xpos += 16

		gf_mult(s, h, tmp)
		buffer.writeu32(s, 0, buffer.readu32(tmp, 0))
		buffer.writeu32(s, 4, buffer.readu32(tmp, 4))
		buffer.writeu32(s, 8, buffer.readu32(tmp, 8))
		buffer.writeu32(s, 12, buffer.readu32(tmp, 12))
	end

	if xpos < aadlen then
		local last = aadlen - xpos
		buffer.writeu32(tmp, 0, 0)
		buffer.writeu32(tmp, 4, 0)
		buffer.writeu32(tmp, 8, 0)
		buffer.writeu32(tmp, 12, 0)

		for i = 0, last - 1 do
			buffer.writeu8(tmp, i, buffer.readu8(aad, xpos + i))
		end

		buffer.writeu32(s, 0, bit32.bxor(buffer.readu32(s, 0), buffer.readu32(tmp, 0)))
		buffer.writeu32(s, 4, bit32.bxor(buffer.readu32(s, 4), buffer.readu32(tmp, 4)))
		buffer.writeu32(s, 8, bit32.bxor(buffer.readu32(s, 8), buffer.readu32(tmp, 8)))
		buffer.writeu32(s, 12, bit32.bxor(buffer.readu32(s, 12), buffer.readu32(tmp, 12)))

		gf_mult(s, h, tmp)
		buffer.writeu32(s, 0, buffer.readu32(tmp, 0))
		buffer.writeu32(s, 4, buffer.readu32(tmp, 4))
		buffer.writeu32(s, 8, buffer.readu32(tmp, 8))
		buffer.writeu32(s, 12, buffer.readu32(tmp, 12))
	end

	m = math.floor(cryptlen / 16)
	xpos = 0

	for i = 0, m - 1 do
		buffer.writeu32(s, 0, bit32.bxor(buffer.readu32(s, 0), buffer.readu32(crypt, xpos)))
		buffer.writeu32(s, 4, bit32.bxor(buffer.readu32(s, 4), buffer.readu32(crypt, xpos + 4)))
		buffer.writeu32(s, 8, bit32.bxor(buffer.readu32(s, 8), buffer.readu32(crypt, xpos + 8)))
		buffer.writeu32(s, 12, bit32.bxor(buffer.readu32(s, 12), buffer.readu32(crypt, xpos + 12)))
		xpos += 16

		gf_mult(s, h, tmp)
		buffer.writeu32(s, 0, buffer.readu32(tmp, 0))
		buffer.writeu32(s, 4, buffer.readu32(tmp, 4))
		buffer.writeu32(s, 8, buffer.readu32(tmp, 8))
		buffer.writeu32(s, 12, buffer.readu32(tmp, 12))
	end

	if xpos < cryptlen then
		local last = cryptlen - xpos
		buffer.writeu32(tmp, 0, 0)
		buffer.writeu32(tmp, 4, 0)
		buffer.writeu32(tmp, 8, 0)
		buffer.writeu32(tmp, 12, 0)

		for i = 0, last - 1 do
			buffer.writeu8(tmp, i, buffer.readu8(crypt, xpos + i))
		end

		buffer.writeu32(s, 0, bit32.bxor(buffer.readu32(s, 0), buffer.readu32(tmp, 0)))
		buffer.writeu32(s, 4, bit32.bxor(buffer.readu32(s, 4), buffer.readu32(tmp, 4)))
		buffer.writeu32(s, 8, bit32.bxor(buffer.readu32(s, 8), buffer.readu32(tmp, 8)))
		buffer.writeu32(s, 12, bit32.bxor(buffer.readu32(s, 12), buffer.readu32(tmp, 12)))

		gf_mult(s, h, tmp)
		buffer.writeu32(s, 0, buffer.readu32(tmp, 0))
		buffer.writeu32(s, 4, buffer.readu32(tmp, 4))
		buffer.writeu32(s, 8, buffer.readu32(tmp, 8))
		buffer.writeu32(s, 12, buffer.readu32(tmp, 12))
	end

	local aad_bits = aadlen * 8
	local crypt_bits = cryptlen * 8

	local lenbuf = buffer.create(16)
	buffer.writeu32(lenbuf, 0, 0)
	buffer.writeu32(lenbuf, 4, bit32.byteswap(aad_bits))
	buffer.writeu32(lenbuf, 8, 0)
	buffer.writeu32(lenbuf, 12, bit32.byteswap(crypt_bits))

	buffer.writeu32(s, 0, bit32.bxor(buffer.readu32(s, 0), buffer.readu32(lenbuf, 0)))
	buffer.writeu32(s, 4, bit32.bxor(buffer.readu32(s, 4), buffer.readu32(lenbuf, 4)))
	buffer.writeu32(s, 8, bit32.bxor(buffer.readu32(s, 8), buffer.readu32(lenbuf, 8)))
	buffer.writeu32(s, 12, bit32.bxor(buffer.readu32(s, 12), buffer.readu32(lenbuf, 12)))

	gf_mult(s, h, tmp)
	buffer.writeu32(s, 0, buffer.readu32(tmp, 0))
	buffer.writeu32(s, 4, buffer.readu32(tmp, 4))
	buffer.writeu32(s, 8, buffer.readu32(tmp, 8))
	buffer.writeu32(s, 12, buffer.readu32(tmp, 12))
end

function aes.encrypt(key, iv, plaintext, aad)
	if not key or typeof(key) ~= "buffer" then error("key must be a buffer", 2) end
	if not iv or typeof(iv) ~= "buffer" then error("iv must be a buffer", 2) end
	if not plaintext or typeof(plaintext) ~= "buffer" then error("plaintext must be a buffer", 2) end

	local key_len = buffer.len(key)
	if key_len ~= 16 and key_len ~= 24 and key_len ~= 32 then error("key must be 16, 24, or 32 bytes", 2) end

	local cfg = key_configs[key_len]
	local round_keys = expand_key_schedule(key, key_len, buffer.create(cfg.expanded_length))
	local material_len = cfg.material_length

	local function encryption_processor(pt_block, pt_off, out_buf, out_off)
		encrypt_block(round_keys, material_len, pt_block, pt_off, out_buf, out_off)
	end

	local iv_len = buffer.len(iv)
	local aad_buf = aad or buffer.create(0)
	local aad_len = buffer.len(aad_buf)
	local plain_len = buffer.len(plaintext)

	local out_buf = buffer.create(plain_len)
	local out_tag = buffer.create(16)

	local h = buffer.create(16)
	local j0 = buffer.create(16)
	local s = buffer.create(16)

	encryption_processor(h, 0, h, 0)
	prepare_j0(iv, iv_len, h, j0)
	gcm_gctr(encryption_processor, j0, plaintext, plain_len, out_buf)
	gcm_hash(h, aad_buf, aad_len, out_buf, plain_len, s)
	gctr(encryption_processor, j0, s, 16, out_tag)

	return out_buf, out_tag
end

function aes.decrypt(key, iv, ciphertext, tag, aad)
	if not key or typeof(key) ~= "buffer" then error("key must be a buffer", 2) end
	if not iv or typeof(iv) ~= "buffer" then error("iv must be a buffer", 2) end
	if not ciphertext or typeof(ciphertext) ~= "buffer" then error("ciphertext must be a buffer", 2) end
	if not tag or typeof(tag) ~= "buffer" then error("tag must be a buffer", 2) end

	local key_len = buffer.len(key)
	if key_len ~= 16 and key_len ~= 24 and key_len ~= 32 then error("key must be 16, 24, or 32 bytes", 2) end

	local cfg = key_configs[key_len]
	local round_keys = expand_key_schedule(key, key_len, buffer.create(cfg.expanded_length))
	local material_len = cfg.material_length

	local function encryption_processor(pt_block, pt_off, out_buf, out_off)
		encrypt_block(round_keys, material_len, pt_block, pt_off, out_buf, out_off)
	end

	local iv_len = buffer.len(iv)
	local aad_buf = aad or buffer.create(0)
	local aad_len = buffer.len(aad_buf)
	local crypt_len = buffer.len(ciphertext)
	local tag_len = buffer.len(tag)

	local out_buf = buffer.create(crypt_len)

	local h = buffer.create(16)
	local j0 = buffer.create(16)
	local s = buffer.create(16)
	local computed_tag = buffer.create(16)

	encryption_processor(h, 0, h, 0)
	prepare_j0(iv, iv_len, h, j0)
	gcm_gctr(encryption_processor, j0, ciphertext, crypt_len, out_buf)
	gcm_hash(h, aad_buf, aad_len, ciphertext, crypt_len, s)
	gctr(encryption_processor, j0, s, 16, computed_tag)

	if not constant_time_equals(tag, computed_tag, tag_len) then
		return false
	end

	return true, out_buf
end

return aes
