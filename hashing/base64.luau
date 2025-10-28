--!native
--!optimize 2

local padding_character = 61

local alphabet_lookup = {} do
	local chars = {
		65,66,67,68,69,70,71,72,73,74,75,76,77,78,79,80,
		81,82,83,84,85,86,87,88,89,90,
		97,98,99,100,101,102,103,104,105,106,107,108,109,110,111,112,
		113,114,115,116,117,118,119,120,121,122,
		48,49,50,51,52,53,54,55,56,57,
		43,47
	}

	for i = 0, 63 do
		alphabet_lookup[i] = chars[i + 1]
	end
end

local direct_lookup = {} do
	for i = 0, 255 do
		direct_lookup[i] = alphabet_lookup[bit32.band(i, 63)]
	end
end

local decode_lookup = {} do
	for i = 0, 255 do decode_lookup[i] = 255 end
	for i = 65, 90 do decode_lookup[i] = i - 65 end
	for i = 97, 122 do decode_lookup[i] = i - 97 + 26 end
	for i = 48, 57 do decode_lookup[i] = i - 48 + 52 end
	decode_lookup[43] = 62; decode_lookup[47] = 63
end

local base64 = {}

function base64.encode(input: buffer): buffer
	local pad = padding_character
	local lookup = direct_lookup
	local input_len = buffer.len(input)
	if input_len == 0 then
		return buffer.create(0)
	end

	local chunks = math.ceil(input_len / 3)
	local output_len = chunks * 4
	local out = buffer.create(output_len)

	local double_chunks = math.floor((chunks - 1) / 2)
	for chunk_index = 1, double_chunks do
		local in_idx = (chunk_index - 1) * 6
		local out_idx = (chunk_index - 1) * 8

		local w1 = bit32.byteswap(buffer.readu32(input, in_idx))
		local o11 = bit32.rshift(w1, 26)
		local o12 = bit32.rshift(w1, 20)
		local o13 = bit32.rshift(w1, 14)
		local o14 = bit32.rshift(w1, 8)

		local w2 = bit32.byteswap(buffer.readu32(input, in_idx + 3))
		local o21 = bit32.rshift(w2, 26)
		local o22 = bit32.rshift(w2, 20)
		local o23 = bit32.rshift(w2, 14)
		local o24 = bit32.rshift(w2, 8)

		buffer.writeu32(out, out_idx, bit32.bor(
			lookup[bit32.band(o11, 255)],
			lookup[bit32.band(o12, 255)] * 256,
			lookup[bit32.band(o13, 255)] * 65536,
			lookup[bit32.band(o14, 255)] * 16777216
		))

		buffer.writeu32(out, out_idx + 4, bit32.bor(
			lookup[bit32.band(o21, 255)],
			lookup[bit32.band(o22, 255)] * 256,
			lookup[bit32.band(o23, 255)] * 65536,
			lookup[bit32.band(o24, 255)] * 16777216
		))
	end

	local processed_chunks = double_chunks * 2
	if processed_chunks < chunks - 1 then
		local in_idx = processed_chunks * 3
		local out_idx = processed_chunks * 4

		local w = bit32.byteswap(buffer.readu32(input, in_idx))
		local o1 = bit32.rshift(w, 26)
		local o2 = bit32.rshift(w, 20)
		local o3 = bit32.rshift(w, 14)
		local o4 = bit32.rshift(w, 8)

		buffer.writeu32(out, out_idx, bit32.bor(
			lookup[bit32.band(o1, 255)],
			lookup[bit32.band(o2, 255)] * 256,
			lookup[bit32.band(o3, 255)] * 65536,
			lookup[bit32.band(o4, 255)] * 16777216
		))
	end

	if input_len > 0 then
		local total_processed = double_chunks * 2 + (processed_chunks < chunks - 1 and 1 or 0)
		local processed_bytes = total_processed * 3
		local remaining = input_len - processed_bytes
		local last_out_idx = output_len - 4

		if remaining == 3 then
			if processed_bytes + 4 <= input_len then
				local w = bit32.byteswap(buffer.readu32(input, processed_bytes))
				local o1 = bit32.rshift(w, 26)
				local o2 = bit32.rshift(w, 20)
				local o3 = bit32.rshift(w, 14)
				local o4 = bit32.rshift(w, 8)

				buffer.writeu32(out, last_out_idx, bit32.bor(
					lookup[bit32.band(o1, 255)],
					lookup[bit32.band(o2, 255)] * 256,
					lookup[bit32.band(o3, 255)] * 65536,
					lookup[bit32.band(o4, 255)] * 16777216
				))
			else
				local b1 = buffer.readu8(input, processed_bytes)
				local b2 = buffer.readu8(input, processed_bytes + 1)
				local b3 = buffer.readu8(input, processed_bytes + 2)
				local comb = bit32.bor(bit32.lshift(b1, 16), bit32.lshift(b2, 8), b3)

				local o1 = bit32.rshift(comb, 18)
				local o2 = bit32.band(bit32.rshift(comb, 12), 63)
				local o3 = bit32.band(bit32.rshift(comb, 6), 63)
				local o4 = bit32.band(comb, 63)

				buffer.writeu32(out, last_out_idx, bit32.bor(
					lookup[o1],
					lookup[o2] * 256,
					lookup[o3] * 65536,
					lookup[o4] * 16777216
				))
			end
		elseif remaining == 2 then
			local b1 = buffer.readu8(input, processed_bytes)
			local b2 = buffer.readu8(input, processed_bytes + 1)
			local comb = bit32.bor(bit32.lshift(b1, 16), bit32.lshift(b2, 8))

			local o1 = bit32.rshift(comb, 18)
			local o2 = bit32.rshift(comb, 12)
			local o3 = bit32.rshift(comb, 6)

			buffer.writeu32(out, last_out_idx, bit32.bor(
				lookup[bit32.band(o1, 255)],
				lookup[bit32.band(o2, 255)] * 256,
				lookup[bit32.band(o3, 255)] * 65536,
				pad * 16777216
			))
		elseif remaining == 1 then
			local b1 = buffer.readu8(input, processed_bytes)
			local comb = bit32.lshift(b1, 16)

			local o1 = bit32.rshift(comb, 18)
			local o2 = bit32.rshift(comb, 12)

			buffer.writeu32(out, last_out_idx, bit32.bor(
				lookup[bit32.band(o1, 255)],
				lookup[bit32.band(o2, 255)] * 256,
				pad * 65536,
				pad * 16777216
			))
		end
	end

	return out
end

function base64.decode(input: buffer): string
	local pad = padding_character
	local lookup = decode_lookup
	local input_len = buffer.len(input)

	if input_len == 0 then
		return ""
	end

	local pad_count = 0
	if input_len > 0 and buffer.readu8(input, input_len - 1) == pad then
		pad_count = 1
		if input_len > 1 and buffer.readu8(input, input_len - 2) == pad then
			pad_count = 2
		end
	end

	local out_len = (input_len / 4) * 3 - pad_count
	local out = buffer.create(out_len)
	local input_chunks = input_len // 4

	local double_chunks = (input_chunks - 1) // 2
	for chunk_index = 1, double_chunks do
		local in_idx = (chunk_index - 1) * 8
		local out_idx = (chunk_index - 1) * 6

		local v11 = lookup[buffer.readu8(input, in_idx)]
		local v12 = lookup[buffer.readu8(input, in_idx + 1)]
		local v13 = lookup[buffer.readu8(input, in_idx + 2)]
		local v14 = lookup[buffer.readu8(input, in_idx + 3)]

		local comb1 = bit32.bor(
			bit32.lshift(v11, 18),
			bit32.lshift(v12, 12),
			bit32.lshift(v13, 6),
			v14
		)

		local v21 = lookup[buffer.readu8(input, in_idx + 4)]
		local v22 = lookup[buffer.readu8(input, in_idx + 5)]
		local v23 = lookup[buffer.readu8(input, in_idx + 6)]
		local v24 = lookup[buffer.readu8(input, in_idx + 7)]

		local comb2 = bit32.bor(
			bit32.lshift(v21, 18),
			bit32.lshift(v22, 12),
			bit32.lshift(v23, 6),
			v24
		)

		buffer.writeu32(out, out_idx, bit32.bor(
			bit32.band(bit32.rshift(comb1, 16), 255),
			bit32.band(bit32.rshift(comb1, 8), 255) * 256,
			bit32.band(comb1, 255) * 65536,
			bit32.band(bit32.rshift(comb2, 16), 255) * 16777216
		))

		buffer.writeu8(out, out_idx + 4, bit32.band(bit32.rshift(comb2, 8), 255))
		buffer.writeu8(out, out_idx + 5, bit32.band(comb2, 255))
	end

	local processed_chunks = double_chunks * 2
	for chunk_index = processed_chunks + 1, input_chunks do
		local in_idx = (chunk_index - 1) * 4
		local out_idx = (chunk_index - 1) * 3

		local c1 = buffer.readu8(input, in_idx)
		local c2 = buffer.readu8(input, in_idx + 1)
		local c3 = buffer.readu8(input, in_idx + 2)
		local c4 = buffer.readu8(input, in_idx + 3)

		local v1 = lookup[c1]
		local v2 = lookup[c2]
		local v3 = c3 == pad and 0 or lookup[c3]
		local v4 = c4 == pad and 0 or lookup[c4]

		local comb = bit32.bor(
			bit32.lshift(v1, 18),
			bit32.lshift(v2, 12),
			bit32.lshift(v3, 6),
			v4
		)

		local bytes_to_write = math.min(3, out_len - out_idx)
		if bytes_to_write >= 1 then
			buffer.writeu8(out, out_idx, bit32.band(bit32.rshift(comb, 16), 255))
		end
		if bytes_to_write >= 2 then
			buffer.writeu8(out, out_idx + 1, bit32.band(bit32.rshift(comb, 8), 255))
		end
		if bytes_to_write >= 3 then
			buffer.writeu8(out, out_idx + 2, bit32.band(comb, 255))
		end
	end

	return buffer.tostring(out)
end

return base64
