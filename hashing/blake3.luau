--!optimize 2
--!native

local block_size = 64
local cv_size = 32
local extended_cv_size = 64
local max_stack_depth = 64
local stack_buffer_size = max_stack_depth * cv_size

local chunk_start = 0x01
local chunk_end = 0x02
local parent_flag = 0x04
local root_flag = 0x08

local initial_vectors = buffer.create(cv_size)
for i, v in ipairs({
	0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
	0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19}) do
	buffer.writeu32(initial_vectors, (i-1)*4, v)
end

local bxor = bit32.bxor
local lrotate = bit32.lrotate

local function safe_read32(buf, i)
	return buffer.readu32(buf, i*4) or 0
end

local function compress(hash, block, counter, block_len, flags, is_full)
	local s = {}
	for i = 0, 7 do
		s[i]   = safe_read32(hash, i)
		s[i+8] = safe_read32(block, i)
	end

	local m = {}
	for i = 0, 15 do
		m[i] = safe_read32(block, i)
	end

	for round = 1, 7 do
		for i = 0, 15, 4 do
			s[i+0] = (s[i+0] or 0) + (s[i+1] or 0) + (m[i+0] or 0)
			s[i+3] = lrotate(bxor(s[i+3] or 0, s[i+0]), 16)
			s[i+2] = (s[i+2] or 0) + s[i+3]
			s[i+1] = lrotate(bxor(s[i+1] or 0, s[i+2]), 12)
			s[i+0] = s[i+0] + (s[i+1] or 0) + (m[i+1] or 0)
			s[i+3] = lrotate(bxor(s[i+3], s[i+0]), 8)
			s[i+2] = s[i+2] + s[i+3]
			s[i+1] = lrotate(bxor(s[i+1], s[i+2]), 7)
		end

		m = {
			m[2], m[3], m[10], m[12], m[9], m[11], m[5], m[0],
			m[6], m[4], m[7], m[13], m[14], m[15], m[8], m[1]
		}
	end

	local out_size = is_full and extended_cv_size or cv_size
	local out = buffer.create(out_size)
	for i = 0, 7 do
		buffer.writeu32(out, i*4, bxor(s[i], s[i+8]))
	end
	if is_full then
		for i = 0, 7 do
			buffer.writeu32(out, (i+8)*4, bxor(s[i+8], safe_read32(hash, i)))
		end
	end
	return out
end

local function process_message(iv, flags, msg, length)
	local msg_len = buffer.len(msg)
	local state_stack = buffer.create(stack_buffer_size)
	local stack_size = 0
	local state_cv = buffer.create(cv_size)
	buffer.copy(state_cv, 0, iv, 0, cv_size)

	local chunk_counter = 0
	local chunk_index = 0
	local start_flag = chunk_start
	local end_flag = 0

	local block_buf = buffer.create(block_size)
	local offset = 0

	while offset < msg_len do
		local bytes = math.min(block_size, msg_len - offset)
		buffer.copy(block_buf, 0, msg, offset, bytes)

		state_cv = compress(state_cv, block_buf, chunk_counter, bytes, flags + start_flag + end_flag)
		start_flag = 0
		chunk_index += 1

		if chunk_index >= 16 then
			local merge_cv = state_cv
			local merge_count = chunk_counter + 1
			while merge_count % 2 == 0 and stack_size > 0 do
				stack_size -= 1
				local pop_cv = buffer.create(cv_size)
				buffer.copy(pop_cv, 0, state_stack, stack_size*cv_size, cv_size)

				local combined = buffer.create(extended_cv_size)
				buffer.copy(combined, 0, pop_cv, 0, cv_size)
				buffer.copy(combined, cv_size, merge_cv, 0, cv_size)

				merge_cv = compress(iv, combined, 0, block_size, flags + parent_flag)
				merge_count /= 2
			end
			buffer.copy(state_stack, stack_size*cv_size, merge_cv, 0, cv_size)
			stack_size += 1
			buffer.copy(state_cv, 0, iv, 0, cv_size)
			chunk_counter += 1
			chunk_index = 0
			start_flag = chunk_start
		end

		offset += bytes
	end

	local last_len = msg_len % block_size
	local padded_block = buffer.create(block_size)
	if last_len > 0 then
		buffer.copy(padded_block, 0, msg, msg_len - last_len, last_len)
	end
	
	for i = last_len, block_size-1 do
		buffer.writeu8(padded_block, i, 0)
	end

	local out_cv = state_cv
	local out_block = padded_block
	local out_len = last_len
	local out_flags = flags + start_flag + chunk_end + root_flag

	if chunk_counter > 0 then
		local merge_cv = compress(state_cv, padded_block, chunk_counter, last_len, flags + chunk_end)
		for i = stack_size-1, 0, -1 do
			local stack_cv = buffer.create(cv_size)
			buffer.copy(stack_cv, 0, state_stack, i*cv_size, cv_size)

			local combined = buffer.create(extended_cv_size)
			buffer.copy(combined, 0, stack_cv, 0, cv_size)
			buffer.copy(combined, cv_size, merge_cv, 0, cv_size)
			merge_cv = compress(iv, combined, 0, block_size, flags + parent_flag)
		end

		out_cv = iv
		local first_stack_cv = buffer.create(cv_size)
		buffer.copy(first_stack_cv, 0, state_stack, 0, cv_size)

		out_block = buffer.create(extended_cv_size)
		buffer.copy(out_block, 0, first_stack_cv, 0, cv_size)
		buffer.copy(out_block, cv_size, merge_cv, 0, cv_size)

		out_len = block_size
		out_flags = flags + root_flag + parent_flag
	end

	local output = buffer.create(length)
	local out_offset = 0
	for i = 0, math.ceil(length/block_size)-1 do
		local digest = compress(out_cv, out_block, i, out_len, out_flags, true)
		local copy_bytes = math.min(block_size, length - out_offset)
		buffer.copy(output, out_offset, digest, 0, copy_bytes)
		out_offset += copy_bytes
	end

	return output
end

return function(msg, length)
	return process_message(initial_vectors, 0, msg, length or 32)
end
