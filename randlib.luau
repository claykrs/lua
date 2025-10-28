--!native
--!optimize 2

-- combined from 3 files into 1

local encode = buffer.create(512)
local decode = buffer.create(65536 * 2)
local chars = "0123456789abcdef"

for b = 0, 255 do
	local hi = string.byte(chars, bit32.rshift(b, 4) + 1)
	local lo = string.byte(chars, (b % 16) + 1)
	buffer.writeu16(encode, b * 2, hi + bit32.lshift(lo, 8))
end

local function nibble(ch)
	if ch >= 48 and ch <= 57 then return ch - 48 end
	if ch >= 65 and ch <= 70 then return ch - 55 end
	if ch >= 97 and ch <= 102 then return ch - 87 end
	return 0
end

for hi = 0, 255 do
	for lo = 0, 255 do
		local b = bit32.lshift(nibble(hi), 4) + nibble(lo)
		local idx = bit32.lshift(lo, 8) + hi
		buffer.writeu16(decode, idx * 2, b)
	end
end

local hexconv = {
	tohex = function(buf)
		local len = buffer.len(buf)
		local out = buffer.create(len * 2)
		local cur = 0

		for i = 0, len - 1 do
			local byte = buffer.readu8(buf, i)
			local enc = buffer.readu16(encode, byte * 2)
			buffer.writeu16(out, cur, enc)
			cur += 2
		end

		return buffer.tostring(out)
	end,
	fromhex = function(hex)
		local buf = type(hex) == "string" and buffer.fromstring(hex) or hex
		local len = buffer.len(buf)
		local out = buffer.create(len / 2)
		local cur = 0

		for i = 0, len - 1, 2 do
			local pair = buffer.readu16(buf, i)
			local byte = buffer.readu16(decode, pair * 2)
			buffer.writeu8(out, cur, byte)
			cur += 1
		end

		return out
	end,
}

local dword = 4
local block_size = 64
local state_size = 16

local sigma_const = buffer.create(16)
local tau_const = buffer.create(16)

for i, bv in ipairs({string.byte("expand 32-byte k", 1, -1)}) do
	buffer.writeu8(sigma_const, i - 1, bv)
end

for i, bv in ipairs({string.byte("expand 16-byte k", 1, -1)}) do
	buffer.writeu8(tau_const, i - 1, bv)
end

local function process_block(state, rounds)
	local S = {}
	for i = 0, 15 do
		S[i] = buffer.readu32(state, i * 4)
	end

	local function quarter_round(a, b, c, d)
		S[a] = bit32.bor(S[a] + S[b], 0); S[d] = bit32.lrotate(bit32.bxor(S[d], S[a]), 16)
		S[c] = bit32.bor(S[c] + S[d], 0); S[b] = bit32.lrotate(bit32.bxor(S[b], S[c]), 12)
		S[a] = bit32.bor(S[a] + S[b], 0); S[d] = bit32.lrotate(bit32.bxor(S[d], S[a]), 8)
		S[c] = bit32.bor(S[c] + S[d], 0); S[b] = bit32.lrotate(bit32.bxor(S[b], S[c]), 7)
	end

	for round = 1, rounds do
		if round % 2 == 1 then
			quarter_round(0, 4, 8, 12)
			quarter_round(1, 5, 9, 13)
			quarter_round(2, 6, 10, 14)
			quarter_round(3, 7, 11, 15)
		else
			quarter_round(0, 5, 10, 15)
			quarter_round(1, 6, 11, 12)
			quarter_round(2, 7, 8, 13)
			quarter_round(3, 4, 9, 14)
		end
	end

	for i = 0, 15 do
		buffer.writeu32(state, i * 4, buffer.readu32(state, i * 4) + S[i])
	end
end

local function initialize_state(key, nonce, count)
	local len = buffer.len(key)
	local state = buffer.create(state_size * dword)
	
	local sigma, tau = sigma_const, tau_const
	local constants = (len == 32) and sigma or tau
	
	buffer.copy(state, 0, constants, 0, 16)
	buffer.copy(state, 16, key, 0, math.min(len, 16))
	
	if len == 32 then buffer.copy(state, 32, key, 16, 16)
	else buffer.copy(state, 32, key, 0, 16) end

	buffer.writeu32(state, 48, count)
	buffer.copy(state, 52, nonce, 0, 12)

	return state
end

local function chacha20(data, key, nonce, count, rounds)
	local key_len = buffer.len(key)
	local nonce_len = buffer.len(nonce)

	local block_count = count or 1
	local block_rounds = rounds or 20

	local data_len = buffer.len(data)
	if data_len == 0 then return buffer.create(0) end
	local output = buffer.create(data_len)
	local data_offset = 0

	local state = initialize_state(key, nonce, block_count)
	local state_backup = buffer.create(64)
	buffer.copy(state_backup, 0, state, 0)

	while data_offset < data_len do
		process_block(state, block_rounds)
		local bytes = math.min(block_size, data_len - data_offset)

		for i = 0, bytes - 1 do
			local data_b = buffer.readu8(data, data_offset + i)
			local keystream_b = buffer.readu8(state, i)
			buffer.writeu8(output, data_offset + i, bit32.bxor(data_b, keystream_b))
		end

		data_offset += bytes
		block_count += 1
		buffer.copy(state, 0, state_backup, 0)
		buffer.writeu32(state, 48, block_count)
	end
	
	return output
end

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

local blake3 = function(msg, length)
	return process_message(initial_vectors, 0, msg, length or 32)
end

-- logic should be the same; this is untested with combining the files.

local block_size = 64
local key_size = 32
local nonce_size = 12

local csprng = {
	block_expansion = true,
	size_target = 2048,
	rekey_after = 1024,

	key = buffer.create(0),
	nonce = buffer.create(0),
	buffer = buffer.create(0),

	counter = 0,
	buffer_position = 0,
	buffer_size = 0,
	bytes_left = 0,

	entropy_providers = {}
}

local input_buffer = buffer.create(block_size)
local rekey_threshold = math.max(math.floor(csprng.rekey_after), 2)
local size_target_clamped = math.clamp(math.floor(csprng.size_target), 64, 4294967295)

local function reset()
	csprng.key = buffer.create(0)
	csprng.nonce = buffer.create(0)
	csprng.buffer = buffer.create(0)
	csprng.counter = 0
	csprng.buffer_position = 0
	csprng.buffer_size = 0
end

local function gather_entropy(custom_entropy)
	local entropy_buffers = buffer.create(1024)
	local offset = 0

	local function write_to_buffer(src)
		local len = buffer.len(src)
		buffer.copy(entropy_buffers, offset, src, 0, len)
		offset += len
	end

	local current_time = tick and tick() or 1.234
	local time_buf = buffer.create(8)
	buffer.writef64(time_buf, 0, current_time)
	write_to_buffer(time_buf)

	local clock_time = os.clock()
	local clock_buf = buffer.create(8)
	buffer.writef64(clock_buf, 0, clock_time)
	write_to_buffer(clock_buf)

	local unix_time = os.time()
	local unix_buf = buffer.create(8)
	buffer.writeu32(unix_buf, 0, unix_time % 0x100000000)
	buffer.writeu32(unix_buf, 4, math.floor(unix_time / 0x100000000))
	write_to_buffer(unix_buf)

	local date_time_ms = 5.678
	if DateTime then
		date_time_ms = DateTime.now().UnixTimestampMillis
		local dt_buf = buffer.create(8)
		buffer.writef64(dt_buf, 0, date_time_ms)
		write_to_buffer(dt_buf)

		local dt_prec_buf = buffer.create(16)
		buffer.writef32(dt_prec_buf, 0, date_time_ms / 1000)
		buffer.writef32(dt_prec_buf, 4, (date_time_ms % 1000) / 100)
		buffer.writef32(dt_prec_buf, 8, date_time_ms / 86400000)
		buffer.writef32(dt_prec_buf, 12, (date_time_ms * 0.001) % 1)
		write_to_buffer(dt_prec_buf)
	else
		write_to_buffer(buffer.create(24))
	end

	local frac_time_buf = buffer.create(16)
	buffer.writef32(frac_time_buf, 0, clock_time / 100)
	buffer.writef32(frac_time_buf, 4, current_time / 1000)
	buffer.writef32(frac_time_buf, 8, (clock_time * 12345.6789) % 1)
	buffer.writef32(frac_time_buf, 12, (current_time * 98765.4321) % 1)
	write_to_buffer(frac_time_buf)

	local noise_buf = buffer.create(32)
	for i = 0, 7 do
		local n1 = math.noise(clock_time + i, unix_time + i, clock_time + unix_time + i)
		local n2 = math.noise(current_time + i * 0.1, date_time_ms * 0.0001 + i, clock_time * 1.5 + i)
		local n3 = math.noise(unix_time * 0.01 + i, clock_time + date_time_ms * 0.001, current_time + i * 2)
		local n4 = math.noise(date_time_ms * 0.00001 + i, unix_time + clock_time + i, current_time * 0.1 + i)
		buffer.writef32(noise_buf, i * 4, n1 + n2 + n3 + n4)
	end
	write_to_buffer(noise_buf)

	local bench_buf = buffer.create(32)
	for i = 0, 7 do
		local start_time = os.clock()
		local sum = 0
		local iterations = 50 + i * 25
		for j = 1, iterations do
			sum += j*j + math.sin(j/10)*math.cos(j/7)
		end
		local end_time = os.clock()
		buffer.writef32(bench_buf, i*4, (end_time - start_time) * 1000000)
	end
	write_to_buffer(bench_buf)

	local alloc_buf = buffer.create(24)
	for i = 0,5 do
		local start_alloc = os.clock()
		for j = 1,20 do
			local tmp = buffer.create(64+j)
		end
		local end_alloc = os.clock()
		buffer.writef32(alloc_buf, i*4, (end_alloc - start_alloc)*10000000)
	end
	
	write_to_buffer(alloc_buf)
	local micro_time = math.floor(current_time*1000000)
	local micro_buf = buffer.create(8)
	buffer.writeu32(micro_buf, 0, micro_time % 0x100000000)
	buffer.writeu32(micro_buf, 4, math.floor(micro_time/0x100000000))
	write_to_buffer(micro_buf)

	local function add_entropy(entropy, warn, provider)
		if not entropy then return end
		local left = 1024 - offset
		if left > 0 then
			local truncated = math.min(left, buffer.len(entropy))
			if buffer.len(entropy) > left and warn and provider then
				warn(`CSPRNG: {provider} returned {buffer.len(entropy) - left} extra bytes truncated to {truncated}`)
			end
			buffer.copy(entropy_buffers, offset, entropy, 0, truncated)
			offset += truncated
		end
	end

	for i, prov in ipairs(csprng.entropy_providers) do
		if offset < 1024 then
			local success, out = pcall(prov, 1024-offset)
			add_entropy(out, true, `entropy provider #{i}`)
		end
	end

	if custom_entropy then
		add_entropy(custom_entropy, false)
	end

	local km = blake3(entropy_buffers, key_size + nonce_size)
	csprng.key = buffer.create(key_size)
	buffer.copy(csprng.key, 0, km, 0, key_size)
	csprng.nonce = buffer.create(nonce_size)
	buffer.copy(csprng.nonce, 0, km, key_size, nonce_size)

	return 1024 - offset
end

local function generate_block()
	buffer.fill(input_buffer, 0, 0, block_size)
	local out = chacha20(input_buffer, csprng.key, csprng.nonce, csprng.counter, 20)
	csprng.buffer = csprng.block_expansion and blake3(out, size_target_clamped) or out
	csprng.buffer_position = 0
	csprng.buffer_size = buffer.len(csprng.buffer)
	csprng.counter += 1
	if csprng.counter % rekey_threshold == 0 then
		gather_entropy()
		csprng.counter = 0
	end
end

local function get_bytes(count)
	local out = buffer.create(count)
	local pos = 0
	while pos < count do
		if csprng.buffer_position >= csprng.buffer_size then
			generate_block()
		end
		local need = count - pos
		local avail = csprng.buffer_size - csprng.buffer_position
		local to_copy = math.min(need, avail)
		buffer.copy(out, pos, csprng.buffer, csprng.buffer_position, to_copy)
		pos += to_copy
		csprng.buffer_position += to_copy
	end
	return out
end

local function get_float()
	if csprng.buffer_position+8 > csprng.buffer_size then generate_block() end
	local hi = buffer.readu32(csprng.buffer, csprng.buffer_position)
	local lo = buffer.readu32(csprng.buffer, csprng.buffer_position+4)
	csprng.buffer_position += 8
	return ((bit32.rshift(hi,5) * 67108864) + bit32.rshift(lo,6)) / 9007199254740992
end

local function get_int_range(min,max)
	if max == nil then min,max = 1,min end
	local range = max-min+1
	local limit = 0xFFFFFFFF - (0xFFFFFFFF % range)
	local val
	repeat
		if csprng.buffer_position+4 > csprng.buffer_size then generate_block() end
		val = buffer.readu32(csprng.buffer, csprng.buffer_position)
		csprng.buffer_position += 4
	until bit32.band(range,range-1)==0 or val <= limit
	if bit32.band(range, range-1) == 0 then
		return min + bit32.band(val, range-1)
	else
		return min + (val % range)
	end
end

local function get_number_range(min,max)
	if max == nil then min,max = 0,min end
	local r = get_float()
	return min + r * (max - min)
end

local function get_random_string(length,as_buffer)
	local fixed = if length%4~=0 then length+(4-length%4) else length
	local chars = buffer.create(fixed)
	for i=0,fixed-1,4 do
		buffer.writeu32(chars,i,bit32.bor(
			bit32.lshift(get_int_range(36,122),0),
			bit32.lshift(get_int_range(36,122),8),
			bit32.lshift(get_int_range(36,122),16),
			bit32.lshift(get_int_range(36,122),24)
			))
	end
	if as_buffer then
		if fixed==length then return chars end
		local out = buffer.create(length)
		buffer.copy(out,0,chars,0,length)
		return out
	end
	return buffer.readstring(chars,0,length)
end

local function get_ed25519_random_bytes()
	local out = buffer.create(32)
	for i=0,31,4 do
		buffer.writeu32(out,i,bit32.bor(
			bit32.lshift(get_int_range(0,255),0),
			bit32.lshift(get_int_range(0,255),8),
			bit32.lshift(get_int_range(0,255),16),
			bit32.lshift(get_int_range(0,255),24)
			))
	end
	return out
end

local function get_ed25519_clamped_bytes(buf)
	local out = buffer.create(32)
	buffer.copy(out,0,buf,0,32)
	buffer.writeu8(out,0,bit32.band(buffer.readu8(out,0),0xF8))
	local last = bit32.bor(bit32.band(buffer.readu8(out,31),0x7F),0x40)
	buffer.writeu8(out,31,last)
	local first_mid = buffer.readu8(out,1)
	local has_var = false
	for i=2,30 do
		if buffer.readu8(out,i) ~= first_mid then has_var=true break end
	end
	if not has_var then buffer.writeu8(out,15,bit32.bxor(first_mid,0x55)) end
	return out
end

local function get_hex_string(len)
	return hexconv.tohex(get_bytes(len/2))
end

function csprng.add_entropy_provider(f)
	table.insert(csprng.entropy_providers,f)
end

function csprng.remove_entropy_provider(f)
	for i=#csprng.entropy_providers,1,-1 do
		if csprng.entropy_providers[i]==f then table.remove(csprng.entropy_providers,i) break end
	end
end

function csprng.random() return get_float() end
function csprng.random_int(min,max) return get_int_range(min,max) end
function csprng.random_number(min,max) return get_number_range(min,max) end
function csprng.random_bytes(count) return get_bytes(count) end
function csprng.random_string(len,as_buffer) return get_random_string(len,as_buffer) end
function csprng.random_hex(len) return get_hex_string(len) end
function csprng.ed25519_clamped_bytes(buf) return get_ed25519_clamped_bytes(buf) end
function csprng.ed25519_random() return get_ed25519_clamped_bytes(get_ed25519_random_bytes()) end
function csprng.reseed(entropy) reset() gather_entropy(entropy) end

csprng.bytes_left = gather_entropy()
generate_block()

return csprng
