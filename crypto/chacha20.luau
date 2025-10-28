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

return chacha20
