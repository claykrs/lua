--!native
--!optimize 2

local tag_size = 16
local block_size = 16
local poly1305_key_size = 32

local function process_message(message: buffer, key: buffer): buffer
	local message_len = buffer.len(message)

	local padded = message
	local process_len = message_len

	if message_len % block_size ~= 0 or message_len == 0 then
		local pad_size = block_size - (message_len % block_size)
		process_len = message_len + pad_size
		padded = buffer.create(process_len)
		buffer.copy(padded, 0, message, 0, message_len)
		buffer.writeu8(padded, message_len, 1)
	end

	local partial_block_len = message_len - 15

	local r0 = buffer.readu32(key, 0) % (2 ^ 28)
	local r1 = bit32.band(buffer.readu32(key, 4), 0x0FFFFFFC) % (2 ^ 28) * (2 ^ 32)
	local r2 = bit32.band(buffer.readu32(key, 8), 0x0FFFFFFC) % (2 ^ 28) * (2 ^ 64)
	local r3 = bit32.band(buffer.readu32(key, 12), 0x0FFFFFFC) % (2 ^ 28) * (2 ^ 96)

	local r0low = r0 % (2 ^ 18)
	local r0high = r0 - r0low
	local r1low = r1 % (2 ^ 50)
	local r1high = r1 - r1low
	local r2low = r2 % (2 ^ 82)
	local r2high = r2 - r2low
	local r3low = r3 % (2 ^ 112)
	local r3high = r3 - r3low

	local s1 = 5 / (2 ^ 130) * r1
	local s2 = 5 / (2 ^ 130) * r2
	local s3 = 5 / (2 ^ 130) * r3

	local s1low = s1 % (2 ^ -80)
	local s1high = s1 - s1low
	local s2low = s2 % (2 ^ -48)
	local s2high = s2 - s2low
	local s3low = s3 % (2 ^ -16)
	local s3high = s3 - s3low

	local acc0, acc1, acc2, acc3 = 0, 0, 0, 0
	local acc4, acc5, acc6, acc7 = 0, 0, 0, 0

	for off = 0, process_len - 1, block_size do
		local m0 = buffer.readu32(padded, off)
		local m1 = buffer.readu32(padded, off + 4)
		local m2 = buffer.readu32(padded, off + 8)
		local m3 = buffer.readu32(padded, off + 12)

		local x0 = acc0 + acc1 + m0
		local x2 = acc2 + acc3 + m1 * (2 ^ 32)
		local x4 = acc4 + acc5 + m2 * (2 ^ 64)
		local x6 = acc6 + acc7 + m3 * (2 ^ 96)

		if off < partial_block_len then
			x6 = x6 + (2 ^ 128)
		end

		acc0 = x0 * r0low + x2 * s3low + x4 * s2low + x6 * s1low
		acc1 = x0 * r0high + x2 * s3high + x4 * s2high + x6 * s1high
		acc2 = x0 * r1low + x2 * r0low + x4 * s3low + x6 * s2low
		acc3 = x0 * r1high + x2 * r0high + x4 * s3high + x6 * s2high
		acc4 = x0 * r2low + x2 * r1low + x4 * r0low + x6 * s3low
		acc5 = x0 * r2high + x2 * r1high + x4 * r0high + x6 * s3high
		acc6 = x0 * r3low + x2 * r2low + x4 * r1low + x6 * r0low
		acc7 = x0 * r3high + x2 * r2high + x4 * r1high + x6 * r0high

		local y0 = acc0 + 3 * (2 ^ 69) - 3 * (2 ^ 69)
		acc0 -= y0
		acc1 += y0

		local y1 = acc1 + 3 * (2 ^ 83) - 3 * (2 ^ 83)
		acc1 -= y1
		acc2 += y1

		local y2 = acc2 + 3 * (2 ^ 101) - 3 * (2 ^ 101)
		acc2 -= y2
		acc3 += y2

		local y3 = acc3 + 3 * (2 ^ 115) - 3 * (2 ^ 115)
		acc3 -= y3
		acc4 += y3

		local y4 = acc4 + 3 * (2 ^ 133) - 3 * (2 ^ 133)
		acc4 -= y4
		acc5 += y4

		local y5 = acc5 + 3 * (2 ^ 147) - 3 * (2 ^ 147)
		acc5 -= y5
		acc6 += y5

		local y6 = acc6 + 3 * (2 ^ 163) - 3 * (2 ^ 163)
		acc6 -= y6
		acc7 += y6

		local y7 = acc7 + 3 * (2 ^ 181) - 3 * (2 ^ 181)
		acc7 -= y7

		acc0 += 5 / (2 ^ 130) * y7
	end

	local carry0 = acc0 % (2 ^ 16)
	acc1 = acc0 - carry0 + acc1

	local carry1 = acc1 % (2 ^ 32)
	acc2 = acc1 - carry1 + acc2

	local carry2 = acc2 % (2 ^ 48)
	acc3 = acc2 - carry2 + acc3

	local carry3 = acc3 % (2 ^ 64)
	acc4 = acc3 - carry3 + acc4

	local carry4 = acc4 % (2 ^ 80)
	acc5 = acc4 - carry4 + acc5

	local carry5 = acc5 % (2 ^ 96)
	acc6 = acc5 - carry5 + acc6

	local carry6 = acc6 % (2 ^ 112)
	acc7 = acc6 - carry6 + acc7

	local carry7 = acc7 % (2 ^ 130)

	acc0 = carry0 + 5 / (2 ^ 130) * (acc7 - carry7)
	carry0 = acc0 % (2 ^ 16)
	carry1 = acc0 - carry0 + carry1

	if carry7 == 0x3ffff * (2 ^ 112)
		and carry6 == 0xffff * (2 ^ 96)
		and carry5 == 0xffff * (2 ^ 80)
		and carry4 == 0xffff * (2 ^ 64)
		and carry3 == 0xffff * (2 ^ 48)
		and carry2 == 0xffff * (2 ^ 32)
		and carry1 == 0xffff * (2 ^ 16)
		and carry0 >= 0xfffb
	then
		carry7, carry6, carry5, carry4 = 0, 0, 0, 0
		carry3, carry2, carry1 = 0, 0, 0
		carry0 -= 0xfffb
	end

	local s0 = buffer.readu32(key, 16)
	local s1val = buffer.readu32(key, 20)
	local s2val = buffer.readu32(key, 24)
	local s3val = buffer.readu32(key, 28)

	local unpack0 = s0 + carry0 + carry1
	local unpack1 = unpack0 % (2 ^ 32)

	local unpack2 = unpack0 - unpack1 + s1val * (2 ^ 32) + carry2 + carry3
	local unpack3 = unpack2 % (2 ^ 64)

	local unpack4 = unpack2 - unpack3 + s2val * (2 ^ 64) + carry4 + carry5
	local unpack5 = unpack4 % (2 ^ 96)

	local unpack6 = unpack4 - unpack5 + s3val * (2 ^ 96) + carry6 + carry7
	local unpack7 = unpack6 % (2 ^ 128)

	local out = buffer.create(tag_size)
	buffer.writeu32(out, 0, unpack1)
	buffer.writeu32(out, 4, unpack3 / (2 ^ 32))
	buffer.writeu32(out, 8, unpack5 / (2 ^ 64))
	buffer.writeu32(out, 12, unpack7 / (2 ^ 96))

	return out
end

local function poly1305(message: buffer, key: buffer): buffer
	if message == nil then error("message cannot be nil", 2) end
	if typeof(message) ~= "buffer" then
		error(`message must be a buffer, got {typeof(message)}`, 2)
	end

	if key == nil then error("key cannot be nil", 2) end
	if typeof(key) ~= "buffer" then
		error(`key must be a buffer, got {typeof(key)}`, 2)
	end

	local key_len = buffer.len(key)
	if key_len ~= poly1305_key_size then
		error(`key must be exactly {poly1305_key_size} bytes long, got {key_len} bytes`, 2)
	end

	return process_message(message, key)
end

return poly1305
