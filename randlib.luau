--[[ randlib.lua
    - features:
    	new(seed?)     	 : create a new RNG; seed optional
      	seed(new)        : reseed the RNG
      
      	next()           : 32-bit integer output
      	next_float()     : float in [0, 1)
      	randint(min,max) : integer in [min, max]
      	randrange(min,max,step) : pick from arithmetic range
      	randbool(p)      : true/false with probability p
      	randchoice(list) : random element from list
      	sample(list,k)   : pick k unique elements
      	randomize(list)  : shuffle a list in-place
      	randbytes(n)     : string of n random bytes
      	normal(mean,stddev) : normally-distributed number (Box-Muller)
]]

local randlib = {}
randlib.__index = randlib

local function randseed()
	local t = os.time()
	local c = math.floor(os.clock() * 1e6)
	local r = math.random(0, 0xfffffff)
	local s = bit32.bxor(t, c, r)
	return bit32.band(s, 0xffffffff)
end

function randlib.new(seed)
	return setmetatable({ state = seed or randseed() }, randlib)
end

function randlib:seed(new)
	self.state = new or randseed()
end

function randlib:next()
	local x = self.state
	x = bit32.bxor(x, bit32.lshift(x, 13))
	x = bit32.bxor(x, bit32.rshift(x, 17))
	x = bit32.bxor(x, bit32.lshift(x, 5))
	self.state = bit32.band(x, 0xffffffff)
	return self.state
end

function randlib:next_float()
	return self:next() / 0xffffffff
end

function randlib:randint(min, max)
	return min + (self:next() % (max - min + 1))
end

function randlib:randrange(min, max, step)
	step = step or 1
	local count = math.floor((max - min) / step) + 1
	return min + step * self:randint(0, count - 1)
end

function randlib:randbool(p)
	p = p or 0.5
	return self:next_float() < p
end

function randlib:randchoice(list)
	return list[self:randint(1, #list)]
end

function randlib:sample(list, k)
	local copy = { table.unpack(list) }
	self:randomize(copy)
	local out = {}
	for i = 1, math.min(k, #copy) do
		out[i] = copy[i]
	end
	return out
end

function randlib:randomize(list)
	for i = #list, 2, -1 do
		local j = self:randint(1, i)
		list[i], list[j] = list[j], list[i]
	end
	return list
end

function randlib:randbytes(n)
	local t = {}
	for i = 1, n do
		t[i] = string.char(self:randint(0, 255))
	end
	return table.concat(t)
end

function randlib:normal(mean, stddev)
	mean = mean or 0
	stddev = stddev or 1
	local u1, u2 = self:next_float(), self:next_float()
	local z = math.sqrt(-2 * math.log(u1)) * math.cos(2 * math.pi * u2)
	return mean + z * stddev
end

return randlib
