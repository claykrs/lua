local base36_chars = {
	'0','1','2','3','4','5','6','7','8','9',
	'A','B','C','D','E','F','G','H','I','J',
	'K','L','M','N','O','P','Q','R','S','T',
	'U','V','W','X','Y','Z'
}

return {
	encode = function(n)
		if n == 0 then
			return "0"
		end
		local res = {}
		while n > 0 do
			local digit = (n % 36) + 1
			table.insert(res, 1, base36_chars[digit])
			n = math.floor(n / 36)
		end
		return table.concat(res)
	end,
	decode = function(s)
		local n = 0
		for i = 1, #s do
			local c = s:sub(i, i)
			local val

			if c >= '0' and c <= '9' then
				val = string.byte(c) - 48
			elseif c >= 'A' and c <= 'Z' then
				val = string.byte(c) - 55
			elseif c >= 'a' and c <= 'z' then
				val = string.byte(c) - 87
			else
				error("invalid character in base36 string")
			end
			n = n * 36 + val
		end
		return n
	end,
}
