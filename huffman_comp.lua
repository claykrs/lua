--[[ huffman_comp.lua
    - usage (assumes "lua" is installed and on PATH):
        "lua huffman_comp.lua < inp.txt > comp.huff"         -- compress inp.txt to binary comp.huff
        "lua huffman_comp.lua -d < comp.huff > og.txt"      -- decompress comp.huff to og.txt

        "lua huffman_comp.lua -b < inp.txt > comp.huff.b64" -- compress inp.txt and base64-encode output to comp.huff.b64
        "lua huffman_comp.lua -d -b < comp.huff.b64 > og.txt" -- base64-decode comp.huff.b64 then decompress to og.txt

    ** base64 is highly recommended for transfering a huffman-compressed file !! **
]] 
        
local arg = arg or {}

local function int_to_bytes(n, bytes)
    local t = {}
    for i = bytes - 1, 0, -1 do
        local p = 256 ^ i
        local v = math.floor(n / p) % 256
        t[#t + 1] = string.char(v)
    end
    return table.concat(t)
end

local function bytes_to_int(s, i, bytes)
    local n = 0
    for j = 0, bytes - 1 do
        n = n * 256 + (string.byte(s, i + j) or 0)
    end
    return n
end

local function count_freq(s)
    local out = {}
    for i = 1, #s do
        local c = s:sub(i, i)
        out[c] = (out[c] or 0) + 1
    end
    return out
end

local function make_heap()
    local h = {}
    local size = 0
    local function swap(i, j) h[i], h[j] = h[j], h[i] end
    local function sift_up(i)
        while i > 1 do
            local parent = math.floor(i / 2)
            if h[i].freq < h[parent].freq then
                swap(i, parent)
                i = parent
            else break end
        end
    end
    local function sift_down(i)
        while true do
            local l = i * 2
            local r = l + 1
            local smallest = i
            if l <= size and h[l].freq < h[smallest].freq then smallest = l end
            if r <= size and h[r].freq < h[smallest].freq then smallest = r end
            if smallest == i then break end
            swap(i, smallest)
            i = smallest
        end
    end
    return {
        push = function(node)
            size = size + 1
            h[size] = node
            sift_up(size)
        end,
        pop = function()
            if size == 0 then return nil end
            local root = h[1]
            h[1] = h[size]
            h[size] = nil
            size = size - 1
            if size > 0 then sift_down(1) end
            return root
        end,
        len = function() return size end
    }
end

local function build_tree(freq)
    local heap = make_heap()
    for c, f in pairs(freq) do
        heap.push({ char = c, freq = f, left = nil, right = nil })
    end
    if heap.len() == 0 then return nil end
    if heap.len() == 1 then
        local only = heap.pop()
        return { freq = only.freq, left = only, right = nil }
    end
    while heap.len() > 1 do
        local n1 = heap.pop()
        local n2 = heap.pop()
        heap.push({
            freq = n1.freq + n2.freq,
            left = n1, right = n2,
            char = nil
        })
    end
    return heap.pop()
end

local function build_codes(root)
    local codes = {}
    if not root then return codes end
    if root.char then
        codes[root.char] = "0"
        return codes
    end
    local stack = { { node = root, path = "" } }
    while #stack > 0 do
        local entry = table.remove(stack)
        local node, path = entry.node, entry.path
        if node.char then
            codes[node.char] = path ~= "" and path or "0"
        else
            if node.right then stack[#stack + 1] = { node = node.right, path = path .. "1" } end
            if node.left  then stack[#stack + 1] = { node = node.left,  path = path .. "0" } end
        end
    end
    return codes
end

local function serialize_tree(root)
    if not root then return "" end
    local out = {}
    local function rec(n)
        if n == nil then return end
        if n.char then
            out[#out + 1] = string.char(1)
            out[#out + 1] = n.char
        else
            out[#out + 1] = string.char(0)
            rec(n.left)
            rec(n.right)
        end
    end
    rec(root)
    return table.concat(out)
end

local function deserialize_tree(s, i)
    i = i or 1
    local marker = string.byte(s, i)
    if not marker then error("deserialize: unexpected end") end
    if marker == 1 then
        local c = s:sub(i + 1, i + 1)
        return { char = c, freq = nil, left = nil, right = nil }, i + 2
    elseif marker == 0 then
        local left, ni = deserialize_tree(s, i + 1)
        local right, nj = deserialize_tree(s, ni)
        return { char = nil, left = left, right = right }, nj
    else
        error("deserialize: bad marker")
    end
end

local function compress(s)
    local n = #s
    if n == 0 then
        return int_to_bytes(0, 4) .. int_to_bytes(0, 8)
    end
    local freq = count_freq(s)
    local root = build_tree(freq)
    local codes = build_codes(root)
    local tree_s = serialize_tree(root)
    local tree_len = #tree_s
    local out_bytes = {}
    local cur_byte = 0
    local cur_bits = 0
    for i = 1, n do
        local c = s:sub(i, i)
        local code = codes[c]
        for j = 1, #code do
            cur_byte = cur_byte * 2
            if code:sub(j, j) == "1" then cur_byte = cur_byte + 1 end
            cur_bits = cur_bits + 1
            if cur_bits == 8 then
                out_bytes[#out_bytes + 1] = string.char(cur_byte)
                cur_byte = 0
                cur_bits = 0
            end
        end
    end
    if cur_bits > 0 then
        cur_byte = cur_byte * (2 ^ (8 - cur_bits))
        out_bytes[#out_bytes + 1] = string.char(cur_byte)
    end
    local header = int_to_bytes(tree_len, 4) .. tree_s .. int_to_bytes(n, 8)
    return header .. table.concat(out_bytes)
end

local function decompress(blob)
    local p = 1
    local tree_len = bytes_to_int(blob, p, 4); p = p + 4
    if tree_len == 0 then return "" end
    local tree_s = blob:sub(p, p + tree_len - 1); p = p + tree_len
    local orig_len = bytes_to_int(blob, p, 8); p = p + 8
    local data = blob:sub(p)
    local root, nexti = deserialize_tree(tree_s, 1)
    local out_chars = {}
    if root.char then
        for i = 1, orig_len do out_chars[#out_chars + 1] = root.char end
        return table.concat(out_chars)
    end
    local node = root
    local decoded = 0
    local bi = 1
    local data_len = #data
    while decoded < orig_len and bi <= data_len do
        local byte = string.byte(data, bi)
        for bit = 7, 0, -1 do
            local b = math.floor(byte / (2 ^ bit)) % 2
            if b == 0 then
                node = node.left
            else
                node = node.right
            end
            if node.char then
                out_chars[#out_chars + 1] = node.char
                decoded = decoded + 1
                if decoded >= orig_len then break end
                node = root
            end
        end
        bi = bi + 1
    end
    return table.concat(out_chars)
end

local b64chars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
local b64map = nil
local function build_b64map()
    b64map = {}
    for i = 1, #b64chars do
        b64map[b64chars:sub(i,i)] = i - 1
    end
    b64map["="] = 0
end

local function base64_encode(s)
    local out = {}
    local len = #s
    local i = 1
    while i <= len do
        local a = string.byte(s, i) or 0
        local b = string.byte(s, i + 1) or 0
        local c = string.byte(s, i + 2) or 0
        local avail = math.min(3, len - i + 1)
        local n = a * 65536 + b * 256 + c
        local idx1 = math.floor(n / 262144) % 64
        local idx2 = math.floor(n / 4096) % 64
        local idx3 = math.floor(n / 64) % 64
        local idx4 = n % 64
        if avail == 3 then
            out[#out + 1] = b64chars:sub(idx1 + 1, idx1 + 1)
            out[#out + 1] = b64chars:sub(idx2 + 1, idx2 + 1)
            out[#out + 1] = b64chars:sub(idx3 + 1, idx3 + 1)
            out[#out + 1] = b64chars:sub(idx4 + 1, idx4 + 1)
        elseif avail == 2 then
            out[#out + 1] = b64chars:sub(idx1 + 1, idx1 + 1)
            out[#out + 1] = b64chars:sub(idx2 + 1, idx2 + 1)
            out[#out + 1] = b64chars:sub(idx3 + 1, idx3 + 1)
            out[#out + 1] = "="
        else
            out[#out + 1] = b64chars:sub(idx1 + 1, idx1 + 1)
            out[#out + 1] = b64chars:sub(idx2 + 1, idx2 + 1)
            out[#out + 1] = "=="
        end
        i = i + 3
    end
    return table.concat(out)
end

local function base64_decode(s)
    if not b64map then build_b64map() end
    local clean = s:gsub("%s+", "")
    local out = {}
    local len = #clean
    local i = 1
    while i <= len do
        local c1 = clean:sub(i, i)
        local c2 = clean:sub(i + 1, i + 1)
        local c3 = clean:sub(i + 2, i + 2)
        local c4 = clean:sub(i + 3, i + 3)
        local a = b64map[c1] or 0
        local b = b64map[c2] or 0
        local c = b64map[c3] or 0
        local d = b64map[c4] or 0
        local n = a * 262144 + b * 4096 + c * 64 + d
        local byte1 = math.floor(n / 65536) % 256
        local byte2 = math.floor(n / 256) % 256
        local byte3 = n % 256
        if c3 == "=" then
            out[#out + 1] = string.char(byte1)
        elseif c4 == "=" then
            out[#out + 1] = string.char(byte1, byte2)
        else
            out[#out + 1] = string.char(byte1, byte2, byte3)
        end
        i = i + 4
    end
    return table.concat(out)
end

local function slurp_all()
    return io.read("*a") or ""
end

local do_b64 = false
local do_decomp = false
for i = 1, #arg do
    if arg[i] == "-b" then do_b64 = true end
    if arg[i] == "-d" then do_decomp = true end
end

if do_decomp then
    local blob = slurp_all()
    if do_b64 then
        blob = base64_decode(blob)
    end
    local ok, out = pcall(decompress, blob)
    if not ok then
        io.stderr:write("decompress error: " .. tostring(out) .. "\n")
        os.exit(1)
    end
    io.write(out)
else
    local input = slurp_all()
    local ok, out = pcall(compress, input)
    if not ok then
        io.stderr:write("compress error: " .. tostring(out) .. "\n")
        os.exit(1)
    end
    if do_b64 then out = base64_encode(out) end
    io.write(out)
end
