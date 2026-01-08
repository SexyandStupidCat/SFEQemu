local function fmt_addr(v)
    if type(v) == "number" then
        return string.format("0x%x", v)
    end
    local s = tostring(v)
    return s:match("0x[%da-fA-F]+") or s
end
