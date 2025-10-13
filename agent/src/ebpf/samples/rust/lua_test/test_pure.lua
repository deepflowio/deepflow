-- test_pure.lua
-- Return a coroutine factory. The C runner expects this shape.

local function work(n)
    -- a bit of CPU to stabilize sampling
    local function leaf(k)
      if k <= 0 then return 1 end
      return 1 + leaf(k - 1)
    end
    for i = 1, n do
      leaf(6)
      coroutine.yield(i)  -- this should drive lua_yield/lua_yieldk
    end
    return "done"
  end
  
  return function(k)
    -- Optional: extra pcall surface inside Lua
    local ok, _ = pcall(function() return 1 end)
    ok = pcall(function() error("forced error for pcall path") end)
  
    return coroutine.create(function() return work(k) end)
  end