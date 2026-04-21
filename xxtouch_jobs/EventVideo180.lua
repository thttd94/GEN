screen.init(0)

local TIKTOK_LINKS = {
  'https://www.tiktok.com/t/ZSHoxS0P1/',
  'https://www.tiktok.com/t/ZSHox5J3M/',
  'https://www.tiktok.com/t/ZSHoksvp6/',
}

local function getEnv(name)
  local f = io.popen('printenv ' .. tostring(name or ''))
  if not f then return '' end
  local v = f:read('*a') or ''
  f:close()
  return (v:gsub('%s+$', ''))
end

local function status(t)
  sys.toast(t, 1)
  nLog(t)
end

local function buildLinks(appChoice)
  local out = {}
  local useLite = tostring(appChoice or '') == 'tiktok_lite'
  for _, link in ipairs(TIKTOK_LINKS) do
    if useLite then
      table.insert(out, string.gsub(link, 'https://www.tiktok.com', 'https://lite.tiktok.com'))
    else
      table.insert(out, link)
    end
  end
  return out
end

local function main()
  math.randomseed(os.time())
  math.random(); math.random(); math.random()
  local appChoice = getEnv('EVENT_VIDEO_180_APP')
  if appChoice ~= 'tiktok_lite' then
    appChoice = 'tiktok'
  end
  local links = buildLinks(appChoice)
  if #links == 0 then
    status('Khong co link Event 180')
    return
  end
  local pick = links[math.random(1, #links)]
  status('Mo Event Video 180 ' .. appChoice)
  app.open_url(pick)
end

main()
