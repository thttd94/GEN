screen.init(0)

local IMG_DIR = "/var/mobile/Media/1ferver/lua/examples/"
local CHECK_IMG = IMG_DIR .. "check20p_1.PNG"
local TAP_IMG = IMG_DIR .. "tap20p.PNG"
local FINAL_IMG = IMG_DIR .. "0910.PNG"

local MAX_RUNTIME_SEC = 3 * 60 * 60
local SCRIPT_START_AT = os.time()

-- Vùng "đẹp" cho check20p: trên trung tâm 1 chút
local GOOD_Y_MIN = 360
local GOOD_Y_MAX = 620
local TARGET_Y = 500

local function status(t)
 sys.toast(t, 1)
 nLog(t)
end

local function isTimeout()
 return (os.time() - SCRIPT_START_AT) >= MAX_RUNTIME_SEC
end

local function checkTimeout()
 if isTimeout() then
  status("Da qua 3h, dung script")
  return true
 end
 return false
end

local function findImage(img, sim, x1, y1, x2, y2)
 sim = sim or 85
 x1 = x1 or 0
 y1 = y1 or 0
 x2 = x2 or 750
 y2 = y2 or 1334

 local x, y = screen.find_image(img, sim, x1, y1, x2, y2)
 if x ~= -1 then
  return true, x, y
 end
 return false, -1, -1
end

local function findCheck()
 return findImage(CHECK_IMG, 85, 0, 120, 750, 1230)
end

local function findTap()
 return findImage(TAP_IMG, 85, 0, 120, 750, 1230)
end

local function findFinal()
 return findImage(FINAL_IMG, 85, 0, 120, 750, 1230)
end

local function isCheckInGoodZone(y)
 return y >= GOOD_Y_MIN and y <= GOOD_Y_MAX
end

local function adjustCheckToBetterPosition(x, y)
 if not x or not y or x < 0 or y < 0 then
  local ok
  ok, x, y = findCheck()
  if not ok then
   return false, -1, -1
  end
 end

 if y < 260 then
  status("Check dang qua cao, tam giu nguyen")
  return true, x, y
 end

 if isCheckInGoodZone(y) then
  status("Check dang o vi tri dep, khong can keo")
  return true, x, y
 end

 local anchorX = 375
 local startY = y + 140
 if startY < 900 then
  startY = 900
 end
  if startY > 1180 then
  startY = 1180
 end

 local endY = TARGET_Y
 if endY < 420 then
  endY = 420
 end

 local dragDistance = startY - endY
 if dragDistance < 180 then
  startY = endY + 220
  dragDistance = startY - endY
 end

 if dragDistance < 140 then
  status("Check gan vi tri dep, khong can keo")
  return true, x, y
 end

 status("Dang keo card event 20p len khoi popup de")
 touch.down(1, anchorX, startY)
 sys.msleep(90)

 local currentY = startY
 local step = 32
 while currentY > endY do
  currentY = currentY - step
  if currentY < endY then
   currentY = endY
  end
  touch.move(1, anchorX, currentY)
  sys.msleep(16)
 end

 sys.msleep(140)
 touch.up(1)
 sys.msleep(500)

 local okAfter, xAfter, yAfter = findCheck()
 if okAfter then
  if isCheckInGoodZone(yAfter) then
   status("Da keo event 20p vao vung giua de quan sat")
  else
   status("Da keo event 20p len, se canh tiep o vi tri moi")
  end
  return true, xAfter, yAfter
 end

 status("Da keo card event nhung chua thay lai check, van tiep tuc canh")
 return true, x, y
end

local function swipeUpSearchOneRound()
 if checkTimeout() then return "timeout", -1, -1 end

 local x = 375
 local yStart = 1180
 local yEnd = 180
 local step = 54
 local delay = 54

 touch.down(1, x, yStart)
 sys.msleep(120)

 local y = yStart
 local tick = 0
 while y > yEnd do
  if checkTimeout() then
   touch.up(1)
   return "timeout", -1, -1
  end

  y = y - step
  touch.move(1, x, y)
  tick = tick + 1

  if tick % 4 == 0 then
   local ok, fx, fy = findCheck()
   if ok then
    touch.up(1)
    status("Da thay check20p_1.PNG: " .. fx .. "," .. fy)
    return true, fx, fy
   end
  end

  sys.msleep(delay)
 end

 touch.up(1)
 sys.msleep(120)
 return false, -1, -1
end

local function swipeDownSearchOneRound()
 if checkTimeout() then return "timeout", -1, -1 end

 local x = 375
 local yStart = 260
 local yEnd = 1220
 local step = 54
 local delay = 34

 touch.down(1, x, yStart)
 sys.msleep(120)

 local y = yStart
 local tick = 0
 while y < yEnd do
  if checkTimeout() then
   touch.up(1)
   return "timeout", -1, -1
  end

  y = y + step
  touch.move(1, x, y)
  tick = tick + 1

  if tick % 4 == 0 then
   local ok, fx, fy = findCheck()
   if ok then
    touch.up(1)
    status("Da thay check20p_1.PNG: " .. fx .. "," .. fy)
    return true, fx, fy
   end
  end

  sys.msleep(delay)
 end

 touch.up(1)
 sys.msleep(120)
 return false, -1, -1
end

local function localRecoverSwipeUp()
 if checkTimeout() then return false end

 touch.down(1, 375, 1020)
 sys.msleep(70)
 local y = 1020
 while y > 760 do
  if checkTimeout() then
   touch.up(1)
   return false
  end

  y = y - 12
  touch.move(1, 375, y)
  sys.msleep(12)
 end
 touch.up(1)
 sys.msleep(180)
 return true
end

local function localRecoverSwipeDown()
 if checkTimeout() then return false end

 touch.down(1, 375, 760)
 sys.msleep(70)
 local y = 760
 while y < 1020 do
  if checkTimeout() then
   touch.up(1)
   return false
  end

  y = y + 12
  touch.move(1, 375, y)
  sys.msleep(12)
 end
 touch.up(1)
 sys.msleep(180)
 return true
end

local function recoverCheckNearby()
 if checkTimeout() then return "timeout", -1, -1 end

 status("Mat check, dang tim lai quanh vi tri hien tai")

 for round = 1, 4 do
  if checkTimeout() then return "timeout", -1, -1 end

  local ok, x, y = findCheck()
  if ok then
   status("Da tim lai check20p_1.PNG")
   return true, x, y
  end

  if not localRecoverSwipeUp() then
   return "timeout", -1, -1
  end
  ok, x, y = findCheck()
  if ok then
   status("Da tim lai check20p_1.PNG")
   return true, x, y
  end

  if not localRecoverSwipeDown() then
   return "timeout", -1, -1
  end
  ok, x, y = findCheck()
  if ok then
   status("Da tim lai check20p_1.PNG")
   return true, x, y
  end
 end

 return false, -1, -1
end

local function waitTapAfterCheck(timeoutSec, finalReady)
 if checkTimeout() then return "timeout", -1, -1, finalReady end

 if finalReady then
  status("Da thay 0910.PNG, cho tap cuoi")
 else
  status("Da thay check, dung yen cho tap20p.PNG")
 end

 local loops = math.floor((timeoutSec * 1000) / 250)
 local lostCount = 0
 local lostNeed = 8
 local tapVisibleLastLoop = false
 local tapCount = 0

 for i = 1, loops do
  if checkTimeout() then return "timeout", -1, -1, finalReady end

  local okFinal = findFinal()
  if okFinal and not finalReady then
   finalReady = true
   status("Da thay 0910.PNG, cho tap cuoi")
  end

  local okCheck = findCheck()
  if okCheck then
   lostCount = 0
  else
   lostCount = lostCount + 1
  end

  local okTap, tapX, tapY = findTap()
  if okTap then
   if not tapVisibleLastLoop then
    tapCount = tapCount + 1
    status("Da thay tap20p.PNG: " .. tapX .. "," .. tapY)
    touch.tap(tapX + 10, tapY + 10)
    status("Da bam tap20p.PNG lan " .. tapCount)
    if finalReady then
     status("Da bam tap cuoi sau khi thay 0910.PNG, dung script")
     return "done_final", tapX, tapY, finalReady
    end
   end
   tapVisibleLastLoop = true
  else
   tapVisibleLastLoop = false
  end

  if lostCount >= lostNeed then
   local okRecover = recoverCheckNearby()
   if okRecover == "timeout" then
    return "timeout", -1, -1, finalReady
   elseif okRecover then
    lostCount = 0
   else
    status("Khong tim lai duoc check quanh vi tri hien tai")
    return "lost", -1, -1, finalReady
   end
  end

  sys.msleep(250)
 end

 status("Het thoi gian cho tap20p.PNG")
 return "timeout_wait", -1, -1, finalReady
end

local function runSearchFlow(maxCycles)
 maxCycles = maxCycles or 30
 local lockedOnCheck = false
 local direction = "up"
 local roundsInDirection = 0
 local maxRoundsOneDirection = 12
 local finalReady = false

 for cycle = 1, maxCycles do
  if checkTimeout() then
   return false
  end

  if not finalReady then
   local okFinal = findFinal()
   if okFinal then
    finalReady = true
    status("Da thay 0910.PNG, cho tap cuoi")
   end
  end

  if not lockedOnCheck then
   local okCheck, xCheck, yCheck = findCheck()
   if okCheck then
    lockedOnCheck = true
    adjustCheckToBetterPosition(xCheck, yCheck)
    status("Da thay check20p_1.PNG, dung cuon")
   else
    if direction == "up" then
     okCheck, xCheck, yCheck = swipeUpSearchOneRound()
    else
     okCheck, xCheck, yCheck = swipeDownSearchOneRound()
    end

    if okCheck == "timeout" then
     return false
    end

    roundsInDirection = roundsInDirection + 1

    if okCheck then
     lockedOnCheck = true
     adjustCheckToBetterPosition(xCheck, yCheck)
    else
     if roundsInDirection >= maxRoundsOneDirection then
        if direction == "up" then
       direction = "down"
       status("Da cuon het huong len, dao chieu tim xuong")
      else
       direction = "up"
       status("Da cuon het huong xuong, dao chieu tim len")
      end
      roundsInDirection = 0
     end
    end
   end
  end

  if lockedOnCheck then
   local result, _, _, finalState = waitTapAfterCheck(8, finalReady)
   finalReady = finalState

   if result == "done_final" then
    return true
   elseif result == "lost" then
    lockedOnCheck = false
    status("Mat check, tiep tuc tim lai tu vi tri hien tai")
   elseif result == "timeout_wait" then
    status("Het thoi gian cho tap, tiep tuc tim quanh day")
    local okRecover = recoverCheckNearby()
    if okRecover == "timeout" then
     return false
    elseif okRecover then
     lockedOnCheck = true
    else
     lockedOnCheck = false
    end
   elseif result == "timeout" then
    return false
   end
  end
 end

 status("Khong hoan thanh duoc")
 return false
end

runSearchFlow(30)
