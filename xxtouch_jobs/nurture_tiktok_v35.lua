screen.init(0)

local SCRIPT_VERSION = "3.5"
local STAGE3_TIMEOUT_SEC = 3600
local stage3_started_at = nil
local restart_from_stage1 = false

local function beginStage3Watch()
 stage3_started_at = os.time()
 restart_from_stage1 = false
end

local function clearStage3Watch()
 stage3_started_at = nil
 restart_from_stage1 = false
end

local function markStage3Restart(reason)
 restart_from_stage1 = true
 phase(reason or "Stage 3 quá 60p, quay lại Stage 1")
 return false
end

local function shouldRestartFromStage3()
 if restart_from_stage1 then
  return true
 end

 if stage3_started_at and (os.time() - stage3_started_at >= STAGE3_TIMEOUT_SEC) then
  return markStage3Restart("Stage 3 quá 60p, quay lại Stage 1")
 end

 return false
end

local function sleep(ms)
 sys.msleep(ms)
end

local __last_status = ""
local __last_status_at = 0
local __phase = ""

local function shortText(t)
 if #t > 26 then
  return string.sub(t, 1, 23) .. "..."
 end
 return t
end

function status(t)
 t = shortText(t)
 local text = "Ver " .. SCRIPT_VERSION .. " : " .. t
 local now = os.time()
 if text ~= __last_status or now - __last_status_at >= 1 then
  sys.toast(text, 0)
  __last_status = text
  __last_status_at = now
 end
end

function phase(t)
 __phase = t
 __last_status = ""
 status(t)
end

function phaseProgress(sec)
 status(__phase .. " " .. sec .. "s")
end

function waitCountdown(ms, label)
 local remain = ms
 local lastShown = -1

 while remain > 0 do
  local sec = math.ceil(remain / 1000)
  if sec ~= lastShown then
   status(label .. " " .. sec .. "s")
   lastShown = sec
  end

  local step = 1000
  if remain < 1000 then
   step = remain
  end

  sleep(step)
  remain = remain - step
 end
end

function waitPhase(ms)
 local remain = ms
 local lastShown = -1

 while remain > 0 do
  if shouldRestartFromStage3() then
   return false
  end

  local sec = math.ceil(remain / 1000)
  if sec ~= lastShown then
   phaseProgress(sec)
   lastShown = sec
  end

  local step = 1000
  if remain < 1000 then
   step = remain
  end

  sleep(step)
  remain = remain - step
 end

 return true
end

function waitTap(pattern, x, y, time)
 local start = os.time()
 local lastShown = -1

 while os.time() - start < time do
  if shouldRestartFromStage3() then
   return false
  end

  local remain = time - (os.time() - start)
  if remain ~= lastShown then
   phaseProgress(remain)
   lastShown = remain
  end

  if screen.is_colors(pattern, 90) then
   touch.tap(x, y)
   return true
  end

  sleep(100)
 end

 return false
end

local RES_DIR = "/var/mobile/Media/1ferver/lua/examples/"
local TIKTOK_BUNDLE = "com.ss.iphone.ugc.Ame"
local TIKTOK_LITE_BUNDLE = "com.zhiliaoapp.musicallylite"
local APPMANAGER_BUNDLE = "com.tigisoftware.ADManager"
local POPUP_1_CHECK = { RES_DIR .. "Popup_1_check1.png" }
local POPUP_1_TAP = RES_DIR .. "Popup_1_tap.png"
local POPUP_2_CHECK = { RES_DIR .. "Popup_2_check1.png", RES_DIR .. "Popup_2_check2.png" }
local POPUP_2_TAP = RES_DIR .. "Popup_2_tap.png"
local POPUP_3_CHECK = { RES_DIR .. "Popup_3_check1.png" }
local POPUP_3_TAP = RES_DIR .. "Popup_3_tap.png"
local POPUP_4_CHECK = { RES_DIR .. "Popup_4_check1.png" }
local POPUP_4_TAP = RES_DIR .. "Popup_4_tap.png"
local POPUP_5_CHECK = { RES_DIR .. "Popup_5_check1.png" }
local POPUP_5_TAP = RES_DIR .. "Popup_5_tap.png"
local POPUP_6_CHECK = { RES_DIR .. "Popup_6_check1.png", RES_DIR .. "Popup_6_check2.png" }
local POPUP_6_TAP = RES_DIR .. "Popup_6_tap.png"
local POPUP_8_CHECK = { RES_DIR .. "Popup_8_check1.png", RES_DIR .. "Popup_8_check2.png" }
local POPUP_8_TAP = RES_DIR .. "Popup_8_tap.png"
local POPUP_9_CHECK = { RES_DIR .. "Popup_9_check1.png" }
local POPUP_9_TAP = RES_DIR .. "Popup_9_tap.png"
local OK_IMG = RES_DIR .. "OK.png"
local APPSTORE_INSTALL_ERROR = {
 {214,536,0x000000},{283,534,0x000000},{370,534,0x000000},{453,535,0x000000},
 {282,585,0x4f4f4f},{373,585,0x4d4d4d},{313,682,0x007aff},{372,683,0x007aff}
}
local TIKTOK_ROW_IMG = RES_DIR .. "tiktok_row.png"
local TIKTOK_BACKUP_IMG = RES_DIR .. "tiktok_backup.png"
local TIKTOK_BACKUPDATA_IMG = RES_DIR .. "tiktok_backupData.png"
local TIKTOK_BACKUPING_IMG = RES_DIR .. "tiktok_backuping.png"
local BACKUPOK_IMG = RES_DIR .. "backupok.png"
local EVENT_X1 = 0
local EVENT_Y1 = 120
local EVENT_X2 = 260
local EVENT_Y2 = 420
local EVENT_COLOR_PATTERNS = {
 { name = "event_gold_m", offsetX = 0, offsetY = 0, points = {{0,0,0xffd31b},{-69,0,0xffd31b},{-72,10,0xffd31b},{-28,20,0xffd31b},{-4,-6,0xffd31b}} },
 { name = "event_gold_s", offsetX = 0, offsetY = 0, points = {{0,0,0xffd31b},{-62,0,0xffd31b},{-65,9,0xffd31b},{-25,18,0xffd31b},{-3,-5,0xffd31b}} },
 { name = "event_gold_l", offsetX = 0, offsetY = 0, points = {{0,0,0xffd31b},{-76,0,0xffd31b},{-79,11,0xffd31b},{-31,22,0xffd31b},{-4,-7,0xffd31b}} },
 { name = "event_coin2_m", offsetX = 0, offsetY = 0, points = {{0,0,0xfdb932},{-24,-20,0xfcbd1e},{1,-38,0xffc737},{-13,-11,0xffce32},{2,-22,0xffde66}} },
 { name = "event_coin2_s", offsetX = 0, offsetY = 0, points = {{0,0,0xfdb932},{-22,-18,0xfcbd1e},{1,-34,0xffc737},{-12,-10,0xffce32},{2,-20,0xffde66}} },
 { name = "event_coin2_l", offsetX = 0, offsetY = 0, points = {{0,0,0xfdb932},{-26,-22,0xfcbd1e},{1,-42,0xffc737},{-14,-12,0xffce32},{2,-24,0xffde66}} }
}
local popup_cleared = false

function findImage(img, sim, x1, y1, x2, y2)
 sim = sim or 82
 x1 = x1 or 0
 y1 = y1 or 0
 x2 = x2 or 750
 y2 = y2 or 1334
 local x, y = screen.find_image(img, sim, x1, y1, x2, y2)
 if x ~= -1 then return true, x, y end
 return false, -1, -1
end
function findAnyImage(imgList, sim, x1, y1, x2, y2)
 for i = 1, #imgList do
  local ok, x, y = findImage(imgList[i], sim, x1, y1, x2, y2)
  if ok then return true, x, y, imgList[i] end
 end
 return false, -1, -1, nil
end
function tapByImage(img, sim, x1, y1, x2, y2, offsetX, offsetY)
 offsetX = offsetX or 0
 offsetY = offsetY or 0
 local ok, x, y = findImage(img, sim, x1, y1, x2, y2)
 if ok then touch.tap(x + offsetX, y + offsetY) return true, x, y end
 return false, -1, -1
end
function hasPopup7ByColor()
 local x, y = screen.find_color({{195,865,0xffffff},{179,867,0xffffff},{180,889,0xffffff},{351,876,0xffffff},{353,900,0xffffff},{441,875,0xffffff},{469,876,0xffffff},{555,880,0xffffff}}, 90, 0, 0, 0, 0)
 if x ~= -1 then return true, x, y end
 return false, -1, -1
end
function hasAgreeContinuePopupByColor()
 local x, y = screen.find_color({{189,586,0xffffff},{560,586,0xffffff},{189,798,0xffffff},{560,798,0xffffff},{374,807,0xffffff}}, 86, 120, 420, 640, 980)
 if x ~= -1 then return true, x, y end
 return false, -1, -1
end
function handlePopup8Fixed()
 local byAgree = hasAgreeContinuePopupByColor()
 local byCheck = findAnyImage(POPUP_8_CHECK, 84, 0, 0, 750, 1334)
 if (not byAgree) and (not byCheck) then return false end
 phase("Popup 8")
 status("Popup 8 detect")
 touch.tap(370, 807)
 waitPhase(700)
 if hasAgreeContinuePopupByColor() or findAnyImage(POPUP_8_CHECK, 84, 0, 0, 750, 1334) then status("Popup 8 còn") else status("Popup 8 hết") end
 return true
end
function hasAppStoreInstallError() return screen.is_colors(APPSTORE_INSTALL_ERROR, 88) end
function handleAppStoreInstallError() if not hasAppStoreInstallError() then return false end phase("Lỗi cài TikTok") touch.tap(337, 685) waitPhase(1500) return true end
function openTikTok() phase("Mở TikTok") app.run(TIKTOK_BUNDLE) waitPhase(10000) end
function closeTikTok() phase("Đóng TikTok") app.quit(TIKTOK_BUNDLE) waitPhase(1500) end
function closeAppManager() phase("Đóng AppManager") app.quit(APPMANAGER_BUNDLE) waitPhase(1500) end
function openAppManager() phase("Mở AppManager") app.run(APPMANAGER_BUNDLE) waitPhase(4000) end
function hasPopupActive()
 if findAnyImage(POPUP_1_CHECK, 88, 0, 0, 750, 1334) then return true end
 if findAnyImage(POPUP_2_CHECK, 88, 0, 0, 750, 1334) then return true end
 if findAnyImage(POPUP_3_CHECK, 88, 0, 0, 750, 1334) then return true end
 if findAnyImage(POPUP_4_CHECK, 88, 0, 0, 750, 1334) then return true end
 if findAnyImage(POPUP_5_CHECK, 88, 0, 0, 750, 1334) then return true end
 if findAnyImage(POPUP_6_CHECK, 88, 0, 0, 750, 1334) then return true end
 if hasAgreeContinuePopupByColor() then return true end
 if findAnyImage(POPUP_8_CHECK, 84, 0, 0, 750, 1334) then return true end
 if findAnyImage(POPUP_9_CHECK, 84, 0, 0, 750, 1334) then return true end
 if hasPopup7ByColor() and (not hasAgreeContinuePopupByColor()) and (not findAnyImage(POPUP_8_CHECK, 84, 0, 0, 750, 1334)) then return true end
 return false
end
function confirmNoPopupSlow()
 waitPhase(300); if findAnyImage(POPUP_1_CHECK, 88, 0, 0, 750, 1334) then return false end
 waitPhase(300); if findAnyImage(POPUP_2_CHECK, 88, 0, 0, 750, 1334) then return false end
 waitPhase(300); if findAnyImage(POPUP_3_CHECK, 88, 0, 0, 750, 1334) then return false end
 waitPhase(300); if findAnyImage(POPUP_4_CHECK, 88, 0, 0, 750, 1334) then return false end
 waitPhase(300); if findAnyImage(POPUP_5_CHECK, 88, 0, 0, 750, 1334) then return false end
 waitPhase(300); if findAnyImage(POPUP_6_CHECK, 88, 0, 0, 750, 1334) then return false end
 waitPhase(300); if hasAgreeContinuePopupByColor() then return false end
 waitPhase(300); if findAnyImage(POPUP_8_CHECK, 84, 0, 0, 750, 1334) then return false end
 waitPhase(300); if findAnyImage(POPUP_9_CHECK, 84, 0, 0, 750, 1334) then return false end
 waitPhase(300); if hasPopup7ByColor() and (not hasAgreeContinuePopupByColor()) and (not findAnyImage(POPUP_8_CHECK, 84, 0, 0, 750, 1334)) then return false end
 return true
end
function waitPopupStableFast() waitPhase(2500) end
function handlePopupByImages(name, checkImgs, tapImg, simCheck, simTap, x1, y1, x2, y2)
 local okCheck, checkX, checkY = findAnyImage(checkImgs, simCheck or 88, x1, y1, x2, y2)
 if not okCheck then return false end
 phase(name) status(name .. " detect")
 local tapped = tapByImage(tapImg, simTap or 88, x1, y1, x2, y2)
 if tapped then waitPhase(500) if findAnyImage(checkImgs, simCheck or 88, x1, y1, x2, y2) then status(name .. " còn") else status(name .. " hết") end return true end
 local fallbackOffsetX = 0 local fallbackOffsetY = 0 if name == "Popup 8" or name == "Popup 9" then fallbackOffsetX = 120 fallbackOffsetY = 120 end
 status(name .. " fallback") touch.tap(checkX + fallbackOffsetX, checkY + fallbackOffsetY) waitPhase(500)
 if findAnyImage(checkImgs, simCheck or 88, x1, y1, x2, y2) then status(name .. " còn") else status(name .. " hết") end
 return true
end
function handlePopupNoInternet()
 local found = findAnyImage(POPUP_4_CHECK, 88, 0, 0, 750, 1334)
 if not found then return false end
 phase("Lỗi mạng")
 local start = os.time() local lastShown = -1
 while os.time() - start < 60 do
  local remain = 60 - (os.time() - start)
  if remain ~= lastShown then phaseProgress(remain) lastShown = remain end
  local stillThere = findAnyImage(POPUP_4_CHECK, 88, 0, 0, 750, 1334)
  if not stillThere then break end
  tapByImage(POPUP_4_TAP, 88, 0, 0, 750, 1334)
  waitPhase(700)
 end
 return true
end
function ensurePopup7Cleared(maxRounds)
 maxRounds = maxRounds or 4
 for i = 1, maxRounds do
  if handlePopup8Fixed() then waitPhase(500) end
  if handlePopupByImages("Popup 9", POPUP_9_CHECK, POPUP_9_TAP, 84, 84, 0, 0, 750, 1334) then waitPhase(500) end
  if not hasAgreeContinuePopupByColor() and (not findAnyImage(POPUP_8_CHECK, 84, 0, 0, 750, 1334)) and (not findAnyImage(POPUP_9_CHECK, 84, 0, 0, 750, 1334)) and (not hasPopup7ByColor()) then return true end
  phase("Dọn Popup 7")
  local moved = false
  for j = 1, 3 do
   if handlePopup8Fixed() then waitPhase(500) end
   if handlePopupByImages("Popup 9", POPUP_9_CHECK, POPUP_9_TAP, 84, 84, 0, 0, 750, 1334) then waitPhase(500) end
   if not hasPopup7ByColor() then break end
   touch.down(1, 360, 1050) sleep(20) touch.move(1, 360, 860) sleep(20) touch.up(1)
   moved = true
   waitPhase(500)
  end
  if moved then waitPopupStableFast() end
  if handlePopup8Fixed() then waitPhase(500) end
  if handlePopupByImages("Popup 9", POPUP_9_CHECK, POPUP_9_TAP, 84, 84, 0, 0, 750, 1334) then waitPhase(500) end
  if not hasAgreeContinuePopupByColor() and (not findAnyImage(POPUP_8_CHECK, 84, 0, 0, 750, 1334)) and (not findAnyImage(POPUP_9_CHECK, 84, 0, 0, 750, 1334)) and (not hasPopup7ByColor()) then return true end
  runTikTokPopupFlow(20)
  waitPhase(300)
 end
 return (not hasAgreeContinuePopupByColor()) and (not hasPopup7ByColor()) and (not findAnyImage(POPUP_8_CHECK, 84, 0, 0, 750, 1334)) and (not findAnyImage(POPUP_9_CHECK, 84, 0, 0, 750, 1334))
end
function handlePopupSwipeUp()
 local found8 = hasAgreeContinuePopupByColor() or findAnyImage(POPUP_8_CHECK, 84, 0, 0, 750, 1334)
 if found8 then status("Đang có Popup 8") return false end
 local found = hasPopup7ByColor()
 if not found then return false end
 phase("Vuốt lên") status("Popup 7 -> vuốt lên")
 touch.down(1, 360, 1050) sleep(20) touch.move(1, 360, 860) sleep(20) touch.up(1)
 waitPhase(400)
 return true
end
function handleOnePopup()
 status("Rà Popup 1") if handlePopupByImages("Popup 1", POPUP_1_CHECK, POPUP_1_TAP, 88, 88, 0, 0, 750, 1334) then return true end
 status("Rà Popup 2") if handlePopupByImages("Popup 2", POPUP_2_CHECK, POPUP_2_TAP, 88, 88, 0, 0, 750, 1334) then return true end
 status("Rà Popup 3") if handlePopupByImages("Popup 3", POPUP_3_CHECK, POPUP_3_TAP, 88, 88, 0, 0, 750, 1334) then return true end
 status("Rà Popup 4") if handlePopupNoInternet() then return true end
 status("Rà Popup 5") if handlePopupByImages("Popup 5", POPUP_5_CHECK, POPUP_5_TAP, 88, 88, 0, 0, 750, 1334) then return true end
 status("Rà Popup 6") if handlePopupByImages("Popup 6", POPUP_6_CHECK, POPUP_6_TAP, 88, 88, 0, 0, 750, 1334) then return true end
 status("Rà Popup 8") if handlePopup8Fixed() then return true end
 status("Rà Popup 9") if handlePopupByImages("Popup 9", POPUP_9_CHECK, POPUP_9_TAP, 84, 84, 0, 0, 750, 1334) then return true end
 status("Rà Popup 7") if handlePopupSwipeUp() then return true end
 status("Không match popup")
 return false
end
function runTikTokPopupFlow(maxSeconds)
 local startTime = os.time() local lastShown = -1 maxSeconds = maxSeconds or 120 popup_cleared = false phase("Xử lý popup")
 while os.time() - startTime < maxSeconds do
  local remain = maxSeconds - (os.time() - startTime)
  if remain ~= lastShown then phaseProgress(remain) lastShown = remain end
  if hasPopupActive() then
   waitPopupStableFast()
   if handleOnePopup() then waitPhase(400) else phase("Popup chưa rõ") waitPhase(300) end
  else
   if confirmNoPopupSlow() then phase("Popup xong") popup_cleared = true return true else waitPopupStableFast() handleOnePopup() waitPhase(300) end
  end
 end
 phase("Popup timeout") popup_cleared = false return false
end
function findEventByColor(sim)
 sim = sim or 93
 for i = 1, #EVENT_COLOR_PATTERNS do
  local p = EVENT_COLOR_PATTERNS[i]
  local x, y = screen.find_color(p.points, sim, EVENT_X1, EVENT_Y1, EVENT_X2, EVENT_Y2)
  if x ~= -1 then return true, x + (p.offsetX or 0), y + (p.offsetY or 0), p.name end
 end
 return false, -1, -1, nil
end
function findEventFast() local ok, x, y, tag = findEventByColor(95) if ok then return true, x, y, tag end ok, x, y, tag = findEventByColor(93) if ok then return true, x, y, tag end ok, x, y, tag = findEventByColor(90) if ok then return true, x, y, tag end return false, -1, -1, nil end
function tapEventFast()
 if not popup_cleared then return false end
 local ok, x, y, hit = findEventFast()
 if not ok then return false end
 status("Đã thấy Event")
 if hit == "event_gold_m" or hit == "event_gold_s" or hit == "event_gold_l" then touch.tap(x, y) else touch.tap(x + 30, y + 30) end
 waitPhase(450)
 return true
end
function waitOKByImage(maxSeconds)
 local start = os.time() local lastShown = -1 maxSeconds = maxSeconds or 20 phase("Chờ OK")
 while os.time() - start < maxSeconds do
  local remain = maxSeconds - (os.time() - start)
  if remain ~= lastShown then phaseProgress(remain) lastShown = remain end
  local ok = findImage(OK_IMG, 82, 80, 220, 680, 920)
  if ok then status("Đã thấy OK") waitPhase(200) return true end
  sleep(100)
 end
 return false
end
function patrolPopupDuringEvent()
 if hasPopupActive() then
  phase("Tuần tra popup") status("Đang rà popup") waitPopupStableFast()
  if handleOnePopup() then status("Xử lý popup xong 1 nhịp") waitPhase(350) else status("Có popup nhưng chưa xử lý được") waitPhase(200) end
  return true
 end
 return false
end
function waitEventInWindow(seconds)
 local start = os.time() local lastShown = -1 local next_swipe_at = 20
 if not popup_cleared then phase("Chưa sạch popup") return false end
 phase("Chờ Event")
 while os.time() - start < seconds do
  local elapsed = os.time() - start
  local remain = seconds - elapsed
  if remain ~= lastShown then phaseProgress(remain) lastShown = remain end
  local popup_patrolled = patrolPopupDuringEvent()
  if (not popup_patrolled) and elapsed >= next_swipe_at then
   phase("Chờ Event - vuốt lên") touch.down(1, 360, 1050) sleep(20) touch.move(1, 360, 860) sleep(20) touch.up(1)
   next_swipe_at = next_swipe_at + 20
   waitPhase(500)
   popup_patrolled = patrolPopupDuringEvent()
  end
  if (not popup_patrolled) and tapEventFast() then
   if waitOKByImage(60) then phase("Qua Event") return true else phase("Event lỗi") return false end
  end
  sleep(80)
 end
 return false
end
function runEventFlowWithRestart() if not popup_cleared then phase("Chưa sạch popup") return false end return waitEventInWindow(60) end
function waitTapImage(img, msg, timeout, sim, x1, y1, x2, y2, offsetX, offsetY)
 local start = os.time() local lastShown = -1 sim = sim or 82 offsetX = offsetX or 0 offsetY = offsetY or 0 x1 = x1 or 0 y1 = y1 or 0 x2 = x2 or 750 y2 = y2 or 1334 phase(msg)
 while os.time() - start < timeout do
  local remain = timeout - (os.time() - start)
  if remain ~= lastShown then phaseProgress(remain) lastShown = remain end
  local ok, x, y = findImage(img, sim, x1, y1, x2, y2)
  if ok then touch.tap(x + offsetX, y + offsetY) waitPhase(1200) return true, x, y end
  sleep(300)
 end
 return false, -1, -1
end
function waitImageAppear(img, msg, timeout, sim, x1, y1, x2, y2)
 local start = os.time() local lastShown = -1 sim = sim or 82 x1 = x1 or 0 y1 = y1 or 0 x2 = x2 or 750 y2 = y2 or 1334 phase(msg)
 while os.time() - start < timeout do
  local remain = timeout - (os.time() - start)
  if remain ~= lastShown then phaseProgress(remain) lastShown = remain end
  local ok, x, y = findImage(img, sim, x1, y1, x2, y2)
  if ok then return true, x, y end
  sleep(300)
 end
 return false, -1, -1
end
function waitImageDisappear(img, msg, timeout, sim, x1, y1, x2, y2)
 local start = os.time() local lastShown = -1 sim = sim or 82 x1 = x1 or 0 y1 = y1 or 0 x2 = x2 or 750 y2 = y2 or 1334 phase(msg)
 while os.time() - start < timeout do
  local remain = timeout - (os.time() - start) local sec = math.ceil(remain)
  if sec ~= lastShown then phaseProgress(sec) lastShown = sec end
  local ok = findImage(img, sim, x1, y1, x2, y2)
  if not ok then return true end
  sleep(500)
 end
 return false
end
function backupTikTokInAppManager() phase("Bắt đầu backup") closeTikTok() closeAppManager() openAppManager() local row_ok = waitTapImage(TIKTOK_ROW_IMG, "Tìm TikTok", 30, 82, 0, 150, 750, 1100) if not row_ok then return false end local backup_ok = waitTapImage(TIKTOK_BACKUP_IMG, "Tìm Backup", 30, 82, 0, 150, 750, 1334) if not backup_ok then return false end local backup_data_ok = waitTapImage(TIKTOK_BACKUPDATA_IMG, "Xác nhận data", 30, 82, 0, 150, 750, 1334) if not backup_data_ok then return false end local backuping_appear = waitImageAppear(TIKTOK_BACKUPING_IMG, "Đợi popup backup", 30, 82, 0, 150, 750, 1334) if not backuping_appear then return false end local backuping_done = waitImageDisappear(TIKTOK_BACKUPING_IMG, "Backup", 1800, 82, 0, 150, 750, 1334) if not backuping_done then return false end return true end
function gotoHome() phase("Về Home") app.run("com.apple.springboard") waitPhase(800) end
function openTikTokStoragePage() phase("Mở Storage") app.quit("com.apple.Preferences") waitPhase(1500) app.open_url("prefs:root=General&path=STORAGE_MGMT/com.ss.iphone.ugc.Ame") waitPhase(12000) app.open_url("prefs:root=General&path=STORAGE_MGMT/com.ss.iphone.ugc.Ame") waitPhase(5000) end
function stage1DeleteTikTokOnce()
 closeTikTok() gotoHome() app.quit("com.apple.Preferences") app.quit("com.apple.AppStore") waitPhase(1500)
 local function hasBundleInstalled(bundle_id)
  local bundles = app.bundles()
  if type(bundles) ~= "table" then return nil end
  for _, bid in ipairs(bundles) do if bid == bundle_id then return true end end
  return false
 end
 local installed_tiktok = hasBundleInstalled(TIKTOK_BUNDLE)
 local installed_tiktok_lite = hasBundleInstalled(TIKTOK_LITE_BUNDLE)
 if installed_tiktok == false and installed_tiktok_lite == false then status("Không có TikTok") waitCountdown(60000, "Đợi AppStore") return true end
 phase("Gỡ TikTok")
 local ok_tiktok = true
 local ok_tiktok_lite = true
 if installed_tiktok ~= false then ok_tiktok = app.uninstall(TIKTOK_BUNDLE) waitPhase(1500) end
 if installed_tiktok_lite ~= false then phase("Gỡ TikTok Lite") ok_tiktok_lite = app.uninstall(TIKTOK_LITE_BUNDLE) waitPhase(1500) end
 local start_wait = os.time() local lastShown = -1 phase("Chờ gỡ TikTok")
 while os.time() - start_wait < 120 do
  local remain = 120 - (os.time() - start_wait)
  if remain ~= lastShown then phaseProgress(remain) lastShown = remain end
  local installed_now_tiktok = hasBundleInstalled(TIKTOK_BUNDLE)
  local installed_now_tiktok_lite = hasBundleInstalled(TIKTOK_LITE_BUNDLE)
  if installed_now_tiktok == false and installed_now_tiktok_lite == false then phase("Gỡ xong") waitCountdown(60000, "Đợi AppStore") return true end
  if installed_now_tiktok == nil or installed_now_tiktok_lite == nil then if not app.is_running(TIKTOK_BUNDLE) and not app.is_running(TIKTOK_LITE_BUNDLE) then phase("TikTok đã tắt") end end
  if os.time() - start_wait == 20 or os.time() - start_wait == 45 or os.time() - start_wait == 75 then
   phase("Gỡ lại TikTok")
   if installed_now_tiktok ~= false then app.uninstall(TIKTOK_BUNDLE) waitPhase(1000) end
   if installed_now_tiktok_lite ~= false then phase("Gỡ lại TikTok Lite") app.uninstall(TIKTOK_LITE_BUNDLE) waitPhase(1000) end
  end
  sleep(1000)
 end
 if ok_tiktok or ok_tiktok_lite then phase("Chưa xác nhận gỡ") else phase("Gỡ TikTok lỗi") end
 return false
end
function stage2DownloadTikTokOnce()
 phase("Mở AppStore") app.quit("com.apple.AppStore") waitPhase(1500)
 local tiktok_store_url = "https://apps.apple.com/jp/app/tiktok-global-video-community/id1235601864?l=en-US"
 local NEW_IMG = RES_DIR
 local CHECK_TAI_1 = NEW_IMG .. "/CheckTai1.png"
 local CHECK_TAI_2 = NEW_IMG .. "/CheckTai2.png"
 local CHECK_TAI_3 = NEW_IMG .. "/CheckTai3.png"
 local CANNOT_IMG = NEW_IMG .. "/canot.png"
 local CLOUD_IMG = NEW_IMG .. "/cloud.png"
 local OPEN_IMG = NEW_IMG .. "/open.png"
 local RETRY_IMG = NEW_IMG .. "/retry.png"
 local UNABLE_IMG = NEW_IMG .. "/unable.png"
 local UNABLE_OK_IMG = NEW_IMG .. "/unable_ok.png"
 local CLOUD_X1 = 250 local CLOUD_Y1 = 500 local CLOUD_X2 = 430 local CLOUD_Y2 = 700
 local CANNOT_X1 = 80 local CANNOT_Y1 = 380 local CANNOT_X2 = 670 local CANNOT_Y2 = 860
 local RETRY_X1 = 180 local RETRY_Y1 = 600 local RETRY_X2 = 560 local RETRY_Y2 = 900
 local function openStoreTikTok() phase("Mở AppStore") app.quit("com.apple.AppStore") waitPhase(1500) app.open_url(tiktok_store_url) waitPhase(6000) end
 local function hasAnyCheckTai() if findImage(CHECK_TAI_1, 82, 0, 0, 750, 1334) then return true end if findImage(CHECK_TAI_2, 82, 0, 0, 750, 1334) then return true end if findImage(CHECK_TAI_3, 82, 0, 0, 750, 1334) then return true end return false end
 local function hasCloud() local ok = findImage(CLOUD_IMG, 82, CLOUD_X1, CLOUD_Y1, CLOUD_X2, CLOUD_Y2) return ok == true end
 local function hasOpen() local ok = findImage(OPEN_IMG, 82, 0, 0, 750, 1334) return ok == true end
 local function hasCannot() local ok = findImage(CANNOT_IMG, 82, CANNOT_X1, CANNOT_Y1, CANNOT_X2, CANNOT_Y2) if ok then return true end return false end
 local function tapRetryOnce() local ok, x, y = findImage(RETRY_IMG, 82, RETRY_X1, RETRY_Y1, RETRY_X2, RETRY_Y2) if ok then phase("Bấm retry") touch.tap(x + 20, y + 20) waitPhase(1000) return true end return false end
 local function handleCannotAndRetry(window_sec)
  local start = os.time() local lastShown = -1 local retried = false phase("Chờ retry")
  while os.time() - start < window_sec do
   local remain = window_sec - (os.time() - start)
   if remain ~= lastShown then phaseProgress(remain) lastShown = remain end
   if hasAnyCheckTai() then return true end
   if hasCannot() then
    phase("Tuần tra canot")
    if not retried then if tapRetryOnce() then retried = true phase("Đã bấm retry, chờ") waitPhase(4000) end else end
   else
    if retried then end
    retried = false
   end
   sleep(1000)
  end
  phase("Retry timeout")
  return false
 end
 local function waitCannotRecovery()
  local retry_schedule = {120, 300, 900, 1800, 2700, 3600, 7200}
  local retry_labels = {"2p", "5p", "15p", "30p", "45p", "60p", "120p"}
  local last_mark = 0
  for i = 1, #retry_schedule do
   local step = retry_schedule[i] - last_mark
   phase("Retry mốc " .. retry_labels[i])
   if step > 0 then if handleCannotAndRetry(step) then return true end end
   phase("Mở lại AppStore") openStoreTikTok() if hasAnyCheckTai() then return true end
   last_mark = retry_schedule[i]
  end
  return false
 end
 local function tapCloudOnce() local ok, x, y = findImage(CLOUD_IMG, 82, CLOUD_X1, CLOUD_Y1, CLOUD_X2, CLOUD_Y2) if ok then phase("Bấm cloud") touch.tap(x + 20, y + 20) waitPhase(1000) return true end return false end
 openStoreTikTok()
 local start_stage2 = os.time() local lastShown = -1 local last_cloud_tap_at = 0 local cloud_tap_cooldown = 12 local download_started = false
 phase("Mở AppStore")
 while os.time() - start_stage2 < 10800 do
  local elapsed = os.time() - start_stage2 local remain = 10800 - elapsed
  if download_started and remain ~= lastShown then phaseProgress(remain) lastShown = remain end
  if hasOpen() then phase("Đã thấy OPEN") return true end
  if hasCannot() then phase("Không có kết nối") if waitCannotRecovery() then phase("Ra lại bước tải") else return false end else local ready_for_cloud = hasAnyCheckTai() if (not download_started) and ready_for_cloud then phase("Tìm cloud") if hasCloud() and (os.time() - last_cloud_tap_at >= cloud_tap_cooldown) then if tapCloudOnce() then last_cloud_tap_at = os.time() download_started = true phase("Chờ OPEN") waitPhase(8 * 1000) end end elseif download_started then phase("Chờ OPEN") end end
  local has_unable = findImage(UNABLE_IMG, 82, 0, 0, 750, 1334)
  if has_unable then phase("Unable") waitTapImage(UNABLE_OK_IMG, "Bấm unable ok", 3, 82, 0, 0, 750, 1334) waitPhase(2000) if hasCloud() and (os.time() - last_cloud_tap_at >= 2) then if tapCloudOnce() then last_cloud_tap_at = os.time() download_started = true phase("Chờ OPEN") waitPhase(8 * 1000) end end end
  if hasCloud() and download_started and (os.time() - last_cloud_tap_at >= cloud_tap_cooldown) then phase("Cloud xuất hiện lại") if tapCloudOnce() then last_cloud_tap_at = os.time() phase("Chờ OPEN") waitPhase(8 * 1000) end end
  sleep(1000)
 end
 return false
end
function stage3OpenTikTokOnce() closeTikTok() openTikTok() phase("Đợi sau mở TikTok") waitPhase(20000) local popup_ok = runTikTokPopupFlow(120) if not popup_ok then return false end if not popup_cleared then return false end waitPhase(1000) local event_ok = runEventFlowWithRestart() if not event_ok then closeTikTok() waitPhase(1500) return false end closeTikTok() waitPhase(1500) return true end
function tapBackupOk() touch.tap(380, 1284) waitPhase(3000) touch.tap(380, 1284) return true end
function backupTikTokInAppManagerNoStop() phase("Bắt đầu backup") closeTikTok() closeAppManager() openAppManager() local row_ok = waitTapImage(TIKTOK_ROW_IMG, "Tìm TikTok", 30, 82, 0, 150, 750, 1100) if not row_ok then return false end local backup_ok = waitTapImage(TIKTOK_BACKUP_IMG, "Tìm Backup", 30, 82, 0, 150, 750, 1334) if not backup_ok then return false end local backup_data_ok = waitTapImage(TIKTOK_BACKUPDATA_IMG, "Xác nhận data", 30, 82, 0, 150, 750, 1334) if not backup_data_ok then return false end local backuping_appear = waitImageAppear(TIKTOK_BACKUPING_IMG, "Đợi popup backup", 30, 82, 0, 150, 750, 1334) if not backuping_appear then return false end local backuping_done = waitImageDisappear(TIKTOK_BACKUPING_IMG, "Backup", 1800, 82, 0, 150, 750, 1334) if not backuping_done then return false end phase("Backup xong") return true end
function stage4BackupTikTokOnce() closeTikTok() closeAppManager() return backupTikTokInAppManagerNoStop() end
phase("Khởi động v" .. SCRIPT_VERSION) waitPhase(1500)
local current_stage = 1 clearStage3Watch()
while true do
 if shouldRestartFromStage3() then current_stage = 1 clearStage3Watch() closeTikTok() closeAppManager() app.quit("com.apple.Preferences") app.quit("com.apple.AppStore") waitPhase(1500) end
 if current_stage == 1 then clearStage3Watch() phase("Stage 1") if stage1DeleteTikTokOnce() then current_stage = 2 else closeTikTok() app.quit("com.apple.Preferences") app.quit("com.apple.AppStore") waitPhase(1500) end
 elseif current_stage == 2 then clearStage3Watch() phase("Stage 2") local stage2_result = stage2DownloadTikTokOnce() if stage2_result == true then current_stage = 3 beginStage3Watch() elseif stage2_result == "restart_stage1" then current_stage = 1 clearStage3Watch() closeTikTok() closeAppManager() app.quit("com.apple.Preferences") app.quit("com.apple.AppStore") waitPhase(1500) else closeTikTok() app.quit("com.apple.AppStore") waitPhase(1500) end
 elseif current_stage == 3 then if not stage3_started_at then beginStage3Watch() end phase("Stage 3") if stage3OpenTikTokOnce() then clearStage3Watch() current_stage = 4 else if shouldRestartFromStage3() then current_stage = 1 clearStage3Watch() closeTikTok() closeAppManager() app.quit("com.apple.Preferences") app.quit("com.apple.AppStore") else closeTikTok() end waitPhase(1500) end
 elseif current_stage == 4 then clearStage3Watch() phase("Stage 4") if stage4BackupTikTokOnce() then tapBackupOk() break else closeTikTok() closeAppManager() waitPhase(1500) end end
end
return
