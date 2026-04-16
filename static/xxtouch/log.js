$(document).ready(function() {
    $("#main-drawer a[href='./log.html']").addClass("mdui-list-item-active");
    $("#debugTextArea").height(($(window).height() - 270));
    $(window).resize(function() {
        $("#debugTextArea").height(($(window).height() - 270))
    });
    var debugTextArea = document.getElementById("debugTextArea");
    var statusLabel = $("#statusLabel");
    var pauseBtn = $("#pauseBtn");

    function setWSStatus(status) {
        statusLabel.text(status)
    }

    function debug(message) {
        debugTextArea.value += message + "\n";
        debugTextArea.scrollTop = debugTextArea.scrollHeight
    }
    var servicer_ip = document.domain;
    var wsUri = "ws://" + servicer_ip + ":46957";
    var websocket = null;
    var paused = false;
    var lastErrorTime = 0;
    $("#clearLogs").click(function() {
        debugTextArea.value = ""
    });
    $("#pauseBtn").click(function() {
        paused = !paused;
        if (paused) {
            if (websocket && websocket.readyState == 1) {
                websocket.close()
            }
            pauseBtn.removeClass("mdui-xxtouch-button");
            pauseBtn.addClass("mdui-xxtouch-color");
            pauseBtn.html("<i class='mdui-icon material-icons'>&#xe037;</i>Tiếp tục nhận")
        } else {
            initWebSocket();
            pauseBtn.removeClass("mdui-xxtouch-color");
            pauseBtn.addClass("mdui-xxtouch-button");
            pauseBtn.html("<i class='mdui-icon material-icons'>&#xe034;</i>Tạm dừng nhận")
        }
    });

    function initWebSocket() {
        try {
            if (typeof MozWebSocket == "function") {
                WebSocket = MozWebSocket
            }
            if (websocket && websocket.readyState == 1) {
                websocket.close()
            }
            websocket = new WebSocket(wsUri);
            websocket.onopen = function(evt) {
                setWSStatus("Đã kết nối dịch vụ log")
            };
            websocket.onclose = function(evt) {
                if (paused) {
                    setWSStatus("Tạm dừng lấy log")
                } else {
                    setWSStatus("Đang chờ thiết bị khởi tạo dịch vụ log……")
                }
            };
            websocket.onmessage = function(evt) {
                debug(evt.data)
            };
            websocket.onerror = function(evt) {
                lastErrorTime = new Date().getTime()
            }
        } catch (exception) {
            lastErrorTime = new Date().getTime()
        }
    }

    function stopWebSocket() {
        if (websocket) {
            websocket.close()
        }
    }

    function checkSocket() {
        if (websocket != null) {
            var stateStr;
            switch (websocket.readyState) {
                case 0:
                    stateStr = "CONNECTING";
                    break;
                case 1:
                    stateStr = "OPEN";
                    break;
                case 2:
                    stateStr = "CLOSING";
                    break;
                case 3:
                    stateStr = "CLOSED";
                    break;
                default:
                    stateStr = "UNKNOW";
                    break
            }
            debug("WebSocket state = " + websocket.readyState + " ( " + stateStr + " )")
        } else {
            debug("WebSocket is null")
        }
    }

    function while_check() {
        if (!paused) {
            if (websocket == null || websocket.readyState > 1) {
                setWSStatus("Đang chờ thiết bị khởi tạo dịch vụ log……");
                initWebSocket()
            } else {
                setWSStatus("Đã kết nối dịch vụ log")
            }
        } else {
            setWSStatus("Tạm dừng lấy log")
        }
        if (lastErrorTime != 0) {
            lastErrorTime = 0;
            setTimeout(while_check, 10000)
        } else {
            setTimeout(while_check, 1000)
        }
    }
    $(document).ready(function() {
        while_check()
    })
});