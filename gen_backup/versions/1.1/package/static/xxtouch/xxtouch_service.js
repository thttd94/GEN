$(document).ready(function() {
    function c() {
        $.post("/deviceinfo", "", function() {
            a.close()
        }, "json").error(function() {
            setTimeout(c, 3e3)
        })
    }
    var a, b, d;
    $("#main-drawer a[href='./xxtouch_service.html']").addClass("mdui-list-item-active"), a = new mdui.Dialog($('<div class="mdui-dialog" id="dialog"><div class="mdui-dialog-content"><div class="mdui-progress"><div class="mdui-progress-indeterminate"></div></div><br /><div class="mdui-text-center">Đang xử lý...</div></div></div>')), b = function(c) {
        c ? ($("#close-service").html("Tắt điều khiển từ xa"), $("#close-service").off("click"), $("#close-service").on("click", function() {
            a.open(), $.post("/close_remote_access", "", function(c) {
                mdui.snackbar({
                    message: c.message
                }), a.close(), b(!1)
            }, "json").error(function() {
                a.close(), mdui.snackbar({
                    message: "Không thể giao tiếp với thiết bị"
                })
            })
        })) : ($("#close-service").html("Bật điều khiển từ xa"), $("#close-service").off("click"), $("#close-service").on("click", function() {
            a.open(), $.post("/open_remote_access", "", function(c) {
                mdui.snackbar({
                    message: c.message
                }), a.close(), b(!0)
            }, "json").error(function() {
                a.close(), mdui.snackbar({
                    message: "Không thể giao tiếp với thiết bị"
                })
            })
        }))
    }, $.post("/is_remote_access_opened", "", function(a) {
        0 == a.code && ("local" == document.domain || "127.0.0.1" == document.domain ? b(a.data.opened) : a.data.opened && $("#close-service").on("click", function() {
            d("Tắt dịch vụ điều khiển từ xa", "Muốn kết nối lại lần sau cần bật lại trên thiết bị. Tất cả trang hiện tại sẽ mất hiệu lực.", "close_remote_access", "")
        }))
    }, "json").error(function() {
        setTimeout(c, 3e3)
    }), d = function(b, c, d, e) {
        var f = function() {
            a.open(), $.post("/" + d, e, function(b) {
                mdui.snackbar({
                    message: b.message
                }), a.close()
            }, "json").error(function() {
                a.close(), mdui.snackbar({
                    message: "Không thể giao tiếp với thiết bị"
                })
            })
        };
        "" != b ? mdui.dialog({
            title: b,
            content: c,
            buttons: [{
                text: "Hủy"
            }, {
                text: "Xác nhận",
                onClick: function() {
                    setTimeout(f, 300)
                }
            }]
        }) : f()
    }, $("#uicache").click(function() {
        d("Xóa cache UI", "Xóa toàn bộ thông tin cache hiện tại trên SpringBoard.", "uicache", "")
    }), $("#clear-gps").click(function() {
        d("Xóa thông tin GPS giả lập", "Xóa toàn bộ thông tin giả lập vị trí của các app trước đó.", "clear_gps", "")
    }), $("#clear-all").click(function() {
        mdui.prompt("Xóa可能会造成数据的丢失，此操作是不可逆转的<br>请输入“CLEAR”以继续清理。", "Xóa sạch thiết bị", function(a) {
            "CLEAR" == a.toUpperCase() && d("", "", "clear_all", "")
        }, function() {})
    }), $("#restart-service").click(function() {
        mdui.dialog({
            title: "Khởi động lại dịch vụ",
            content: "Khởi động lại dịch vụ XXTouch",
            buttons: [{
                text: "Hủy"
            }, {
                text: "Xác nhận",
                onClick: function() {
                    a.open(), $.post("/restart", "", function() {
                        setTimeout(c, 5e3)
                    }, "json").error(function() {
                        a.close(), mdui.snackbar({
                            message: "Không thể giao tiếp với thiết bị"
                        })
                    })
                }
            }]
        })
    }), $("#halt-device").click(function() {
        d("", "", "halt", "")
    }), $("#restart-device").click(function() {
        d("", "", "reboot2", "")
    }), $("#respring-device").click(function() {
        d("", "", "respring", "")
    })
});