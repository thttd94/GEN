$(document).ready(function() {
    $("#main-drawer a[href='./action_conf.html']").addClass(
            "mdui-list-item-active"
        ),
        $("#main-drawer div[class='mdui-collapse-item']:eq(0)").addClass(
            "mdui-collapse-item-open"
        );
    var a = function() {
        var a = function(a, b) {
                switch (b) {
                    case "0":
                        a.html("Bật/tắt script (có popup)");
                        break;
                    case "1":
                        a.html("Bật/tắt script");
                        break;
                    case "2":
                        a.html("Không làm gì");
                }
                a.on("click", function() {
                    var b = this.id;
                    mdui.dialog({
                        title: "Thiết lập cách kích hoạt",
                        content: "Bật/tắt script (có popup): 会弹出一个选择框,进行选择操作方法.<br>Bật/tắt script: 会直接启动Dừng脚本.<br>Không làm gì: sẽ không có phản hồi.",
                        stackedButtons: !0,
                        buttons: [{
                                text: "Bật/tắt script (có popup)",
                                onClick: function() {
                                    $.post("set_" + b + "_action", "0", function() {
                                        a.html("Bật/tắt script (có popup)");
                                    }).error(function() {
                                        mdui.snackbar({
                                            message: "Không thể giao tiếp với thiết bị"
                                        });
                                    });
                                },
                            },
                            {
                                text: "Bật/tắt script",
                                onClick: function() {
                                    $.post("set_" + b + "_action", "1", function() {
                                        a.html("Bật/tắt script");
                                    }).error(function() {
                                        mdui.snackbar({
                                            message: "Không thể giao tiếp với thiết bị"
                                        });
                                    });
                                },
                            },
                            {
                                text: "Không làm gì",
                                onClick: function() {
                                    $.post("set_" + b + "_action", "2", function() {
                                        a.html("Không làm gì");
                                    }).error(function() {
                                        mdui.snackbar({
                                            message: "Không thể giao tiếp với thiết bị"
                                        });
                                    });
                                },
                            },
                        ],
                    });
                });
            },
            b = function(a, b) {
                switch (b) {
                    case !0:
                        a.html("Đã bật");
                        break;
                    case !1:
                        a.html("Đã tắt");
                }
                a.on("click", function() {
                    var b = this.id,
                        c = "";
                    (c =
                        "record_volume_up" == b ?
                        "Sự kiện “Âm lượng +” cũng sẽ được ghi lại." :
                        "Sự kiện “Âm lượng -” cũng sẽ được ghi lại."),
                    mdui.dialog({
                        title: "Thiết lập nút ghi",
                        content: c,
                        stackedButtons: !0,
                        buttons: [{
                                text: "Bật",
                                onClick: function() {
                                    $.post("set_" + b + "_on", "", function() {
                                        a.html("已Bật");
                                    }).error(function() {
                                        mdui.snackbar({
                                            message: "Không thể giao tiếp với thiết bị"
                                        });
                                    });
                                },
                            },
                            {
                                text: "Tắt",
                                onClick: function() {
                                    $.post("set_" + b + "_off", "", function() {
                                        a.html("Đã tắt");
                                    }).error(function() {
                                        mdui.snackbar({
                                            message: "Không thể giao tiếp với thiết bị"
                                        });
                                    });
                                },
                            },
                        ],
                    });
                });
            };
        $.post(
            "/get_record_conf",
            "",
            function(c) {
                0 == c.code ?
                    (b($("#record_volume_up"), c.data.record_volume_up),
                        b($("#record_volume_down"), c.data.record_volume_down),
                        $.post(
                            "/get_volume_action_conf",
                            "",
                            function(b) {
                                0 == b.code ?
                                    (a($("#hold_volume_up"), b.data.hold_volume_up),
                                        a($("#hold_volume_down"), b.data.hold_volume_down),
                                        a($("#click_volume_up"), b.data.click_volume_up),
                                        a($("#click_volume_down"), b.data.click_volume_down)) :
                                    mdui.snackbar({
                                        message: b.message
                                    });
                            },
                            "json"
                        ).error(function() {
                            mdui.snackbar({
                                message: "Không thể giao tiếp với thiết bị"
                            });
                        })) :
                    mdui.snackbar({
                        message: c.message
                    });
            },
            "json"
        ).error(function() {
            mdui.snackbar({
                message: "Không thể giao tiếp với thiết bị"
            });
        });
    };
    a();
});