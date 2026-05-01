Array.prototype.filter = function(a) {
    var b, c, d, e, g;
    try {
        for (b = this.length, c = new Array, d = 0; b > d; d++) e = this[d], a(e, d, this) && c.push(this[d]);
        return c
    } catch (f) {
        g = "Array.filter gặp lỗi.\n\n", g += "Mô tả lỗi:" + f.description + "\n\n", g += "Nhấn OK để tiếp tục.\n\n", alert(g)
    }
}, Array.prototype.removeAt = function(a) {
    if (isNaN(a) || a > this.length) return !1;
    for (var b = 0, c = 0; b < this.length; b++) this[b] != this[a] && (this[c++] = this[b]);
    this.length -= 1
}, Array.prototype.remove = function(a) {
    if (null != a) {
        for (var b = 0, c = 0; b < this.length; b++) this[b] != a && (this[c++] = this[b]);
        this.length -= 1
    }
}, Array.prototype.Contains = function(a) {
    if (null != a) {
        for (var b = 0; b < this.length; b++)
            if (this[b] == a) return !0;
        return !1
    }
}, Array.prototype.indexOf = function(a) {
    if (null != a) {
        for (var b = 0; b < this.length; b++)
            if (this[b] == a) return b;
        return -1
    }
}, Array.prototype.Clear = function() {
    this.length = 0
}, Array.prototype.removeVoidElement = function() {
    for (var a = 0; a < this.length; a++)("" == this[a] || null == this[a] || "null" == this[a]) && this.remove(this[a])
}, $(document).ready(function() {
    var a = "";
    a += '<div class="mdui-list" mdui-collapse="{accordion: true}" style="margin-bottom:76px"><ul class="mdui-list"><a href="./script_choose.html" class="mdui-list-item mdui-ripple"><i class="mdui-list-item-icon mdui-icon material-icons mdui-text-color-blue">&#xe873;</i><div class="mdui-list-item-content">Chọn script</div></a> <a href="./xxtouch_auth.html" class="mdui-list-item mdui-ripple"><i class="mdui-list-item-icon mdui-icon material-icons mdui-text-color-deep-orange">&#xe0da;</i><div class="mdui-list-item-content">Cấp phép</div></a> <a href="./xxtouch_service.html" class="mdui-list-item mdui-ripple"><i class="mdui-list-item-icon mdui-icon material-icons mdui-text-color-indigo">&#xe0de;</i><div class="mdui-list-item-content">Thiết bị & dịch vụ</div></a> <a href="./log.html" class="mdui-list-item mdui-ripple"><i class="mdui-list-item-icon mdui-icon material-icons mdui-text-color-brown">&#xe85d;</i><div class="mdui-list-item-content">Nhật ký thiết bị</div></a></ul><div class="mdui-collapse-item"><div class="mdui-collapse-item-header mdui-list-item mdui-ripple"><i class="mdui-list-item-icon mdui-icon material-icons mdui-text-color-green">&#xe8b8;</i><div class="mdui-list-item-content">Cài đặt</div><i class="mdui-collapse-item-arrow mdui-icon material-icons">&#xe313;</i></div><div class="mdui-collapse-item-body mdui-list"><a href="./action_conf.html" class="mdui-list-item mdui-ripple">Cài đặt phím</a> <a href="./startup_conf.html" class="mdui-list-item mdui-ripple">Cài đặt khởi động cùng máy</a> <a href="./user_conf.html" class="mdui-list-item mdui-ripple">Tùy chọn người dùng</a></div></div><ul class="mdui-list"><a href="./applist.html" class="mdui-list-item mdui-ripple"><i class="mdui-list-item-icon mdui-icon material-icons mdui-text-color-red">&#xe5c3;</i><div class="mdui-list-item-content">Danh sách ứng dụng</div></a> <a href="./picker.html" class="mdui-list-item mdui-ripple"><i class="mdui-list-item-icon mdui-icon material-icons mdui-text-color-cyan">&#xe410;</i><div class="mdui-list-item-content">Trình bắt màu</div></a> <a href="./cc.html" class="mdui-list-item mdui-ripple"><i class="mdui-list-item-icon mdui-icon material-icons mdui-text-color-cyan">&#xe1b1;</i><div class="mdui-list-item-content">Điều khiển tập trung qua LAN</div></a> <a href="./screen.html" class="mdui-list-item mdui-ripple"><i class="mdui-list-item-icon mdui-icon material-icons mdui-text-color-brown">&#xe1bc;</i><div class="mdui-list-item-content">Màn hình thời gian thực</div></a> <a href="./upgrade.html" class="mdui-list-item mdui-ripple"><i class="mdui-list-item-icon mdui-icon material-icons mdui-text-color-purple">&#xe62a;</i><div class="mdui-list-item-content">Nâng cấp phần mềm</div></a> <a href="./encript.html" class="mdui-list-item mdui-ripple"><i class="mdui-list-item-icon mdui-icon material-icons mdui-text-color-teal">&#xe63f;</i><div class="mdui-list-item-content">Mã hóa script</div></a></ul><div class="mdui-collapse-item"><div class="mdui-collapse-item-header mdui-list-item mdui-ripple"><i class="mdui-list-item-icon mdui-icon material-icons mdui-text-color-deep-purple">&#xe06f;</i><div class="mdui-list-item-content">Tài liệu</div><i class="mdui-collapse-item-arrow mdui-icon material-icons">&#xe313;</i></div><div class="mdui-collapse-item-body mdui-list"><a href="https://www.xxtou.ch/docs/dev" target="_blank" class="mdui-list-item mdui-ripple">Tài liệu phát triển</a> <a href="https://www.xxtou.ch/docs/openapi" target="_blank" class="mdui-list-item mdui-ripple">Tài liệu OpenAPI</a> <a href="https://www.xxtou.ch/docs/manual" target="_blank" class="mdui-list-item mdui-ripple">Hướng dẫn sử dụng</a> <a href="https://www.xxtou.ch/docs/updates" target="_blank" class="mdui-list-item mdui-ripple">Nhật ký cập nhật</a> <a href="./about.html" class="mdui-list-item mdui-ripple">Giới thiệu</a></div></div></div>\n', $("#main-drawer").append(a), (window.ActiveXObject || "ActiveXObject" in window) && (location.href = "http://www.google.cn/chrome/browser/desktop/index.html", mdui.snackbar({
        message: "Để bảo đảm hiển thị đầy đủ và trải nghiệm tốt nhất, vui lòng dùng trình duyệt khác IE để truy cập.<br >Nếu bạn dùng trình duyệt nội địa, hãy chọn <b>chế độ nhanh</b> để duyệt web.",
        position: "top",
        timeout: 3e4,
        buttonText: "Tải Chrome",
        closeOnOutsideClick: !0,
        onButtonClick: function() {
            location.href = "http://www.google.cn/chrome/browser/desktop/index.html"
        }
    }))
});
