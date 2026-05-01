# GEN

Bản này dùng để update Genrouter từ GitHub và đã bỏ FRPC/reverse tunnel khỏi router.

## Cài trên router

```sh
cd /root
rm -rf GEN GEN-main GEN-main.tar.gz
wget --no-check-certificate -O GEN-main.tar.gz "https://codeload.github.com/thttd94/GEN/tar.gz/refs/heads/main"
tar -xzf GEN-main.tar.gz
mv GEN-main GEN
cd GEN
chmod +x install.sh start.sh update.sh rollback.sh
sh install.sh
```

Script sẽ hỏi:

```sh
Enter install password:
```

Nhập đúng mật khẩu để cài tiếp.

## Kết quả của bản này

- giữ `proxy-manager-v1` chạy local như cũ
- dừng và gỡ `genrouter-frpc`
- dừng và gỡ `genrouter-reverse-tunnel`
- bỏ boot loop `frpc`
- xóa file/runtime FRPC trong `/opt/proxy-manager-v1`
- reset `/etc/rc.local` về trạng thái không tự kéo FRPC nữa
