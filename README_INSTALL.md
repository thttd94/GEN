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

## Mat khau cai dat (Ver 2.41 tro di)

Tu Ver 2.41, `install.sh` **khong con luu mat khau dang chu ro** trong repo (repo nay PUBLIC,
mat khau cu da nam trong git history nen phai coi nhu da lo vinh vien - va no bi chan cung
trong code, khong dung lai duoc).

Co 3 cach chay:

```sh
# 1. Nhap tay (mac dinh) - script se hoi "Enter install password:"
sh install.sh

# 2. Truyen qua bien moi truong (dung cho script tu dong)
INSTALL_PASSWORD='matkhau' sh install.sh

# 3. Bo qua kiem tra (khi da o trong mang tin cay)
INSTALL_SKIP_PASSWORD=1 sh install.sh
```

**Doi mat khau cho rieng router cua ban** (khong can sua file install.sh):

```sh
# tinh hash cua mat khau moi
NEWPASS='matkhaumoi'
HASH="$(printf '%s' "genrouter-install-v241${NEWPASS}" | sha256sum | awk '{print $1}')"
# chay install voi hash do
INSTALL_PASSWORD_SHA256="$HASH" INSTALL_PASSWORD="$NEWPASS" sh install.sh
```

Muon dat salt rieng thi truyen them `INSTALL_PASSWORD_SALT='...'` (phai dung cung salt do khi
tinh hash).

## Kết quả của bản này

- giữ `proxy-manager-v1` chạy local như cũ
- dừng và gỡ `genrouter-frpc`
- dừng và gỡ `genrouter-reverse-tunnel`
- bỏ boot loop `frpc`
- xóa file/runtime FRPC trong `/opt/proxy-manager-v1`
- reset `/etc/rc.local` về trạng thái không tự kéo FRPC nữa
