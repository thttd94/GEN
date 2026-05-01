# Release & Rollback Guide

## Versioning rule

Use release tags in this format:

- `vYYYY.MM.DD-01`
- `vYYYY.MM.DD-02`

Examples:

- `v2026.04.18-01`
- `v2026.04.18-02`

Each release should include:

1. a Git commit
2. a Git tag
3. optional `VERSION.txt` content on deployed server

## Windows release flow

```powershell
& "C:\Program Files\Git\cmd\git.exe" -C E:\OpenClaw\Genrouter_jobs\proxy-manager-v1 add .
& "C:\Program Files\Git\cmd\git.exe" -C E:\OpenClaw\Genrouter_jobs\proxy-manager-v1 commit -m "v2026.04.18-02 describe changes"
& "C:\Program Files\Git\cmd\git.exe" -C E:\OpenClaw\Genrouter_jobs\proxy-manager-v1 tag v2026.04.18-02
& "C:\Program Files\Git\cmd\git.exe" -C E:\OpenClaw\Genrouter_jobs\proxy-manager-v1 push origin main
& "C:\Program Files\Git\cmd\git.exe" -C E:\OpenClaw\Genrouter_jobs\proxy-manager-v1 push origin v2026.04.18-02
```

## Linux update from latest main

```bash
cd /root || exit 1
rm -f GEN-main.tar.gz
[ -d GEN ] && mv GEN "GEN_bak_$(date +%Y%m%d_%H%M%S)"
wget --no-check-certificate -O GEN-main.tar.gz "https://codeload.github.com/thttd94/GEN/tar.gz/refs/heads/main" || exit 1
tar -xzf GEN-main.tar.gz || exit 1
rm -rf GEN
mv GEN-main GEN || exit 1
cd GEN || exit 1
chmod +x install.sh start.sh update.sh rollback.sh
sh install.sh
```

## Linux deploy from a specific tag

```bash
cd /root || exit 1
VER="v2026.04.18-02"
rm -f "GEN-${VER}.tar.gz"
[ -d GEN ] && mv GEN "GEN_bak_$(date +%Y%m%d_%H%M%S)"
wget --no-check-certificate -O "GEN-${VER}.tar.gz" "https://codeload.github.com/thttd94/GEN/tar.gz/refs/tags/${VER}" || exit 1
tar -xzf "GEN-${VER}.tar.gz" || exit 1
rm -rf GEN
mv "GEN-${VER#v}" GEN 2>/dev/null || mv "GEN-${VER}" GEN || exit 1
cd GEN || exit 1
chmod +x install.sh start.sh update.sh rollback.sh
sh install.sh
```

## Rollback strategy

### Option 1, rollback from backup folder

```bash
cd /root || exit 1
rm -rf GEN
mv GEN_bak_YYYYMMDD_HHMMSS GEN
cd GEN || exit 1
chmod +x install.sh start.sh update.sh rollback.sh
sh install.sh
```

### Option 2, rollback from Git tag

Deploy an older tag using `update.sh <tag>`.

Example:

```bash
cd /root/GEN || exit 1
./update.sh v2026.04.18-01
```
