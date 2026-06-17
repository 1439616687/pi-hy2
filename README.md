# 树莓派 mihomo 全局代理配置指南

> **适用环境**：Raspberry Pi 5 / Raspberry Pi OS（64 位，Debian 系）/ root 权限
> **目标**：整机所有流量透明走 hy2 节点（TUN 全局）。配好之后 Docker、Claude Code、apt、curl 等所有程序自动走代理，**不用逐个配置**。
> **为什么用 mihomo 而不是裸 hysteria**：mihomo 用 **fake-ip + DNS 劫持**，DNS 在本地就解析掉，不依赖节点的 UDP 转发。裸 hysteria 的 TUN 把 DNS 当 UDP 包往隧道里转，一旦节点 UDP 转发不稳就全盘卡死（DNS 超时）。fake-ip 正是绕开这个死穴的关键，也是 Windows 客户端一直好用的原因。

---

## 0. 节点信息（换节点时只改这一处）

| 字段 | 值 |
|------|-----|
| server | `your-node.example.com` |
| port | `443` |
| password | `REDACTED` |
| sni | `your-node.example.com` |
| 混淆 obfs | 无 |

> 若密码来自 `hy2://` 分享链接，链接里的 `%2F` 要还原成 `/` 再填。
> 这些值对应下面配置文件里 `proxies:` 那一段，换节点时改那几行即可。

---

## 1. 准备 TUN 设备

```bash
modprobe tun
echo tun > /etc/modules-load.d/tun.conf
ls -l /dev/net/tun   # 能列出 /dev/net/tun 就 OK
```

---

## 2. 安装 mihomo（ARM64）

> ⚠️ 重装后此时还没有代理，这一步**直连 GitHub，可能很慢（几分钟），耐心等**。

```bash
URL=$(curl -fsSL https://api.github.com/repos/MetaCubeX/mihomo/releases/latest \
  | grep browser_download_url \
  | grep 'mihomo-linux-arm64-v' \
  | grep '\.gz"' \
  | grep -vE 'compatible|go12' \
  | head -1 | cut -d'"' -f4)
echo "下载: $URL"
curl -fL --http1.1 --retry 5 --retry-delay 2 -o /tmp/mihomo.gz "$URL"
gunzip -f /tmp/mihomo.gz && chmod +x /tmp/mihomo && mv /tmp/mihomo /usr/local/bin/mihomo
mihomo -v   # 打印版本号即安装成功
```

**下载失败或太慢的两个退路：**
1. 在手机/电脑上打开 mihomo 的 GitHub releases 页，下载 `mihomo-linux-arm64-vX.X.X.gz`，用 U 盘或 `scp` 拷到树莓派，`gunzip` 后放到 `/usr/local/bin/mihomo`。
2. **最省事**：把装好的 `/usr/local/bin/mihomo` 二进制 + 第 3 步的配置文件，提前备份到树莓派**之外**（电脑/网盘）。重装后直接拷回去，跳过下载和写配置。

---

## 3. 写配置文件

```bash
mkdir -p /etc/mihomo
cat > /etc/mihomo/config.yaml << 'EOF'
mixed-port: 7890
allow-lan: false
mode: rule
log-level: warning
ipv6: false

dns:
  enable: true
  listen: 0.0.0.0:1053
  enhanced-mode: fake-ip
  fake-ip-range: 198.18.0.1/16
  nameserver:
    - https://1.1.1.1/dns-query
    - https://8.8.8.8/dns-query
  proxy-server-nameserver:
    - 223.5.5.5
    - 119.29.29.29

tun:
  enable: true
  stack: system
  dns-hijack:
    - any:53
  auto-route: true
  auto-redirect: true
  auto-detect-interface: true

proxies:
  - name: hy2
    type: hysteria2
    server: your-node.example.com
    port: 443
    password: "REDACTED"
    sni: your-node.example.com
    skip-cert-verify: false
    alpn:
      - h3
    up: 20 Mbps
    down: 100 Mbps

rules:
  - IP-CIDR,192.168.0.0/16,DIRECT,no-resolve
  - IP-CIDR,10.0.0.0/8,DIRECT,no-resolve
  - IP-CIDR,172.16.0.0/12,DIRECT,no-resolve
  - MATCH,hy2
EOF
```

各部分作用：
- `dns` + `fake-ip`：本地解析 DNS，绕开节点 UDP 转发的坑。
- `proxy-server-nameserver`（国内 DNS）：直连解析节点域名 `your-node.example.com`，避免“要连节点才能解析、解析又得先连节点”的死锁。
- `dns-hijack: any:53`：拦下系统所有 DNS 查询交给 mihomo。
- 三条 `IP-CIDR ... DIRECT`：局域网直连，**保证你 SSH 还能连上树莓派**。
- `MATCH,hy2`：其余所有流量走节点。

写完先测语法：

```bash
mihomo -d /etc/mihomo -t   # 出现 "test is successful" 即可
```

---

## 4. 设为系统服务并开机自启

```bash
cat > /etc/systemd/system/mihomo.service << 'EOF'
[Unit]
Description=mihomo
After=network.target

[Service]
ExecStart=/usr/local/bin/mihomo -d /etc/mihomo
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable --now mihomo
```

---

## 5. 验证

```bash
sleep 5
journalctl -u mihomo -n 25 --no-pager
curl -m 20 https://api.ipify.org; echo
```

- 日志里有 `Initial configuration complete`、`[TUN] default interface ... => wlan0`（或 eth0）即正常。
- **curl 返回节点出口 IP（某地区）就说明整机全局生效了。**

到这一步，Docker、Claude Code、apt 等全部自动走节点，无需再配。

---

## 6.（可选）部署 Portainer

> 前提：已装好 Docker。代理生效后，Docker 拉镜像直接走节点。

```bash
docker rm -f portainer 2>/dev/null
docker run -d -p 9443:9443 --name portainer --restart=always \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v portainer_data:/data \
  portainer/portainer-ce:latest
```

浏览器打开 `https://<树莓派IP>:9443`，证书警告点继续，设管理员密码即可。

---

## 7. 调整与排错

| 现象 | 处理 |
|------|------|
| 速度不理想 | 把配置里 `up` / `down` 改成接近你**实际宽带**的值（如 200M 宽带写 `down: 200 Mbps`）。填太高反而会让连接不稳，改完 `systemctl restart mihomo`。 |
| 日志报证书错误 | 把 `skip-cert-verify` 改成 `true`，重启 mihomo。 |
| TUN 起不来 / 报 operation not supported | 把 `stack: system` 改成 `stack: gvisor`，重启。 |
| `7890: address already in use` | 无害。本地混合代理端口被占，不影响 TUN 全局。`ss -ltnp | grep 7890` 可查谁占用。 |
| SSH 连不上树莓派 | 不会发生——私有网段已设 `DIRECT`。若真有问题，确认那三条 `IP-CIDR ... DIRECT` 还在。 |
| 换了节点 | 只改 `proxies:` 段的 server/port/password/sni，重启 mihomo。 |

常用命令：

```bash
systemctl restart mihomo          # 改完配置后重启
systemctl status mihomo           # 看运行状态
journalctl -u mihomo -f           # 实时看日志
mihomo -d /etc/mihomo -t          # 改配置后先测语法
```

---

## 8. 停用 / 卸载

```bash
systemctl disable --now mihomo                       # 停掉并取消自启（隧道随即关闭）
rm -f /etc/systemd/system/mihomo.service
rm -rf /etc/mihomo
rm -f /usr/local/bin/mihomo
systemctl daemon-reload
```

---

## 备份清单（重装前存好这两样，就能秒级恢复）

1. `/usr/local/bin/mihomo`（二进制）
2. `/etc/mihomo/config.yaml`（配置）

重装系统后：装好 TUN 设备（第 1 步）→ 把这两个文件拷回原位 → 建服务并启动（第 4 步）→ 验证（第 5 步）。跳过最慢的下载环节。
