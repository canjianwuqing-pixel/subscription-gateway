# Subscription Gateway

独立的订阅专用清洗网关。只接受 `/api/v1/{单个路径段}/subscribe`，其它 Gateway 路径返回 444；不代理登录、套餐等业务 API，也不连接 V2Board 数据库。

## 状态与安装

代码已包含正式安装、证书、Admin、规则发布和分析实现；当前 Windows 开发机没有 Docker，**Linux 全新 VPS 安装和真实 ACME 尚未验证**。首次使用应先在隔离的 Debian/Ubuntu 测试 VPS 验证，不要直接切换生产流量。

将项目上传到 Linux 后，以 root 在项目根目录执行：

若上传工具未保留可执行位，先运行 `chmod 0755 setup.sh update.sh`。

```bash
./setup.sh
./setup.sh --check
```

首次安装会检查 Debian/Ubuntu、64 位、磁盘、Docker/Compose，并仅在确认后安装缺失的 Docker。交互输入入口域名、Admin 端口、管理员用户名和证书方式（HTTP-01、Cloudflare DNS-01、已有证书）。Admin 路径、两把 Token 密钥和初始密码独立随机生成；密码仅在安装成功时显示一次，不写入 `.env`。部署配置在 `sgw/.env`（0600），运行文件在 `sgw/runtime/`，两者均不纳入 Git。

Admin 地址为 `https://<GATEWAY_DOMAIN>:<ADMIN_PORT>/<ADMIN_SECRET_PATH>`。首次安装不询问上游，Gateway 保持 Fail-Closed；登录后在“设置”中填写上游 HTTPS/HTTP Origin，规则通过候选文件、`nginx -t` 和安全 reload 发布。入口域名只能通过安装命令更换。

## 运维命令

```bash
./setup.sh --check
./setup.sh --reset-admin-password
./setup.sh --set-admin-secret-path
./setup.sh --set-gateway-domain
./setup.sh --configure-certificate
./setup.sh --renew-certificate
./setup.sh --uninstall
./setup.sh --purge
./update.sh
./update.sh --pull
```

重复执行 `./setup.sh` 不重置现有密码、密钥、证书、规则或数据库。`--uninstall` 只停删项目容器并保留数据；`--purge` 需输入当前域名及 `PURGE`，永久删除本项目运行数据和 `.env`。`update.sh` 使用 SQLite `VACUUM INTO` 备份、保留旧镜像标识并在失败时尝试回滚；`--pull` 要求 Git 工作区干净且存在远端。

自动证书通过 acme.sh 的 root-only 数据保存续期凭据，续期结果先写 staging，再验证并切换 active；手工证书不自动续期。Cloudflare DNS API Token 不进入本项目 `.env`、SQLite、页面或日志。

## 边界与验证

- Gateway 只处理订阅，Token/IP/UA 黑白名单与 Rate Limit 使用确定性优先级；风险标签不会自动封禁。
- Admin 或 SQLite 故障时，Gateway 继续使用最近一次已应用的本地规则。分析 worker 只读事件日志，失败不能进入订阅代理链路。
- 普通 access log 不含 Query；受限的 `token-events.log` 只供本机 worker 导入，SQLite `access_logs` 不保存明文 Token。
- `TEMP_BLOCKED` 带 UTC 到期时间，本地 watcher 最多约 30 秒后尝试移除已到期规则。

开发机测试：

```bash
php tests/run.php
bash tests/watch_fake.sh
bash tests/ops_fake.sh
```

fake watcher 和 fake 运维测试不等同于 Docker/Linux 真实集成、HTTP-01/DNS-01 签发或真实续期。上线前必须在隔离 VPS 完成这些验证，并确认重复 Token Query、TLS、规则回滚、worker 轮转和健康检查在目标发行版上的行为。
