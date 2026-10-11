# Subscription Gateway

独立的订阅专用清洗网关。只接受 `/api/v1/{单个路径段}/subscribe`，其它 Gateway 路径返回 444；不代理登录、套餐等业务 API，也不连接 V2Board 数据库。

## 状态与安装

### 一实例多入口域名（Schema v7）

首次安装仍只配置主 `GATEWAY_DOMAIN`，主证书继续由宿主机管理 `/runtime/ssl/active`；HTTP-01、Cloudflare DNS-01、existing 模式及原证书命令保持。首次 DNS-CF 安装在 SQLite 就绪后通过 stdin 加密初始化“默认 Cloudflare”凭据；中断恢复时没有原 Token 仅提示稍后在后台添加。

后台“入口域名”可直接填写备用 FQDN、Cloudflare API Token、32 位 Zone ID，或选择已有凭据。后端验证 DNS label 边界和 Zone，最多 100 个备用入口；不修改 A/AAAA/proxied。每个备用域名独立签发 DNS-01 证书，位于 `sgw/runtime/domain-certs/<id>/releases/<release>`，`active` 原子指向版本。Admin 对主证书仍为只读，对备用证书可写；Gateway 对两者均只读。不同账号、不同 Zone 可同时使用。

CF Token 使用 `TOKEN_ENCRYPTION_KEY`、XChaCha20-Poly1305、独立 AAD `subscription-gateway:cloudflare-token:v1` 加密。GET API 只返回已配置/末四位；编辑留空保留旧 Token；被域名引用的凭据不能删除。官方 acme.sh 3.1.1 在镜像构建时校验固定 SHA-256，受限 PHP curl DNS 驱动只操作 ACME TXT，不把 Authorization 送进 shell argv。临时 ACME 配置销毁，仅白名单 CA 账户密钥/注册信息持久化，续签不重复注册账户。

独立 certificate worker 处理 PENDING/RUNNING/RETRY 作业。证书必须 PEM/key 匹配、SAN 覆盖、至少剩余一天，才可发布。`domain-request.json`/`domain-candidate.conf`/`domain-result.json` 独立于规则发布通道，watcher 验证 hash、`nginx -t`、原子替换 `domains.conf`、reload/失败回滚。发布 ACK 后才置 ACTIVE；超时保留 RUNNING 等 ACK，重启可恢复。每天检查，剩余 <=30 天续签；失败从 5 分钟指数退避至最多一天，手动重试立即执行。续签失败恢复旧 active，删除失败恢复原状态；主域名禁止后台删除。

所有入口共用同一份 Gateway location、SQLite、Token hash/分组/assignment、映射与安全规则。备用入口只开放订阅，不开放 Admin；Admin 明确只接受主域名 Host（可带配置的 Admin 端口）。Gateway 重启恢复持久化配置；坏配置优先回退备份，必要时只保留主入口。`setup.sh --check` 检查 PRIMARY 一致、ACTIVE alias 证书/权限、配置及 worker；update 暂停证书任务并备份 SQLite、环境、规则、域名配置和 active 指针，回滚保留旧镜像/证书。

CI 使用注入 mock CF API/ACME runner，但 Gateway、watcher、SQLite、证书文件和多 SNI TLS/reload/rollback 是真实 Docker/Nginx。此测试不代表真实 Let's Encrypt 签发成功；上线前仍须在隔离 VPS 验证真实 DNS 权限、签发和续签。

代码包含正式安装、失败续装、证书、Admin、规则发布和分析实现。CI 验证模拟首次安装/续装和真实 Linux Docker/Nginx；**真实公网 VPS 的 HTTP-01/DNS-01 签发、续期仍需在目标环境验证**。首次使用先在隔离的 Debian/Ubuntu 测试 VPS 验证，不要直接切换生产流量。

将项目上传到 Linux 后，以 root 在项目根目录执行：

若上传工具未保留可执行位，先运行 `chmod 0755 setup.sh update.sh`。

```bash
./setup.sh
./setup.sh --check
```

首次安装会检查 Debian/Ubuntu、64 位、磁盘、Docker/Compose，并仅在确认后安装缺失的 Docker。交互输入入口域名、Admin 端口、管理员用户名和证书方式（HTTP-01、Cloudflare DNS-01、已有证书）。Admin 路径、两把 Token 密钥和初始密码独立随机生成；密码仅在安装成功时显示一次，不写入 `.env`。部署配置在 `sgw/.env`（0600），运行文件在 `sgw/runtime/`，两者均不纳入 Git。

正式流量是**公网 443 → Gateway 容器 8443（TLS）**。Admin 默认公网 HTTPS 端口为 **64444**。`8080` 仅用于容器内 healthz，不能使用旧的 `proxy_pass http://127.0.0.1:8080` 转发订阅；`8081` 是 Compose 内部 Transformer，`8443` 是容器内 TLS 监听端口。这三个容器端口不要额外发布/开放到公网。安装会提前检查宿主机 Gateway/Admin 端口冲突，续装时识别本项目已有容器，不要求宿主机 8080/8081/8443 空闲。

HTTP-01 仍使用 Let's Encrypt/acme.sh standalone，**签发及续期时需要端口 80 空闲、公网可达，域名 A 记录匹配本机**。DNS-01 不要求端口 80，Cloudflare API Token 必填、Zone ID 可选。两种自动模式都会询问安装缺失的 cron，并验证服务启动/开机启用、续期任务和部署 hook。已有证书模式不需要 cron、acme.sh、端口 80 或续期 hook。

安装失败时，先修复报告的错误，再执行 `./setup.sh` 即可安全续装。`.env` 存在不等于安装完成：安装器检查实际证书、镜像、迁移、管理员、容器健康和续期状态，只补齐缺失阶段，保留现有密钥、秘密路径、数据库/追踪和有效 active 证书。只有完整检查成功才原子写入 root 拥有、0600 的 `runtime/install-complete`，标记不包含密码或密钥。若管理员已经创建但安装未完成、密码尚未交付，最终成功时会重置并仅显示一次 `Recovery administrator password (shown once)`；不会保存明文密码。该“显示”指向当前运行的标准输出，请在交互终端执行，不要将输出重定向到共享日志。

Admin 地址为 `https://<GATEWAY_DOMAIN>:<ADMIN_PORT>/<ADMIN_SECRET_PATH>`。首次安装不询问上游，Gateway 保持 Fail-Closed；登录后在“设置”中填写上游 HTTPS/HTTP Origin，规则通过候选文件、`nginx -t` 和安全 reload 发布。入口域名只能通过安装命令更换。

## 入口追踪分组

Admin 的“入口追踪”页面可为不同 Token 稳定分配不同的订阅节点入口。数据库升级到 schema v3 时会自动建立 `root → 1/2/3`，并使用现有 Token HMAC 密钥做确定性分组；分组只保存 Token 哈希，不保存明文。任一活动叶组都可先创建三个草稿子组，完整填写同一组源域名到目标域名的映射、验证后再原子激活。激活只重新分配该父组内的 Token，其他分支不受影响，并可继续递归拆分。

追踪模式默认 `off`，不会改变现有订阅行为：

- `off`：Gateway 直接回源，和升级前一致。
- `preflight`：内部转换器解析并验证响应，但始终向客户端返回原始响应；转换器不可达时 Gateway 自动直连原上游。
- `enforced`：按 Token 所在叶组替换 Clash/Mihomo YAML 的 `proxies[*].server`，或 VLESS、VMess、Shadowsocks、Trojan、Hysteria2/Hy2、TUIC URI 的连接 authority/地址字段。SNI、UUID、密码、Reality 参数和其他字段保持原值；未知格式、解析错误、响应过大或映射缺失会失败关闭。

转换器只在 Compose 内部的 Admin `8081` 端口监听，不发布到宿主机。它最多转换 8 MiB 响应，通过固定的已校验上游 Origin 回源，校验证书且不跟随重定向。启用 `enforced` 前，所有活动叶组必须具有完全相同且完整的源域名集合。

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

完整安装后重复执行 `./setup.sh` 会同时验证完成标记和实际运行状态，不重置现有密码、密钥、证书、规则或数据库；状态损坏时报告并尝试安全恢复。`--uninstall` 只停删项目容器并保留数据，之后再执行 `./setup.sh` 可启动保留的数据，密码保持不变。`--purge` 需输入当前域名及 `PURGE`，永久删除本项目运行数据（含安装标记）和 `.env`，不删除全局 Docker/acme.sh。`update.sh` 使用 SQLite `VACUUM INTO` 备份、保留旧镜像标识并在失败时尝试回滚；`--pull` 要求 Git 工作区干净且存在远端。

`--check` 不会自动迁移数据库：检查当前 schema v3、合法 tracking_mode、root/1/2/3 初始组、管理员、SQLite 完整性、curl/yaml、实际 8081 → Transformer FPM 9001、8081 无宿主机绑定、restart policy、自动续期/cron、证书、两端 nginx 和规则版本同步。未配置上游是合法的初始 Fail-Closed 状态，检查仍可通过；新数据库 tracking_mode 为 `off`。

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
sudo bash tests/install_fake.sh  # Linux 下检查真实 root 权限；无真实 ACME/apt/get.docker.com
```

fake watcher 和 fake 运维测试不等同于 Docker/Linux 真实集成、HTTP-01/DNS-01 签发或真实续期。上线前必须在隔离 VPS 完成这些验证，并确认重复 Token Query、TLS、规则回滚、worker 轮转和健康检查在目标发行版上的行为。
