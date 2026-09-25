# Subscription Gateway

一个从零开发的订阅专用清洗网关。

本项目与 SubSieve 完全独立，不复制或修改 SubSieve 源码。

## 当前阶段

第一阶段已建立 Git 基线，第二阶段实现仍待 Linux 集成验证：

- SQLite 单一配置源和幂等 Schema 初始化
- 管理员密码安全哈希
- Token HMAC-SHA256 索引
- Token XChaCha20-Poly1305 加密存储
- 安全 Session、CSRF 和登录尝试限制
- Token、IPv4/CIDR、UA 和设置的数据层
- 第一阶段最小管理入口和 API
- 不依赖 PHPUnit 的自动测试
- 订阅专用 Gateway、确定性规则编译、候选规则测试及失败回滚
- Token/IP/UA 人工黑白名单与 Nginx Rate Limit
- Admin 通过共享控制目录发布规则，并区分保存成功与应用成功

尚未实现：

- 临时 Token 到期执行
- Nginx 日志采集和分析页面
- 安装及更新脚本

因此当前版本仅具备进入 Linux 真实集成测试的条件，不是生产可部署成品。
重复 Token Query 参数的 Nginx 实际取值语义，须在 Linux 集成测试前确认。

后续通过HTTPS反代Admin时，外层反代必须保留浏览器请求的原始 `Host`（包括非标准端口）。
CSRF校验会比较 `Origin` 与 `Host`；`SESSION_COOKIE_SECURE=true` 时后台必须通过HTTPS访问。
部署目标仅支持64位PHP（Linux x86_64或arm64）。

## 目录

```text
sgw/
├── .env.example
├── admin/
│   ├── Dockerfile
│   ├── entrypoint.sh
│   ├── nginx.conf
│   └── src/
│       ├── api.php
│       ├── dashboard.php
│       ├── db.php
│       ├── index.php
│       └── rules.php
├── control/
├── data/
├── gateway/        # 订阅专用 Nginx 与规则 watcher
└── logs/
tests/
└── run.php
```

## 自动测试

需要 PHP 8.2+，并启用：

- PDO SQLite
- Sodium

执行：

```bash
php tests/run.php
bash tests/watch_fake.sh
```

测试使用临时数据库，不读取生产 `.env`，测试结束后删除临时文件。
watcher 测试使用 fake nginx，只验证发布协议和回滚逻辑，不代表真实 Nginx 集成测试。

## 安全边界

- 不存在默认管理员密码。
- `.env` 中不得保存管理员明文密码。
- Token 明文不得保存到 SQLite 普通字段。
- 所有数据库查询使用 PDO 参数绑定。
- 完整 Token 只能由已认证管理员读取。
- 当前阶段不会连接或修改 V2Board 数据库。
