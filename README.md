# Subscription Gateway

一个从零开发的订阅专用清洗网关。

本项目与 SubSieve 完全独立，不复制或修改 SubSieve 源码。

## 当前阶段

当前只完成第一阶段：

- SQLite 单一配置源和幂等 Schema 初始化
- 管理员密码安全哈希
- Token HMAC-SHA256 索引
- Token XChaCha20-Poly1305 加密存储
- 安全 Session、CSRF 和登录尝试限制
- Token、IPv4/CIDR、UA 和设置的数据层
- 第一阶段最小管理入口和 API
- 不依赖 PHPUnit 的自动测试

尚未实现：

- Gateway Nginx 订阅代理
- Nginx 规则生成和安全 reload
- 临时 Token 到期执行
- Nginx 日志采集和分析页面
- 安装及更新脚本

因此当前版本不是可部署成品。

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
├── gateway/        # 第二阶段实现
└── logs/
tests/
└── run.php
```

## 第一阶段测试

需要 PHP 8.2+，并启用：

- PDO SQLite
- Sodium

执行：

```bash
php tests/run.php
```

测试使用临时数据库，不读取生产 `.env`，测试结束后删除临时文件。

## 安全边界

- 不存在默认管理员密码。
- `.env` 中不得保存管理员明文密码。
- Token 明文不得保存到 SQLite 普通字段。
- 所有数据库查询使用 PDO 参数绑定。
- 完整 Token 只能由已认证管理员读取。
- 当前阶段不会连接或修改 V2Board 数据库。
