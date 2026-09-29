# mini-acme

> [English version](README.md)

> [Russian version](README_RU.md)

**mini-acme** - 使用 **crypery**（HTTPS Library）库以纯 C 语言编写的 ACME（RFC 8555）证书自动管理工具。

针对 Let's Encrypt 证书颁发机构（CA），该工具通过 ACME 协议申请证书，使用 **HTTP-01** 域名所有权验证方法：在 80 端口上提供特殊的验证文件 `/.well-known/acme-challenge/<token>`，CA 服务器通过 HTTP 请求该文件。

## 描述

mini-acme 启动时：

1. 创建（或从缓存加载）带有 RSA-2048 密钥的 ACME 账户。
2. 向 Let's Encrypt 为一个或多个域名申请 RSA-2048 证书：第一个 `-domain` 为主域名（CN + 缓存文件名），所有域名都列入 SAN 扩展。
3. 通过 HTTP-01 为每个域名完成所有权验证：在 80 端口启动 HTTP 服务器，提供验证文件（其他 HTTP 请求重定向到 HTTPS）。
4. 将签发的证书（完整链：leaf + intermediate）和密钥保存到缓存目录后退出 - 不启动 HTTPS 服务器。

账户密钥和签发的证书存储在本地缓存目录中（默认为 `certs/`）：`<primary>.pem`（密钥 + 完整链）、`<primary>.crt`（完整链）、`<primary>.key`（密钥）。只要缓存证书有效期超过 30 天**且**其 SAN 覆盖所有请求的域名，重新启动时会复用缓存证书；否则将签发新证书。

## 项目特点

- **纯 C 实现，无外部加密库** - 完整的 TLS 协议栈（TLS 1.2/1.3、AES-128-GCM、SHA-256、HMAC-SHA256、HKDF、RSA-2048、ECDH P-256/X25519、X.509）均在 crypery 库内实现。
- **完整的 ACME 流程**：创建账户、多域名证书订单、每个域名的 HTTP-01 验证以及证书获取。
- **多域名（SAN）证书**：`-domain` 最多可重复 8 次（例如 apex + `www`）- 所有名称包含在一张证书中。
- **完整链证书**：保存的 `.crt`/`.pem` 文件包含 leaf 和 intermediate 证书，浏览器可无错误地构建证书链。
- **跨平台**：Windows（Winsock2/WinAPI）和 POSIX（BSD 套接字、pthreads）- 同一份源代码。
- **一次性运行**：获取证书后即退出 - 不留守护进程和开放端口。
- **缓存机制**：只要缓存证书有效期超过 30 天且覆盖所有请求的域名，重新启动时不会创建新账户或申请新证书；过期或缺失 SAN 名称的缓存将触发重新签发。
- **最小依赖**：仅标准 C 库、pthreads（POSIX）和 zlib（HTTP 模块的 gzip 压缩）。
- **默认安全**：默认使用 Let's Encrypt 的 staging 环境，以免耗尽生产 CA 的速率限制。

## 使用的模块

| 模块 | 用途 |
|------|------|
| **crypery** | 纯 C 网络协议栈：TLS 1.2/1.3 加密层（`tls`）、OpenSSL 兼容封装层（`ssl`）、HTTP/1.1 服务器（`http`）和 HTTP/HTTPS 客户端（`url`）。所有加密算法均从零实现；用于 ACME 请求（`url` 客户端）以及 RSA 密钥生成/签名（`tls` 模块）。 |
| **utilery** | 基础 C 库集合：JSON 解析器（`json` - 解析 ACME 服务器响应）、日志模块（`log`）、配置模块（`sett`）和 `ecma` 库（UTF-8 编解码、正则表达式、字符串缓冲区）。无外部依赖。 |
| **zlib** | 压缩库；被 crypery 的 `http` 模块用于 gzip 压缩响应（可选，可通过 `HTTP_NO_GZIP` 标志禁用）。 |

## 编译

### Windows（build_acme.bat）

需要 MinGW（gcc 在 PATH 中）。运行：

```bat
build_acme.bat
```

结果：项目根目录下的 `mini-acme.exe`。

### Linux（build_acme.sh）

编译在带有 gcc 的 Docker 容器（`gcc:13` 镜像）中执行，因此主机上只需安装 Docker。运行：

```bash
bash build_acme.sh
```

结果：`mini-acme` 二进制文件（ELF，x86-64）被复制到项目根目录。

可通过环境变量 `IMAGE` 覆盖容器镜像（例如 `IMAGE=gcc:14 bash build_acme.sh`）。

## 使用

```
mini-acme [-domain <name>]... [-dir <acme-directory-url>] [-cache <dir>] [-email <addr>] [-h]
```

| 参数 | 描述 | 默认值 |
|------|------|--------|
| `-domain <name>` | 包含在证书中的域名（可重复，最多 8 个；第一个为主域名：CN + 缓存文件名，全部列入 SAN） | 主机名 |
| `-dir <url>` | CA 的 ACME 目录 URL | Let's Encrypt staging |
| `-cache <dir>` | 缓存目录（账户密钥、证书） | `certs` |
| `-email <addr>` | ACME 账户的联系邮箱 | `admin@example.com` |
| `-h`、`-help` | 帮助 | - |

### 要求

- 每个域名必须**可公开访问** - 其 A/AAAA 记录必须指向运行该工具的机器，否则 HTTP-01 验证无法通过。
- 开放入站端口 **80**（HTTP-01）。
- 具有绑定 80 端口的权限（在 Linux 上 - 以 root 运行或具有 `CAP_NET_BIND_SERVICE` 权限）。

### 示例

```bash
# 为 example.com 在 staging 环境（默认）申请证书
mini-acme -domain example.com

# Apex + www 在一张证书中，Let's Encrypt 生产环境
mini-acme -domain example.com -domain www.example.com -dir https://acme-v02.api.letsencrypt.org/directory

# 自定义缓存目录和邮箱
mini-acme -domain example.com -cache /var/lib/mini-acme -email admin@example.com
```

### 会话示例

```
Domains (2): example.com www.example.com
Obtaining certificate for example.com ...
Certificate valid until: 2026-12-20 12:00:00 UTC
Certificate saved to certs/example.com.pem
Done.
```

程序在获取证书后退出。如需强制重新签发（例如添加域名后），请删除主域名的缓存文件（`certs/<primary>.pem`、`.crt`、`.key`）后重新运行。

## 许可证

GNU AGPL v3（Affero GPL）
