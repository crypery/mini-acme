# mini-acme

> [English version](README.md)

> [Russian version](README_RU.md)

**mini-acme** 是一个用于自动管理 ACME（RFC 8555）证书的实用工具，使用 **crypery**（HTTPS Library）库以纯 C 语言编写。

对于 Let's Encrypt 证书颁发机构（CA），该工具通过 ACME 协议请求证书，并使用 **HTTP-01** 域名所有权验证方法：在 80 端口提供特殊的验证文件 `/.well-known/acme-challenge/<token>`，由 CA 服务器通过 HTTP 请求。通配符域名（`*.example.com`）无法通过 HTTP-01 验证——对它们自动使用 **DNS-01** 方法：所需的 `_acme-challenge.*` TXT 记录或通过 DNS 服务商 API（`--dns <provider> --apikey <key>`，目前支持 `dynadot`）自动发布和删除，或由工具打印出来供管理员在 DNS 服务商处添加；然后工具等待该记录可在公共 DNS 中解析，再完成订单。

## 说明

mini-acme 启动时：

1. 创建（或从缓存加载）带有 RSA-2048 密钥的 ACME 账户。
2. 向 Let's Encrypt 请求一个或多个域名的 RSA-2048 证书：第一个 `-domain` 为主域名（CN + 缓存文件名），所有域名都列入 SAN 扩展。
3. 为每个域名通过所有权验证：常规域名通过 HTTP-01（在 80 端口启动提供验证文件的 HTTP 服务器，其余 HTTP 请求重定向到 HTTPS）；通配符域名通过 DNS-01（发布所需 TXT 记录——指定 `--dns`/`--apikey` 时通过 DNS 服务商 API 自动完成，否则打印出来供管理员添加——并等待其在公共 DNS 中可见）。
4. 将签发的证书（完整链：叶子 + 中间证书）和密钥保存到缓存目录，然后退出——不启动 HTTPS 服务器。

账户密钥和签发的证书存储在本地缓存目录（默认：`certs/`）中：`<primary>.pem`（密钥 + 完整链）、`<primary>.crt`（完整链）、`<primary>.key`（密钥）。重启时，只要缓存证书剩余有效期超过 30 天**且**其 SAN 覆盖所有请求的域名，就会复用缓存证书；否则签发新证书。

## 项目特性

- **纯 C，无外部加密库** —— 整个 TLS 栈（TLS 1.2/1.3、AES-128-GCM、SHA-256、HMAC-SHA256、HKDF、RSA-2048、ECDH P-256/X25519、X.509）均在 crypery 库内实现。
- **完整的 ACME 流程**：创建账户、多域名证书订单、为每个域名做 HTTP-01/DNS-01 验证并获取证书。
- **多域名（SAN）证书**：`-domain` 最多可重复 8 次（例如 apex + `www`）——所有域名都进入同一张证书。
- **通配符域名**：`*.example.com` 通过 DNS-01 验证（TXT 记录 `_acme-challenge.example.com` 在使用 `--dns <provider> --apikey <key>` 时通过 DNS 服务商 API 发布和删除——目前支持 `dynadot`——否则打印出来供手动添加；工具轮询公共 DNS 直至记录可见，两次确认后在验证完成时删除）。
- **完整证书链**：保存的 `.crt`/`.pem` 文件包含叶子和中间证书，浏览器可无错误地构建证书链。
- **跨平台**：Windows（Winsock2/WinAPI）和 POSIX（BSD 套接字、pthreads）——同一份源代码。
- **一次性运行**：获取证书后退出——无守护进程、无遗留的开放端口。
- **缓存**：只要缓存证书剩余有效期超过 30 天并覆盖所有请求的域名，重启就不会创建新账户或请求新证书；过期的缓存（到期或缺少 SAN 名称）会触发重新签发。
- **最小依赖**：仅标准 C 库、pthreads（POSIX）和 zlib（HTTP 模块的 gzip 压缩）。
- **按需使用 staging**：默认使用 Let's Encrypt 生产环境；如需在 staging CA 上测试以避免耗尽生产环境速率限制，请传入 `-dir https://acme-staging-v02.api.letsencrypt.org/directory`。

## 使用的模块

| 模块 | 用途 |
|--------|---------|
| **crypery** | 纯 C 网络栈：TLS 1.2/1.3 加密层（`tls`）、OpenSSL 兼容封装层（`ssl`）、HTTP/1.1 服务器（`http`）以及 HTTP/HTTPS 客户端（`url`）。所有加密算法均从零实现；用于 ACME 请求（`url` 客户端）以及 RSA 密钥生成/签名（`tls` 模块）。 |
| **utilery** | 基础 C 库集合：JSON 解析器（`json` —— 解析 ACME 服务器响应）、日志模块（`log`）、配置模块（`sett`）以及 `ecma` 库（UTF-8 编解码、正则表达式、字符串缓冲区）。无外部依赖。 |
| **zlib** | 压缩库；被 crypery 的 `http` 模块用于 gzip 压缩响应（可选，通过 `HTTP_NO_GZIP` 标志禁用）。 |

## 编译

### Windows（build_acme.bat）

需要 MinGW（gcc 在 PATH 中）。运行：

```bat
build_acme.bat
```

结果：项目根目录下的 `mini-acme.exe`。

### Linux（build_acme.sh）

编译在带 gcc 的 Docker 容器（`gcc:13` 镜像）内进行，因此主机上只需要 Docker。运行：

```bash
bash build_acme.sh
```

结果：`mini-acme` 二进制文件（ELF，x86-64）被复制到项目根目录。

可通过环境变量 `IMAGE` 覆盖容器镜像（例如 `IMAGE=gcc:14 bash build_acme.sh`）。

## 使用

```
mini-acme [-domain <name>]... [-dir <acme-directory-url>] [-cache <dir>] [-email <addr>] [--apikey <key> --dns <provider>] [-h]
```

| 参数 | 说明 | 默认值 |
|----------|-------------|---------|
| `-domain <name>` | 要包含在证书中的域名（可重复，最多 8 次；第一个 = 主域名：CN + 缓存文件名，全部 = SAN） | 主机名 |
| `-dir <url>` | CA 的 ACME 目录 URL | Let's Encrypt production |
| `-cache <dir>` | 缓存目录（账户密钥、证书） | `certs` |
| `-email <addr>` | ACME 账户的联系邮箱 | `admin@example.com` |
| `--apikey <key>` | DNS 服务商 API 密钥（必须与 `--dns` 一起给出）；用于自动发布/删除 dns-01 TXT 记录 | - |
| `--dns <provider>` | 用于自动管理 TXT 记录的 DNS 服务商（支持：`dynadot`；必须与 `--apikey` 一起给出） | - |
| `-h`、`-help` | 帮助 | - |

### 要求

- 每个常规域名必须**可公共访问** —— 其 A/AAAA 记录必须指向运行该工具的机器，否则 HTTP-01 验证无法通过。
- 入站端口 **80**（HTTP-01）必须开放。
- 有权绑定 80 端口（Linux 上 —— 以 root 运行或具备 `CAP_NET_BIND_SERVICE`）。
- 对于**通配符**域名：使用 `--dns`/`--apikey` 时需要有效的 DNS 服务商 API 密钥（否则需要 DNS 服务商处添加 DNS TXT 记录的权限），以及出站端口 **53**（UDP，并自动回退到 TCP —— 工具在等待记录期间轮询公共解析器 8.8.8.8 / 1.1.1.1 / 9.9.9.9）。

### 示例

```bash
# 为 example.com 申请证书（默认：Let's Encrypt production）
mini-acme -domain example.com

# apex + www 合并到一张证书，Let's Encrypt staging 环境（用于测试）
mini-acme -domain example.com -domain www.example.com -dir https://acme-staging-v02.api.letsencrypt.org/directory

# 通配符：打印需要在 DNS 服务商处添加的 TXT 记录，然后等待其出现
mini-acme -domain example.com -domain '*.example.com'

# 通配符，通过 Dynadot API 自动管理 TXT 记录
mini-acme -domain example.com -domain '*.example.com' --dns dynadot --apikey <你的-api-密钥>

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

程序在获取证书后退出。若要强制重新签发（例如添加域名后），删除主域名的缓存文件（`certs/<primary>.pem`、`.crt`、`.key`）并再次运行。

## 许可证

GNU AGPL v3（Affero GPL）
