# DevSidecar · Tauri 重构版

> 开发者边车加速工具：本地 MITM 代理 + DNS 优选 + 插件加速，为 GitHub、npm、pip、Docker 等开发者资源提供稳定的网络通道。
>
> 本项目是 [docmirror/dev-sidecar](https://github.com/docmirror/dev-sidecar)（Electron 版）的 **Tauri 2 + Rust + SolidJS** 重写，功能与原版保持一致，**已完全移除 overwall（科学上网）相关功能**。

| 维度 | 原版 | 本版本 |
| --- | --- | --- |
| 运行框架 | Electron（Node 常驻） | **Tauri 2**（Rust 常驻，体积与内存占用显著降低） |
| 代理核心 | Node 实现 | **Rust**（tokio + hyper + rustls + rcgen） |
| 前端 | Vue | **SolidJS + TypeScript + TailwindCSS 4** |
| 许可 | MPL-2.0 | **MPL-2.0** |

---

## 目录

- [功能特性](#功能特性)
- [技术栈与架构](#技术栈与架构)
- [目录结构](#目录结构)
- [快速开始](#快速开始)
- [界面与交互](#界面与交互)
- [配置](#配置)
- [IPC 参考](#ipc-参考)
- [安全说明](#安全说明)
- [与原版差异](#与原版差异)
- [故障排查](#故障排查)
- [开发约定](#开发约定)
- [许可](#许可)

---

## 功能特性

### 1. 加速服务（MITM 代理）

- 本地 HTTP/HTTPS 代理，默认监听 `127.0.0.1:31181`；HTTPS 通过本地 CA 动态签发证书实现 MITM。
- **请求/响应拦截规则**（`server.intercepts`）：内置 24 组规则覆盖 GitHub、GitHub Raw/头像、codeload、Docker、Google 静态资源、gstatic 字体等，支持域名改写、请求头改写、响应脚本注入。
- **拦截模式**（`server.setting.interceptMode`）：`all-but-whitelist`（默认，非白名单域名均解密）/ `intercepts-only`（仅解密规则命中的域名）。
- **上游连接**：DNS 优选 / 预置 IP、SNI 改写、TLS 1.2 兼容开关、按域名配置超时（`timeoutMapping`）、请求失败重试。
- **多地址回退**：解析出多个地址时按 Happy Eyeballs 错峰并发尝试（间隔 250ms，IPv4 优先），避免「首个地址不可达即整体失败」；直连隧道与拦截路径行为一致。
- **连接复用**：按「域名 + 实际 IP + SNI + 校验策略 + TLS 版本 + 协议」池化上游客户端，复用 TCP/TLS 连接（不再每请求重新握手）；测速切换优选 IP 后自动使用新连接。
- **HTTP/2 上游**：`server.setting.allowHttp2`（默认 `true`）开启后与上游按 ALPN 协商 h2/http1.1，对客户端侧仍以 HTTP/1.1 回写。
- **WebSocket / 协议升级**：请求带 `Upgrade` 头且上游返回 `101` 时原样透传响应头并转为双向隧道。
- **大请求体流式转发**：`Content-Length` 超过 `server.setting.streamBodyThreshold`（默认 1MB）的请求体边读边转发，不在内存中缓冲（该类请求不参与重试）。
- 兼容开关：`compatible`、`cloudflareRoute`、`fakeServerMaxLength`。

### 2. DNS 与优选

- 多 DoH 提供方：`safe360`、`aliyun`、`cloudflare`、`quad9`、`rubyfish`。
- `mapping`：按域名指定 DNS 与地址族；`familyMapping`；`preSetIpList` 预置 IP（GitHub 等）。
- **查询结果缓存**：provider 级 `cacheTtl`（秒，默认 60，`0` 表示不过期）控制解析结果缓存时长，到期自动重新解析；`PreSet` 为静态映射不受影响。
- `speedTest`：后台定时测速，为命中域名挑选最优 IP（结果推送前端展示）；DNS 解析与 TCP 测速均有界并发（8 路），缩短整体测速周期。

### 3. 系统代理

- 一键设置/取消系统代理（Windows 注册表、环境变量），可同时写入证书相关环境变量。
- **国内域名直连白名单**（`excludeIpList`），支持从 `china-domain-allowlist` 自动更新。
- 退出（窗口退出 / 托盘退出 / 关机）时自动恢复系统代理，避免残留失效设置。

### 4. 插件加速（可配置随应用启动）

| 插件 | 能力 |
| --- | --- |
| **NPM** | 切换 registry（默认官方源，可选 taobao/npmmirror、中科大）、`strict-ssl`/`cafile`、证书环境变量、Electron 等二进制镜像环境变量 |
| **Git** | 写入全局 `http.proxy` / `https.proxy` 指向本地加速服务；`sslVerify`；`noProxyUrls` 指定不走代理的站点 |
| **PIP** | `index-url` / `trusted-host`（阿里云、清华、中科大等 10 个镜像可选） |

### 5. 证书

- 首次使用自动生成本地 CA：`~/.dev-sidecar/dev-sidecar.ca.crt`（证书）与 `dev-sidecar.ca.key.pem`（私钥）。
- 「安装证书」页提供检测、安装到系统信任区、打开证书所在目录。

### 6. 工具

- **流量统计**：实时上/下行字节与速率，来自后端流量事件。
- **网络检测**：对目标域名做连通性/延迟检测。
- **GitHub 状态**：展示 githubstatus.com 服务状态。
- **日志**：按天落盘、超限滚动，可开关、可改目录与大小上限。

### 7. 配置

- 四层配置：**内置默认** → **远程共享配置** → **个人远程配置** → **用户差异配置**（JSONC，支持注释）。
- 远程配置可下载/更新，并支持「个人远程配置」URL。

### 8. 界面与桌面集成

- 12 个页面（含插件、流量、GitHub 状态、网络检测、证书、设置、帮助）。
- **草稿编辑 + 「保存 / 保存并应用」**：改配置后出现保存条，保存即写盘并按需重启服务/重应用代理/重装插件。
- 主题（深/浅）、窗口尺寸（可保存并立即应用，启动时自动恢复）。
- **关闭策略**：每次询问（默认）/ 直接退出 / 最小化到托盘；托盘菜单支持「显示窗口」「退出」。

---

## 技术栈与架构

### 前端

- **SolidJS 1.9** + **TypeScript 5.7** + **TailwindCSS 4**（`@tailwindcss/vite`）+ **Vite 6**，包管理 **pnpm**。
- 全局状态集中在 `src/store.ts`（配置、状态、流量、测速、Toast、主题）；`src/api.ts` 封装 Tauri `invoke` 并做入参/出参类型约定。
- 主题通过 `document.documentElement[data-theme]` + CSS 变量实现。

### 后端

- **Tauri 2** + Rust（edition 2021，MSRV 1.77）；异步栈 **tokio**，HTTP **hyper 1**，TLS **rustls 0.23（ring / tls12）**，证书签发 **rcgen**，DoH/远程配置 **reqwest**。
- 代理链路：`proxy/mod.rs`（服务生命周期、CONNECT 的直连隧道 / MITM 决策）→ `proxy/forward.rs`（请求转发管线：拦截器两阶段、DNS 优选、重试、响应组装、脚本注入、升级隧道）→ `proxy/interceptor.rs`（规则匹配与改写）→ `proxy/connector.rs`（自定义连接器：指定 IP、SNI 改写、跳过校验、多地址回退、上游客户端池）。
- TLS：`tls.rs` 统一管理本地 CA（私钥 0600 / Windows ACL 收紧、leaf 私钥进程级复用）与上游 `ClientConfig`（按 `(verify, allowTls12, allowHttp2)` 缓存）。
- 日志：`util/log.rs` 提供 `log_debug!/log_info!/log_warn!/log_error!`，按天写 `~/.dev-sidecar/logs/`。

### 数据流

```text
┌──────────────── 前端（WebView）────────────────┐
│ SolidJS 页面 ── 全局信号 store.ts ── api.ts    │
└───────────────┬───────────────────────────────┘
                │ Tauri IPC：36 个命令 + 事件推送
┌───────────────▼───────────────────────────────┐
│ Rust 后端                                      │
│ app.rs       应用状态、启动/关闭、CA 懒加载    │
│ proxy/       MITM 代理（mod 生命周期 / forward 管线 /  │
│              interceptor 规则 / connector 连接池）│
│ dns/         DoH 解析、PreSet 映射、TTL 缓存    │
│ plugin/      node / git / pip 插件             │
│ sysproxy/    系统代理与环境变量                │
│ tls.rs       本地 CA、上游 TLS 客户端配置缓存  │
│ speed.rs     优选 IP 测速（有界并发）          │
│ event.rs     状态 / 流量 / 测速 事件           │
│ config/      默认+远程+用户配置的加载与合并    │
└───────────────────────────────────────────────┘
```

---

## 目录结构

```text
dev-sidecar-tauri/
├─ index.html
├─ package.json                 # 前端脚本与依赖（dev/build/typecheck/tauri）
├─ vite.config.ts               # Vite：端口 1420，Tailwind 插件
├─ src/                         # 前端（SolidJS）
│  ├─ api.ts                    # invoke 封装 + 外链/路径打开
│  ├─ store.ts                  # 全局信号：config/status/traffic/speed/toasts + useDraft
│  ├─ router.ts                 # 菜单定义与 hash 路由
│  ├─ App.tsx                   # 外壳：菜单分组、页面切换、主题按钮
│  ├─ components/
│  │  ├─ ui.tsx                 # Container/Card/Switch/Button/Input/Select/Field/Tag/
│  │  │                         # SaveBar/JsonEditor/TextArea/StatusDot/Toasts
│  │  ├─ CloseDialog.tsx        # 关闭询问弹窗（关闭策略 ask）
│  │  └─ PowerButton.tsx        # 主服务开关
│  └─ pages/                    # Index/Server/Proxy/PluginNode/PluginGit/PluginPip/
│                               # Traffic/GithubStatus/Check/Ca/Setting/Help
└─ src-tauri/                   # 后端（Rust）
   ├─ Cargo.toml
   ├─ tauri.conf.json           # 窗口 900×750（最小 900×620）、托盘、打包配置
   ├─ icons/                    # 应用图标
   ├─ tests/                    # 集成测试：interceptor / mitm / upgrade / http2 / smoke
   └─ src/
      ├─ main.rs, lib.rs        # 入口：托盘、窗口事件、命令注册
      ├─ macros.rs              # 日志宏
      ├─ app.rs                 # 应用状态与生命周期（init/start/stop/shutdown）
      ├─ commands.rs            # Tauri IPC 命令（36 个）
      ├─ event.rs               # 事件：status/speed/speedTesting/traffic/error/sniList
      ├─ matcher.rs             # 域名匹配（支持通配）
      ├─ tls.rs                 # 本地 CA、上游 TLS 配置缓存
      ├─ speed.rs               # 优选 IP 测速（有界并发）
      ├─ config/                # default.json + 配置加载/合并/保存
      ├─ dns/                   # DoH 客户端、Preset 映射、DNS 报文、TTL 缓存
      ├─ proxy/                 # MITM 代理核心
      │  ├─ mod.rs              #   服务生命周期、监听、CONNECT（直连隧道 / MITM）
      │  ├─ forward.rs          #   请求转发管线（拦截器、DNS 优选、重试、注入、升级隧道）
      │  ├─ interceptor.rs      #   拦截规则匹配与改写
      │  ├─ connector.rs        #   上游连接器与客户端池
      │  └─ http.rs             #   HTTP/1.1 报文解析与写入
      ├─ plugin/                # node / git / pip 插件实现
      ├─ sysproxy/              # 系统代理与环境变量
      └─ util/                  # jsonc 解析、日志、路径、合并工具
   ```

---

## 快速开始

### 环境要求

- **Node.js ≥ 20**、**pnpm**（包管理统一使用 pnpm）
- **Rust ≥ 1.77**（Windows 需 MSVC 工具链）
- Windows 10/11 需 **WebView2 Runtime**（Win11 通常已内置）

### 开发

```bash
pnpm install
pnpm tauri dev          # 启动桌面应用（前端 dev server 端口 1420）
pnpm dev                # 仅启动前端（无后端能力，用于样式调试）
```

加速服务默认监听 `127.0.0.1:31181`，GitHub 加速等能力需在「加速服务」「安装证书」页完成初始化。

### 校验

```bash
pnpm typecheck                        # tsc --noEmit
pnpm build                            # vite 构建前端

cd src-tauri
cargo check                           # 后端编译检查
cargo test                            # 单元测试 + 集成测试（interceptor / mitm / upgrade / http2 / smoke）
cargo test --lib                      # 仅单元测试（日志、连接器、重试策略、DNS TTL 缓存）
```

### 打包

```bash
pnpm tauri build
```

产物位于 `src-tauri/target/release/bundle`（MSI / NSIS）。release profile 已开启 LTO、`opt-level = "s"`、`panic = "abort"`、strip。

---

## 界面与交互

### 页面

| 页面 | 说明 |
| --- | --- |
| 首页概览 | 服务/代理/插件状态总览、主服务开关、流量概览、快速入口 |
| 加速服务 | 监听地址端口、DNS/超时/拦截等设置（草稿编辑 + 保存并应用） |
| 系统代理 | 系统代理与证书环境变量、国内域名直连白名单 |
| NPM 加速 | registry 与环境变量、随应用启动 |
| Git 代理 | 全局 `http.proxy` / `https.proxy`、`sslVerify`、`noProxyUrls` |
| PIP 加速 | `index-url`、`trusted-host` |
| 流量统计 | 实时上/下行与速率，可重置 |
| GitHub 状态 | githubstatus.com 服务状态 |
| 网络检测 | 域名连通性/延迟检测 |
| 安装证书 | 本地 CA 状态、安装到信任区、打开目录 |
| 应用设置 | 界面（主题/窗口/关闭策略）、远程配置、日志、维护 |
| 帮助 | 远程配置下发的帮助链接 |

### 交互约定

- **草稿编辑**：页面内改动先进入草稿（不落盘），底部出现保存条；运行时开关（如启用/停止）保持即时生效。
- **保存 vs 保存并应用**：
  - 其他页面：**保存并应用** = 写盘 + 立即生效（重启服务 / 重应用代理 / 重装插件）。
  - 应用设置·界面：**保存** = 仅写盘（主题即时生效，窗口尺寸下次启动生效）；**保存并应用** = 额外立即调整当前窗口尺寸。
- **多行文本框**：无右下角缩放角标，鼠标移到下边框按住即可拖拽调整高度。
- **关闭策略**：`每次询问`（默认）弹出弹窗选择「退出应用 / 最小化到托盘」并可记住选择；`直接退出`、`最小化到托盘` 可在应用设置中切换。
- 草稿未保存时切换页面会丢弃修改（与原版一致），保存条会持续提示。

---

## 配置

### 位置与文件

用户目录 `~/.dev-sidecar`（可用环境变量 `DEV_SIDECAR_HOME` 覆盖）：

| 文件 | 说明 |
| --- | --- |
| `config.json` | 用户差异配置（**仅保存与默认/远程配置不同的部分**，JSONC 允许注释） |
| `remote_config.json` | 远程共享配置缓存 |
| `remote_config_personal.json` | 个人远程配置缓存 |
| `running.json` | 运行时配置 |
| `dev-sidecar.ca.crt` / `dev-sidecar.ca.key.pem` | 本地 CA 证书与私钥 |
| `logs/YYYY-MM-DD.log` | 日志（按天，超过 `app.maxLogFileSize` 自动滚动） |
| `extra/` | 附加数据（如国内域名白名单文件） |

### 合并与保存

- **合并顺序**（与原版 `getConfigFromFiles` 一致，远程配置合并两次以保证优先级）：

  ```text
  用户配置 → 个人远程 → 共享远程 → 内置默认 → 共享远程 → 个人远程 → 用户配置
  ```

- **保存语义**：`save_config` 只把「相对默认配置 + 远程配置」的差异写入 `config.json`，删除的键不会复活（页面保存使用整段替换语义）。
- **占位符**：默认配置中的 `${userBase}`、`${caCert}`、`${caKey}`、`${logDir}` 在加载时替换为真实路径。

### 主要配置段

| 段 | 关键字段 |
| --- | --- |
| `app` | `theme`、`windowSize`、`closeAction`（`ask`/`hide`/`exit`）、`autoStart`、`remoteConfig`、`logDisabled`、`logFileSavePath`、`maxLogFileSize(+Unit)` |
| `server` | `enabled`、`host`、`port`、`setting`（`verifySsl`、`allowTls12`、`allowHttp2`、`interceptMode`、`streamBodyThreshold`、`defaultTimeout`、`timeoutMapping`…）、`intercepts`、`preSetIpList`、`whiteList`、`dns`（`providers`（含 `cacheTtl`）/`mapping`/`familyMapping`/`speedTest`） |
| `proxy` | `enabled`、`setEnv`、`setCaBundle`、`excludeIpList`、`excludeDomesticDomainAllowList`、`autoUpdateDomesticDomainAllowList` |
| `plugin` | `node` / `git` / `pip`：`enabled`、`startWithApp`、`setting`、`envVariables` |
| `help` | `dataList`（帮助页链接，可由远程配置下发） |

---

## IPC 参考

### 命令（36 个）

| 命令 | 说明 | 参数 → 返回 |
| --- | --- | --- |
| `get_config` | 读取完整生效配置 | — → 配置对象 |
| `get_config_by_path` | 按路径读取配置片段 | `path` → 值 |
| `save_config` | 保存配置（仅写差异） | `config` → 生效配置 |
| `reset_default` | 重置为默认配置（可按 key） | `key?` → 生效配置 |
| `remove_user_config` | 备份并清空用户配置（恢复出厂） | — → 是否发生备份 |
| `download_remote_config` | 下载远程配置 | — → 生效配置 |
| `start_server` / `stop_server` / `restart_server` | 启动/停止/重启加速服务 | — → `void` |
| `server_status` | 加速服务是否运行 | — → `{ running }` |
| `app_status` | 服务/代理/插件运行状态快照 | — → `{ server, proxy, node, git, pip }` |
| `start_proxy` / `stop_proxy` | 应用/取消系统代理 | — → `void` |
| `is_ca_exists` | 本地 CA 是否存在 | — → `boolean` |
| `can_trust_ca` | 当前平台能否安装 CA | — → `boolean` |
| `get_ca_cert_path` / `get_user_base_path` / `get_log_dir` | 获取证书/用户目录/日志目录路径 | — → `string` |
| `setup_ca` | 生成并安装本地 CA | — → 安装结果说明 |
| `enable_plugin` / `disable_plugin` | 启用/停用插件 | `name`（`node`/`git`/`pip`） → `void` |
| `plugin_status` | 各插件运行状态 | — → `Record<string, boolean>` |
| `speed_test` | 触发优选 IP 测速 | — → `{ resultList }` |
| `traffic_stats` / `reset_traffic` | 读取/重置流量统计 | — → `{ upload, download }` / `void` |
| `dns_providers` | 可用 DoH 提供方列表 | — → 对象 |
| `network_check` | 域名连通性检测 | `hostname` → 检测结果 |
| `npm_get_registry` | 当前 npm registry 与命令 | — → `{ registry, command }` |
| `app_version` | 应用版本号 | — → `string` |
| `get_log_status` / `set_log_disabled` | 日志开关与目录 | `disabled` → `{ disabled, dir }` / `{ disabled, config }` |
| `open_path` / `open_url` | 用系统默认程序打开路径/链接 | `path` / `url` → `void` |
| `shutdown` | 优雅关闭（恢复系统代理、回滚插件配置） | — → `void` |
| `execute_close` | 关闭询问弹窗的最终动作 | `action`（`exit` / `hide`） → `void` |
| `apply_window_size` | 立即应用配置中的窗口尺寸 | — → `void` |

### 事件

| 事件 | 负载 | 消费方 |
| --- | --- | --- |
| `status` | `{ key, status }` | 前端状态点（`starting`/`success`/`fail`/`stopped`…） |
| `traffic` | `{ upload, download, uploadSpeed, downloadSpeed }` | 流量统计页 |
| `speed` | `{ resultList }` | 测速结果列表 |
| `speedTesting` | `boolean` | 测速进行中标记 |
| `error` | `{ title, msg }` | 全局 Toast |
| `close-requested` | 窗口 label | 关闭询问弹窗（`closeAction = ask`） |
| `sniList` | SNI 列表 | 后端发出（当前前端未消费） |

---

## 安全说明

- **MITM 原理**：为使 HTTPS 可被改写，加速服务会用本地 CA 为命中的域名动态签发证书，因此需要将该 CA 安装到系统信任区。CA 私钥仅保存在本机 `~/.dev-sidecar/dev-sidecar.ca.key.pem`，**请勿泄露或提交到仓库**。
- **私钥权限**：CA 私钥写入后即收紧权限——Unix 下 `0600`，Windows 下调用 `icacls` 移除继承 ACL 并仅授予当前用户完全控制（收紧失败仅告警，不阻断启动）。
- **拦截范围可收紧**：默认 `all-but-whitelist` 会解密所有非白名单域名；如需最小化解密范围，可将 `server.setting.interceptMode` 设为 `intercepts-only`（仅解密拦截规则命中的域名）。
- **监听范围**：加速服务默认只监听 `127.0.0.1`，不对外网暴露。
- **退出清理**：窗口退出、托盘退出、系统关机路径都会恢复系统代理并回滚插件配置，避免残留失效代理导致无法上网。
- **外链限制**：应用内打开外链仅允许 `http(s)`（帮助页链接由远程配置下发，需防止非预期协议），统一交由后端 opener 处理。
- **配置来源**：远程配置优先级较高，如仅需本地配置可在应用设置中关闭「远程配置」。

---

## 与原版差异

| 项 | 说明 |
| --- | --- |
| 运行框架 | Electron → Tauri 2，Rust 常驻进程；体积、内存占用与冷启动显著下降 |
| 代理核心 | Node → Rust（tokio + hyper + rustls + rcgen），MITM、拦截规则、DNS PreSet 行为对齐原版 |
| 前端 | Vue → SolidJS + TypeScript + TailwindCSS |
| overwall | 相关页面、配置与依赖**全部移除** |
| 日志 | 按天落盘 + 大小滚动，可在界面开关与改路径 |
| 界面交互 | 配置页采用草稿编辑 + 「保存 / 保存并应用」；关闭策略可选（询问/退出/托盘） |

**对齐原版的连接与重试行为**：

- 重试规则来自配置（`times`、`statuses`、`methods`），可按域名下发。
- 无重试规则时，对**幂等方法**（`GET` / `HEAD` / `OPTIONS`，与重试规则的默认方法列表一致）的**建连失败**额外重试一次；超时不重试（避免长轮询类端点等待时间翻倍），非幂等方法不默认重试（避免重复副作用）。
- 上游多地址按 Happy Eyeballs 错峰并发尝试（250ms 间隔、IPv4 优先），不再「取第一个地址失败即整体失败」。

**内部机制相对原版的差异（对外可观测行为不变）**：

| 项 | 说明 |
| --- | --- |
| 上游连接复用 | 按 `UpstreamKey`（域名 + IP + 端口 + SNI + 校验策略 + TLS 版本 + 协议）池化客户端，空闲连接保留 90s / 每 host 8 条；主流程不复用（视为 bug，非兼容性回归） |
| TLS 配置缓存 | 按 `(verify, allowTls12, allowHttp2)` 缓存 `ClientConfig`，避免每请求遍历系统证书库；MITM leaf 私钥进程级复用 |
| HTTP/2 上游 | 新增 `allowHttp2`（默认开启）；升级请求与明文连接强制 HTTP/1.1 |
| 流式请求体 | 新增 `streamBodyThreshold`（默认 1MB），超阈值走管道直通转发且不参与重试 |
| 协议升级 | 新增 WebSocket `101` 双向隧道支持（原版由 Node 侧处理） |
| DNS 缓存 | 新增 provider 级 `cacheTtl`（默认 60s），到期自动重新解析 |
| 插件子进程 | npm 配置批量写入（失败或校验不一致自动回退逐条），减少进程启动开销 |
| 失败路径 | 请求体读取失败返回 `413` 并关闭连接，避免残留字节污染 keep-alive 后续请求 |

---

## 故障排查

### 1. 日志出现 `请求失败: <url> -> client error (Connect) -> TCP 连接失败 <ip>: ...`

含义：代理向上游建连失败，已按设计向客户端返回 `502`（响应头带 `DS-Request-Error` / `DS-URL` / `DS-Target-IP` 便于定位）。

- 失败阶段已在错误链中标明（`DNS 解析失败` / `TCP 连接失败` / `TLS 握手失败`）与目标地址。
- 目标域名若不在 `whiteList` / `preSetIpList` / `dns.mapping` 中，则使用系统 DNS；瞬时失败会自动重试一次（幂等方法）。
- 若持续失败，检查该域名可达性、是否需要加入 DNS 映射或直连白名单。

### 2. 日志文件只有「启动中……」，看不到后续日志

历史缺陷：配置加载会以默认日志目录调用 `set_dir`，此前只重置文件句柄而未重置路径，导致之后日志仅输出到控制台、不再落盘。**已修复**并有回归测试（`util::log::tests::logging_continues_after_set_dir`）。

### 3. 端口被占用

默认 `127.0.0.1:31181`；被占用时可在「加速服务」页修改端口并保存应用。

### 4. 浏览器提示证书错误

需在「安装证书」页安装并信任本地 CA；安装后重启浏览器。

### 5. 关闭代理后仍无法上网

说明系统代理残留：从托盘菜单「退出」应用（会恢复系统代理），或手动关闭系统代理设置。

---

## 开发约定

- 前端样式以内联 `style={{...}}` 与工具类混用为主，主题色走 CSS 变量；组件集中在 `src/components/ui.tsx`。
- 配置页统一使用 `useDraft(section, excludeKeys)` 草稿机制 + `SaveBar`，保存走 `replaceConfig(path, value)`（整段替换，删除的键不复活）。
- Rust 侧错误统一 `anyhow::Result`；日志使用 `log_info!` / `log_warn!` / `log_error!` 宏，勿直接 `println!`。
- 新增 IPC 命令需同时更新 `commands.rs`、`lib.rs` 的 `invoke_handler` 与前端 `src/api.ts` 封装。
- 提交前请确保 `pnpm typecheck`、`cargo test`、`cargo check` 全部通过。

---

## 许可

[MPL-2.0](https://www.mozilla.org/en-US/MPL/2.0/) © dev-sidecar contributors
