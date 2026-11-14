# DevSidecar v1.0.0

首个正式版本。Windows x64，基于 Tauri 2 + SolidJS + TypeScript + TailwindCSS + Rust。

## 产物

| 文件 | 用途 |
| --- | --- |
| `DevSidecar_1.0.0_x64-setup.exe` | NSIS 安装包（推荐，支持安装目录选择与卸载） |
| `DevSidecar_1.0.0_x64_en-US.msi` | MSI 安装包（适合企业批量部署） |
| `DevSidecar_1.0.0_x64-portable.exe` | 免安装单文件，直接运行 |

校验值见 `SHA256SUMS.txt`。

## 主要功能

- 本地 HTTP/HTTPS 代理（HTTP 端口 = HTTPS 端口 − 1），支持 CONNECT 隧道、MITM 拦截、WebSocket / Upgrade 透传、HTTP/2。
- DNS 选择与缓存（含 TTL），拦截器规则、白名单、SNI 设置、测速。
- 系统代理接管与还原（注册表写后读回校验 + `WM_SETTINGCHANGE` 广播）。
- NPM / Git / PIP 加速插件，环境变量统一管理。
- 自签 CA 生成与信任，CA bundle 合并系统公共根证书。
- 远程配置下载、主题、托盘、关闭行为（退出 / 最小化 / 每次询问）。

## 1.0 相对 0.1 的关键修复

**代理协议与转发**
- 无正文响应（HEAD / 1xx / 204 / 205 / 304）不再写入 chunked 终止块，避免 keep-alive 连接被帧污染；上游中断不伪造完整响应。
- 重试日志与 `DS-Request-Error` 响应头脱敏，不再泄露 URL 查询串中的 token。

**配置写入事务化（快照 → 写入 → 读回 → 失败回滚）**
- npm：直接解析 `.npmrc` 区分「未设置」与「显式默认值」，修复 Windows 路径反转义问题；`cafile` 不再默认接管，关闭插件不会删除用户已有的企业根证书配置；重新应用时不再覆盖用户的外部修改。
- Git / PIP：新增事务化写入与恢复，多值 Git 配置拒绝自动接管，无快照时仅清理确认属于本应用的项。
- 系统代理与环境变量：改走注册表写入并读回校验（不再使用可能截断的 `setx`）；端点匹配增加边界判断，避免误清用户自有代理。

**CA 与 TLS**
- `cafile` / `SSL_CERT_FILE` / `REQUEST_CA_BUNDLE` 指向「系统公共根 + DevSidecar CA」合并 bundle，不替换公共根；bundle 原子替换、写后复验、7 天 TTL 自动重建。
- `strict-ssl=true` 保持默认，不采用关闭 SSL 校验的规避方案。

**生命周期与恢复**
- 后端单一编排锁串行化启停，前端先调后端、成功后再落配置；停止时等待端口真正释放。
- 运行日志（journal）+ 托管快照双重对账，崩溃后启动自动恢复用户配置，Git / PIP 恢复不依赖 journal。
- 新增「修复残留配置」入口。

**诊断**
- 每请求一行脱敏诊断日志（路由 / 状态码 / 重试 / DNS / 上游 / 总耗时），不记录查询串、Cookie、Authorization、正文。

**界面**
- 关闭询问弹窗「记住我的选择」默认不勾选，且每次弹窗重置。
- 修复 NPM / Git / PIP 插件页「开关」与状态标签不一致：开关改为以运行时状态为唯一来源，后端在插件启停、服务停止、启动恢复时把真实状态回写 `plugin.<name>.enabled`；未勾选「随应用启动」的插件启动后不再残留 `enabled=true`。

## 验收状态

- `cargo test`：54 passed / 0 failed / 2 ignored（ignored 为需外网的真实链路用例）；新增 `tests/plugin_state.rs` 覆盖插件开关一致性回归。
- 真实链路手动验收通过：经代理访问 `login.microsoftonline.com` 200、`registry.npmjs.org/-/ping` 200、`npm view left-pad@1.3.0` 在 `strict-ssl=true` + 合并 CA bundle 下成功。
- `pnpm typecheck`、`pnpm build`、`pnpm tauri build` 通过；exe 版本号 1.0.0。

## 升级与回滚

- 直接覆盖安装即可，用户配置保留在 `%USERPROFILE%\.dev-sidecar\`。
- 升级前建议先在旧版本中关闭加速，使系统代理与环境变量正常还原。
- 若升级后出现网络异常：在应用内关闭加速，或使用「设置 → 修复残留配置」。
