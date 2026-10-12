# Quickly Configuring SSH Server

在 Git 仓库中独立管理服务器 SSH 公钥，通过 Cloudflare Worker 发布，再由服务器定期同步。

- **优先使用本仓库的 `keys/authorized_keys`**；主清单为空时，可按配置顺序读取备用 HTTPS 公钥源。没有默认 GitHub 账号 SSH Keys 来源。
- 网页、脚本与仓库公钥一起构建发布，不再依赖 GitHub Pages；备用公钥独立标记来源和内容摘要。
- 首页支持浅色 / 深色 / 跟随系统、手机与宽屏，以及 GitHub 风格的代码块复制按钮。
- POSIX Shell 客户端只替换自己的密钥管理区块，保留手工密钥；下载或校验失败保留上次成功的内容。

> 仓库初始没有服务器公钥，生产构建会拒绝空清单。先填写你独立管理的服务器**公钥**或显式配置备用源；不要上传私钥，也不要直接拿测试夹具上线。

## Quick Usage

以下地址是部署配置中的示例。Fork 后先修改 `deployment.json`，填写公钥并完成自己的 Worker 部署，再使用自己的域名。执行前建议下载并检查脚本。

安装公钥并设置定时同步：

```sh
curl -fsSL 'https://ssh.lamgc.me/script.sh' | sh -s -- -c
```

新安装默认每 15 分钟同步一次；已有的有效自定义计划会保留。只更新一次：

```sh
curl -fsSL 'https://ssh.lamgc.me/script.sh' | sh -s -- -o
```

预览、帮助与本地状态：

```sh
curl -fsSL 'https://ssh.lamgc.me/script.sh' | sh -s -- -o --dry-run
```

```sh
curl -fsSL 'https://ssh.lamgc.me/script.sh' | sh -s -- -h
```

```sh
sh "$HOME/.conf-sshd/conf-sshd.sh" --status
```

指定计划、取消计划、单独更新已安装脚本：

```sh
sh "$HOME/.conf-sshd/conf-sshd.sh" -c '0 */6 * * *'
```

```sh
sh "$HOME/.conf-sshd/conf-sshd.sh" -c false
```

```sh
sh "$HOME/.conf-sshd/conf-sshd.sh" -u
```

卸载定时同步与脚本，保留密钥及 SSH 服务配置：

```sh
sh "$HOME/.conf-sshd/conf-sshd.sh" --uninstall
```

这些命令用途不同，按需单独执行。网页只提供逐块复制，不把安装、卸载、密码策略合成“执行全部”。

## 公钥清单与发布

将普通 OpenSSH 公钥逐行放入 `keys/authorized_keys`，可附注释和空行。构建会规范化换行与编码，逐条调用 `ssh-keygen` 校验，拒绝重复钥匙、私钥、无效编码和未知行。

支持 ED25519、RSA（至少 2048 位）、ECDSA nistp256/384/521 和 OpenSSH 安全密钥类型。第一版不接受 DSA、证书或 `command=`、`environment=` 等 authorized_keys 选项。私钥应始终保留在你的客户端或安全密钥设备上。

配置文件 `deployment.json`：

- `baseUrl`：Worker 的正式 HTTPS origin，不带路径或末尾斜杠。
- `repositoryUrl`：自己的项目仓库地址。
- `defaultCron`：新安装的默认同步计划，默认 `*/15 * * * *`。
- `allowEmpty`：默认 `false`；明确设为 `true` 时，空主清单表示撤销全部，禁止回退到备用源。
- `fallbackSources`：默认空数组。可填写最多 5 个公开 HTTPS URL，按顺序尝试；不能带凭据、查询参数或片段，不接受请求端传入的地址。

页面展示的是**当前已发布版本**，不是每台服务器的实时同步状态。提交合并后还要等待部署成功；服务器会在下一次成功同步时应用。

### 有序备用源

只有仓库清单为空，且 `allowEmpty` 不是 `true` 时，Worker 才依次读取 `fallbackSources`。取第一个成功且有效的非空公钥集合，不聚合多个源。仓库清单非空始终优先；明确撤销全部时不调用任何备用源。

每个备用源有 3 秒超时（含正文读取）、1 MiB 正文限制、最多 1000 个公钥，并拒绝重定向。非 2xx、空正文、无效 UTF-8、私钥/选项/证书、损坏密钥或重复密钥会跳过并尝试下一个。全部失败时 `/ssh.keys` 和 `/release.json` 返回 503，首页说明暂不可用；客户端保留上次成功的密钥。

不设置 Worker 备用公钥缓存，不使用陈旧内容兜底；每个相关请求重新获取，要求上游也正确提供当前数据。首页的一次响应中，公钥、复制内容、来源、数量与内容摘要来自同一个结果。不同时间请求可能看到备用源的不同版本，因此页面分别显示代码修订与公钥摘要，不能只用 Git 提交号代表动态公钥版本。

撤销备用源公钥取决于上游更新、下一次成功请求和服务器同步周期；这不是即时断开连接的机制。主清单为空、未允许明确撤销且未配置备用源时，生产构建仍会拒绝。

### 明确撤销全部管理密钥

确实需要删除全部受管理密钥时，在同一提交中清空公钥清单，并显式将 `allowEmpty` 改为 `true`。发布与新客户端都会检查数量、版本和内容摘要，只有合法的明确空清单才会清空管理区块。

先确认其他恢复登录方式可用。手工放在管理区块之外的密钥不会删除；同一把钥匙若还存在于其他 authorized_keys 来源，仍可能允许登录。删除密钥也不会终止已有 SSH 会话。

网络故障、错误正文、未知协议或校验失败都会保留本地旧密钥并报错。因此断网时不能保证及时撤权。旧版本客户端不支持明确空清单撤权，应先升级。

### 安全边界

服务器密钥与 GitHub 账号认证密钥相互独立。在仓库里保存公钥不会把它注册为 GitHub 账号登录凭据。

但能修改并发布这个项目的人，以及被配置为备用公钥源的发布者，都能改变使用它的服务器的授权密钥。请保护仓库主分支、CI、Cloudflare 账号和部署权限。HTTPS 保护传输，SHA-256 用于检测截断或版本不一致，**不能抵抗发布源本身被攻陷**。`curl | sh` 仍意味着信任发布的可执行脚本；定时任务只拉公钥，不会自动更新脚本。

## 安装与部署

### 前提

构建环境需要 Node.js 22+、npm、Git、OpenSSH 客户端工具（`ssh-keygen`）及 POSIX `sh`。依赖固定在 `package-lock.json`。

客户端需要 `sh`、`curl`、`ssh-keygen`、`awk`、`mktemp`、`stat` 和常用 Unix 工具，以及 `sha256sum` / `shasum` / `openssl` 之一；设置定时同步还需 `crontab`。请自行安装所需软件。脚本不安装包、不启动或重载服务；`-n` 保留为兼容参数。

目标为 Linux 上的 dash、Bash 的 sh 用法和 BusyBox ash。真实发行版服务管理、SELinux 标签或自定义 `AuthorizedKeysFile` 不应仅凭单元测试视为已验证。默认目标文件是当前用户的 `$HOME/.ssh/authorized_keys`；自定义 SSH 授权路径需要人工核对。

### 一次性配置

1. Fork / 克隆仓库，填入自己的服务器公钥和 `deployment.json`。
2. 按需要修改 `cf-worker/wrangler.toml` 中的 Worker 名称，并为 `baseUrl` 配置 Worker 自定义域名。无需启用 GitHub Pages。
3. 安装依赖、运行检查、构建生产产物：

```sh
npm ci
npm test
npm run build
node scripts/verify-release.mjs
```

4. 在 GitHub 的生产环境中配置最小权限的 Cloudflare 部署 token 和账号 ID，对应 `CLOUDFLARE_API_TOKEN`、`CLOUDFLARE_ACCOUNT_ID`。凭据只存放在 Secrets，不能提交到代码或公钥清单。
5. 准备好正式公钥、域名和权限后，将仓库变量 `ENABLE_WORKER_DEPLOY` 设为 `true`。此后 main 的更新会运行生产发布流程，也可手动触发。

默认关闭自动生产发布，防止合并本次改动时意外上线。PR 验证不会读取部署凭据或发布 Worker。

生产流程先测试和严格构建，再部署，最后核对 `/release.json` 和 `/ssh.keys` 的版本与摘要。没有正式密钥、没有备用源且未显式允许空清单时会失败；不会偷偷改用 GitHub Keys 或测试密钥。

发布脚本、网页、仓库公钥和备用源配置属于同一构建产物；动态备用公钥有单独的内容摘要。若要回滚历史版本，先查看公钥差异：回滚可能重新启用已撤销的密钥。部署失败保留旧发布，但不能把这描述为新密钥已生效。

## Paths

| 路径 | 内容 |
| --- | --- |
| `/` | 浏览器首页；旧 curl/libcurl 请求仍返回脚本（显式请求 HTML 除外） |
| `/script.sh` | Shell 脚本，推荐所有新命令使用这个明确地址 |
| `/ssh.keys` | 带注释元数据的普通公钥文本 |
| `/release.json` | 当前代码版本、有效公钥来源、数量、摘要和空清单状态 |

动态入口不缓存旧数据；带内容哈希的静态 CSS / JS 可以长期缓存。未知路径返回 404，不能用首页 HTML 代替密钥或脚本错误。

## 客户端保护措施

- 所有参数先解析；未知选项、缺参数或冲突用途会报错。
- 下载具有 HTTPS 限制、HTTP 失败检测、超时、有限重试和大小限制。
- 响应包含协议版本、Git revision、密钥数量、明确空清单标记和 SHA-256；所有公钥逐条校验。
- 每个用户独占运行锁；临时文件使用不可预测名称、严格权限和异常清理。
- 只识别唯一且配对的原有 BEGIN / END 管理标记，损坏或重复时停止，避免误吞手工密钥。
- 同目录原子替换，写入前保存一个受限备份；重复执行内容相同时不重写文件。
- 拒绝符号链接、不合适的所有权/写权限和异常文件类型。
- `-c` 只管理自己的 cron 区块；原版已知命令可迁移，无法可靠判断的记录会停止并提示。
- 正常密钥同步不会修改 `sshd_config`，也不会重载 SSH 服务。

如果运行被不可捕获地终止，锁可能残留。先检查 `.conf-sshd/lock/pid` 对应的进程及工作状态，再人工处理锁，不能仅凭锁的年龄删除。

### Root 密码登录（高级）

保留 `-p yes` / `-p no`，必须单独显式使用并以 root 运行。不属于安装/同步默认流程。它只设置 `PermitRootLogin`，不会替你打开其他认证策略。

脚本会检查原配置、生成临时配置、验证语法与生效值、备份后替换，**不会自动 reload/restart**。发现 Include / Match 等无法安全判断的组合时，会拒绝修改并请你人工处理。应用服务变更前应保留恢复会话并测试新连接。

## 从旧版本迁移

1. 先建立独立服务器公钥清单并发布新 Worker；或显式配置备用源；不会自动导入 GitHub 账号公钥。
2. 检查页面公钥、版本和 `/ssh.keys`，确认是你的服务器密钥。
3. 显式更新已安装脚本，或从新的 `/script.sh` 下载并检查后重新运行 `-c`。
4. 验证自定义 cron 仍保留，手工密钥不变，另开 SSH 会话验证登录。

旧客户端对非空的 `/ssh.keys` 仍有基本格式兼容，但不具备新验证、明确空清单撤权与其他保护。不要因为 Worker 更新了就认为所有客户端已升级。

## 开发与测试

```sh
npm ci
npm test
npm run build:test
npx wrangler deploy --dry-run --config cf-worker/wrangler.toml
```

`build:test` 只用于测试/预览，使用公开的 RFC 测试公钥，并在产物中标记 `testFixture: true`。生产验证脚本拒绝该产物；生产构建只使用仓库公钥和显式配置的备用源，不允许回退到测试夹具。

测试覆盖构建配置与注入边界、逐条密钥验证、Worker 路由/缓存、主题/复制交互、Shell 参数/管理区块/失败保留/cron/自更新等。Shell 测试只在临时 HOME、假命令和测试文件中运行，不操作真实 SSH 配置或服务。

`npm run build:test` 之后若要部署正式版本，必须重新执行 `npm run build` 与 `node scripts/verify-release.mjs`。不得直接部署测试产物。

## License

Apache-2.0，见 [LICENSE](LICENSE)。

客户端会检测写入期间可观察到的手工修改并停止；其他编辑器若不遵守同一锁，仍无法保证操作系统级的原子比较并交换。请避免同时手工编辑授权文件。
