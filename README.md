# Quickly Configuring SSH Server

在 Git 仓库或指定账号的 Gist 中独立管理服务器 SSH 公钥，通过同一个 Cloudflare Worker 发布网页、脚本、公钥清单、签名和公钥证书。

- 不默认读取 GitHub 账号的 SSH 登录钥匙，不依赖独立 GitHub Pages 部署。
- 普通模式仅校验公钥格式；可选高信任模式由**服务器脚本**验证 GPG 签名，Worker 无法远程关闭它。
- 脚本落盘后固定，定时任务只同步公钥。升级、修改信任指纹或关闭验签需要显式重新安装。
- 首页有浅色 / 深色 / 系统主题、响应式布局和逐条命令复制；不显示或内嵌公钥正文、指纹、个人注释。

> 初始生产清单和备用源为空，没有配置实际签名证书或发布凭据。生产构建不会偷偷使用测试密钥。仓库中的公钥文件不是 GitHub 账号登录凭据。

## Quick Usage 与重新安装

先配置并部署自己的 Worker，再使用自己的域名。以下地址只是本项目的部署配置示例。

普通 HTTPS 安装 / 显式重新安装并启用定时同步：

```sh
curl -fsSL 'https://ssh.lamgc.me/script.sh' | sh -s -- --install --download-script -c
```

再次执行安装命令会检测已安装脚本，备份并升级。签名策略只在已替换旧客户端之后激活；若后续磁盘写入失败，可能留下新脚本和未完成的配置，请按错误信息检查并显式重新安装，不要把失败当作策略已启用。已有本地配置和自定义定时计划默认保留，不因远端仓库默认值变化而重置。新安装默认每 15 分钟同步。

**这条命令信任下载到的可执行脚本。** HTTPS、同一 Worker 提供的摘要和后续公钥验签，不能证明首次安装器本身可信。高信任安装应先取得独立渠道核对过的脚本摘要和完整 GPG 指纹，下载、核验本地文件后执行安装。不要把从同一被攻陷来源获得的指纹当作独立信任依据。

原版 Quick Usage 的一次部署、只安装钥匙、root 策略与帮助入口继续保留。普通运行会按权限检查 SSH Server；root 缺少服务端时可按需安装，非 root 不安装系统包。`-n` 跳过服务端检查/安装，`-o` 只处理当前用户的钥匙，不配置 SSH 服务。

一次部署，不设置定时任务：

```sh
curl -fsSL 'https://ssh.lamgc.me/' | sh -s
```

跳过 SSH Server 检查，只安装钥匙：

```sh
curl -fsSL 'https://ssh.lamgc.me/' | sh -s -- -o
```

显式设置 root 登录策略并部署钥匙（必须以 root 执行，可再加 `-c`）：

```sh
curl -fsSL 'https://ssh.lamgc.me/' | sh -s -- -p yes
```

`-p yes` 仅设置 `PermitRootLogin yes`，不额外打开 `PasswordAuthentication`。使用 `-p no` 设置 `prohibit-password`。会先验证钥匙、备份和校验配置；不会自动重载 SSH 服务，请保留恢复会话并按输出手动检查。

日常同步、预览、状态使用已经落盘的脚本：

```sh
sh "$HOME/.conf-sshd/conf-sshd.sh" -o
```

```sh
sh "$HOME/.conf-sshd/conf-sshd.sh" -o --dry-run
```

```sh
sh "$HOME/.conf-sshd/conf-sshd.sh" --status
```

查看完整参数，不修改配置：

```sh
curl -fsSL 'https://ssh.lamgc.me/script.sh' | sh -s -- -h
```

指定 / 取消自己的定时计划：

```sh
sh "$HOME/.conf-sshd/conf-sshd.sh" -c '0 */6 * * *'
```

```sh
sh "$HOME/.conf-sshd/conf-sshd.sh" -c false
```

```sh
sh "$HOME/.conf-sshd/conf-sshd.sh" --uninstall
```

卸载保留授权密钥、SSH 服务配置、本地信任配置与防回滚状态。`-u` 不再下载或替换脚本，会提示显式重新安装。没有自动更新周期；延长更新周期本身也不是安全验证。

## Git / Gist 管理模式

### Git

`keySource.type` 为 `git`（默认）。普通公钥逐行放入 `keys/authorized_keys`；构建校验并去掉所有注释，再发布。若注释曾提交公开仓库，它仍可能存在于历史中，因此发布前也应从源文件去掉个人信息。

支持 ED25519、RSA（2048–16384 位）、ECDSA nistp256/384/521 和 OpenSSH 安全密钥格式。不接受 DSA、SSH 证书、`command=` 等 authorized_keys 选项、重复公钥或私钥。

签名发布使用精确签名文档和 detached ASCII-armored GPG 签名。两者与网页、脚本一同构建，作为同一 Worker 发布产物交付；不会在发布后重新生成签名正文。

在持有签名私钥的可信电脑上，先生成新的文档（序号必须递增，时间自行选择）：

```sh
node scripts/prepare-key-release.mjs --input keys/authorized_keys --output keys/ssh.keys --list-id my-servers --sequence 1 --issued-at 1791856800 --expires-at 1794448800
```

上例时间仅展示参数格式，不应照抄为正式有效期。工具会拒绝覆盖已有文件；更新时先保留旧版并明确选择新输出，再审阅替换。清空发布必须使用空输入并加 `--revoke`。

审核精确文档后，使用你自己的授权签名钥匙手动签名：

```sh
gpg --armor --detach-sign --local-user FULL_PRIMARY_FINGERPRINT --output keys/ssh.keys.sig keys/ssh.keys
```

`FULL_PRIMARY_FINGERPRINT` 必须替换为独立核对的完整指纹；GPG 可选择该主钥的签名子钥。不要上传私钥，也不要在 Actions 中自动运行签名步骤。上传的 `ssh.keys` 与 `ssh.keys.sig` 必须保持原始字节；Gist 使用同样文件即可。Git 也可使用工具打包的 `keys/release.bundle`，但不能与 `keys/ssh.keys` 同时存在。


### Gist

配置固定的 Gist ID、账号数字 `ownerId`、显示用 `ownerLogin` 和文件名。Worker 通过 GitHub REST API 核对所属账号，取得当前修订后，再从那个固定修订读取公钥与签名。不能仅靠 URL 中的用户名判断所属，也不能从任意请求参数传入 Gist/上游地址。

公开 Gist 无需读取 token；仅使用明确配置的文件，不跟随 API 返回的任意 raw URL。缺失文件、截断响应、owner 不匹配、超时或非 200 均视为来源失败。

同一 Gist 同时含 `release.bundle` 与拆分文件时，bundle 优先；切换到拆分文件前应明确移除旧 bundle，避免持续发布旧内容。`ownerLogin` 只是显示信息，数字 owner ID 才是身份固定值。

更新签名文档后必须重新签名。Worker 不持有签名私钥，不会为 Gist 的任意修改自动背书。普通模式可以发布无签名清单；客户端是否验签由其本地策略决定。

Gist 配置示例（将 ID 与账号数字 ID 替换为经过核对的真实值）：

```json
{"keySource":{"type":"gist","id":"0123456789abcdef0123456789abcdef","ownerId":123456,"ownerLogin":"example","file":"ssh.keys","signatureFile":"ssh.keys.sig","bundleFile":"release.bundle"}}
```

### 可见性

网页不嵌入密钥，不代表数据保密。`/ssh.keys` 可公开读取，公开 Git/Gist 和历史也可访问；去掉注释后，相同公钥字节仍能被关联。私钥始终留在使用者或可信签名端，不能上传本项目、Worker、Actions 或 Gist。

## 客户端 GPG 验证（默认 OFF）

- **OFF**：只下载 `/ssh.keys`，校验协议、公钥格式和明确空清单；不请求 `/ssh.keys.sig` 或 `/public-key.gpg`，即使它们存在也不验签。
- **ON**：取得 `/ssh.keys` 原始字节和同源 `/ssh.keys.sig`，用安装时固定的专用本地钥匙环验证。HTTP 下载每次都必须是 200；404、其他状态、重定向、下载失败、证书指纹不符或验签失败均拒绝该更新。绝不自动回退为 OFF。
- 验签覆盖完整响应，包括元数据、换行和公钥正文。不能先去注释、重新排序或转换编码再验签。
- 本地记录完整 40 位 OpenPGP v4 指纹，不接受短 key ID。`primary` 模式接受该主密钥及经 GPG 验证绑定的有效签名子钥；`subkey` 只接受指定签名子钥，不接受同主钥的其他子钥。主钥下后来新增的签名子钥仍需通过显式重新安装更新本地证书；固定指纹不会自动下载最新子钥集合。
- 日常验证使用隔离的专用本地 GPG keyring，不信任用户默认钥匙环，也不自动访问 keyserver；网络返回的其他钥匙不能扩大本地授权。

仓库可设置新安装默认值，安装时可显式覆盖。**已安装机器的本地配置优先**，之后改仓库默认值不能关闭它的验证。开启验证、换指纹/信任范围或关闭已有验证都必须显示具体信息并取得本地明确确认；取消或无法确认时不应用修改。

安装在本地明确确认后依序寻找对应证书：已有本地证书、Worker `/public-key.gpg`、可选 Email 的 WKD、配置的有序 keyserver。每一步仍必须匹配完整指纹；没有 Email 时跳过 WKD；内置有序服务器为 `hkps://keys.openpgp.org`、`hkps://keyserver.ubuntu.com`，允许显式覆盖。它们只是证书分发源，不是信任根；缺少 UID、无法导入或不支持指定子钥查询时继续下一源，绝不缩短指纹。全部失败则保留现有配置并停止。通过验证的公共证书保存到专用本地钥匙环。仓库默认 Email 会写入公开安装脚本，只应填写愿意公开的邮箱；它只是发现提示，不能取代指纹。

公钥证书可公开分发，信任来自独立核对并固定的完整指纹。证书内容即使具有相同主指纹，也未必是最新撤销状态：恶意分发端可能重放旧证书、隐瞒新撤销。客户端检查收到的证书中已有的过期/撤销信息，但不能保证及时获知被隐瞒的撤销。复用本地证书也不会自动获知之后的撤销。重新安装仍优先使用有效的本地证书；若需更新同指纹证书，显式提供从可信渠道取得的新公共证书，再核对其撤销/子钥状态。

完整指纹和 Email 可在 `clientDefaults` 设置，也可显式安装覆盖。例如先独立核验已下载的本地脚本，再执行：

```sh
sh ./conf-sshd.sh --install -c --gpg-verification on --gpg-fingerprint FULL40HEX --gpg-pin-mode primary --list-id my-servers --gpg-email signer@example.com
```

占位指纹必须替换为真实完整指纹；Email 可省略。安装会在本地终端要求输入展示的完整指纹确认，没有静默确认参数。关闭已有验证使用显式重新安装加 `--gpg-verification off`，同样需要终端确认。重新安装可用 `--fallback-urls-file` 指定按行排列的备用文档 URL；`--keyserver` 可重复覆盖内置列表，原有设置默认保留。

### 签名文档、防回滚与故障

列表 ID 使用 1–64 个字母、数字、点、下划线或连字符，单独的 `-` 保留给本地未配置状态，不能作为列表名。

签名文档使用固定 LF 格式：协议标记、列表 ID、单调递增序号、签发/到期 Unix 秒、明确撤销标志、数量、结束标记，以及无注释的规范公钥正文。签名覆盖精确全部字节。

ON 客户端检查固定列表 ID、有效期和持久化的最高序号/摘要。低序号拒绝；同序号只接受同一文档；明确撤销也必须签名并增加序号。首次安装的最低序号应通过可信渠道确定，否则仅有指纹不能排除有效期内的旧发布。

更新使用锁、待提交记录、快照检查和原子替换来处理进程中断。待提交发布已过期时不会强行应用，保留其序号下限后允许有效的新发布继续；损坏且无法可信恢复的状态会停止并提示人工检查。不要删除或恢复旧版本的本地防回滚状态；整机快照回滚、本地管理员篡改或底层文件系统掉电持久性不由一个 POSIX 脚本保证。

下载/验签失败或清单过期会保留最后成功的密钥并报错，**不会自动清空密钥造成锁死**。攻击者仍可阻断更新；离线机器无法保证及时撤权。删除公钥不会终止已有会话，也不会移除管理区块外的手工重复钥匙。部署签名私钥或服务器本地管理员权限失陷超出这层保护范围。

### 服务器本地验签审计

仅在本地验签为 ON 时，成功更新会把 `/ssh.keys` 原始响应与配套 `/ssh.keys.sig` 原始签名保存到 `$HOME/.conf-sshd/audit/`。这是实际签名覆盖的完整文档，不是去掉元数据后写入 authorized_keys 的管理区块。

- `current` 是严格格式的当前记录指针，指向 `a` 或 `b` 槽；槽内有 `ssh.keys`、`ssh.keys.sig` 和 `metadata`。两槽轮替，保留当前与上一份证据，不会随每次 cron 无限增长。
- metadata 记录成功安装时间、列表 ID、序号、来源、实际签名主/子钥完整指纹、本地固定的指纹和模式、文档及签名摘要、客户端格式版本。它是本地辅助信息，不是额外签名的远端证明。
- 下载或验签失败不覆盖当前成功证据。钥匙、回滚状态与审计指针无法跨文件一次性 rename；提交中断会保留恢复 journal，并且可能暂时没有 current 指针。没有 current 时，不应把任一槽猜作当前已安装证据；先检查错误并用同一固定客户端完成恢复。
- OFF 不额外下载或保存签名；成功执行 OFF 更新会取消旧记录的 current 标记，旧证据仅作历史。仅改远端默认值不会关闭本地 ON。
- 审计目录权限为 0700，文件为 0600；可结合本地固定证书离线复核签名。它不能防止服务器 root 篡改、删除证据，也不能证明包安装副作用、SSH 当前会话或整机快照未被回滚。

## 有序备用源

有两份有意区分的配置：

1. Worker 部署的 `fallbackSources`：主来源不可用或普通主清单为空时，按顺序取首个有效集合，不合并多个来源。明确撤销阻止回退。
2. 每台服务器本地保存的备用 URL：主 Worker 更新失败时，按本地顺序尝试，最多一个主源加五个备用源。每个端点单次请求最多 30 秒；由后续源或下次计划同步重试。只通过显式安装配置改变，远端响应不能覆盖。

服务器本地备用 URL 必须返回本项目 v1 或 signed-v1 文档；普通原始公钥文件可通过 Worker 来源适配器发布。客户端 ON 时，备用 URL 和对应 `.sig` 必须满足相同指纹、列表 ID、签名、时效和防回滚策略。不能用另一来源的签名拼接，更不能在失败后接受未签名公钥。Worker 不能替未签名备用源伪造可信签名。

Worker 上游请求有时间、流式字节数、数量限制，并拒绝重定向。没有 Worker 陈旧公钥缓存，每个相关请求重新读取；API 响应 `Cache-Control: no-store`。Gist 的正文与签名取自同一修订。客户端两次 HTTP 请求之间若恰逢新发布，签名不匹配会安全拒绝，后续同步再重试。

## 配置与部署

`deployment.json`：

- `baseUrl`：正式 HTTPS origin，无路径、凭据或末尾斜杠。
- `repositoryUrl`：项目 GitHub 地址。
- `defaultCron`：新安装默认计划。
- `allowEmpty`：普通 Git 模式明确允许撤销全部管理密钥；默认 false。
- `fallbackSources`：最多五个公开 HTTPS URL，不含凭据、query、fragment 或本地/IP 地址。
- `keySource`：Git 或固定账号 Gist 配置。
- `signedRelease`：签名列表身份和可公开发布的证书配置；不是私钥。
- `clientDefaults`：首次安装的验签默认值、完整指纹、primary/subkey 范围、列表 ID 和可选公开 Email；不覆盖现有本地设置。

构建需要 Node.js 22+、npm、Git、OpenSSH 客户端和 POSIX sh；GPG 验证/测试需要 `gpg`。服务器需要 curl、ssh-keygen、awk、mktemp、stat、常用 POSIX 工具及 sha256sum/shasum/openssl 之一，ON 还需要 gpg；计划任务需要 crontab。普通部署可由 root 按需安装 openssh-server，以及启用计划时缺少的 cron/crontabs；支持的包管理器为 apt-get、dnf、yum。已有 sshd 配置无效不当作缺少软件重装。非 root 不安装系统包，缺少 ssh-keygen 时，正常 root 部署可在完成信任确认后先安装客户端工具以便验钥；`-o`、`-n` 和非 root 路径不会这样安装，其他工具仍须预先准备。

```sh
npm ci
npm test
npm run build
node scripts/verify-release.mjs
```

正式上线前配置自己的域名、Worker 名称、正式公钥/签名和最小权限 Cloudflare Secrets。将仓库 `ENABLE_WORKER_DEPLOY=true` 才启用 main 发布；默认关闭。PR 测试不部署。

### 可选 Git 提交签名门禁

`REQUIRE_GPG_SIGNATURE=true` 时，发布验证任务先验证本次精确 `GITHUB_SHA`，然后才执行依赖安装、测试和构建。授权完整主指纹和公钥从 GitHub 设置中的 `GPG_ALLOWED_PRIMARY_FINGERPRINTS`、`GPG_PUBLIC_KEYS` 读取，而不是让待部署提交自行指定。

GitHub 的通用 Verified 标记不是本项目授权名单。最终 merge/squash 提交必须由授权 GPG 钥匙签署；仅 PR 内旧提交签名不够。手动发布也不能绕过同一验证。

**这是附加门禁，不能替代服务器验签。** 同仓库 workflow/验证器可被有权限者修改，需配合主分支与工作流强制审阅、受保护 production 环境和最小权限凭据。能修改验证工作流并访问发布凭据的人仍在信任边界内。

### 可选部署邮件通知 hook

默认关闭。通过 `ENABLE_MAIL_NOTIFICATION`、`MAIL_NOTIFICATION_WEBHOOK` 和可选 `MAIL_NOTIFICATION_TO` 接入你控制的邮件提供方 webhook；本项目不内置 SMTP 服务，也不会自行创建凭据。

通知说明部署结果、代码 SHA、来源模式、列表身份和**部署配置中的**备用 URL。它不是服务器清单，不知道各机器后来修改的本地备用源，也不是每次 Gist 内容变更的监视器。通知失败或被压制不能当作部署未发生/系统安全的证明。

## API

| 路径 | 内容 |
| --- | --- |
| `/` | 浏览器首页；curl/libcurl/wget/HTTPie 返回脚本，显式 HTML 优先 |
| `/script.sh` | 安装脚本 |
| `/ssh.keys` | 精确公钥文档；签名存在时就是被签名的原始字节 |
| `/ssh.keys.sig` | 对上述文档的 detached GPG 签名；没有可用签名时 404 |
| `/public-key.gpg` | 配置的公共 GPG 证书；未配置时 404 |
| `/release.json` | 来源、数量、摘要、代码修订及签名是否提供；不表示服务器已验签 |

脚本、Git 公钥/签名与网站一起构建发布；不需要额外 Pages。动态 Gist/备用数据的序号和摘要与代码修订分别表示。静态 CSS/JS 使用内容哈希缓存，未知接口返回 404，不返回 HTML 冒充密钥。

## 从旧版迁移

1. 保留恢复会话和备用登录方式，先核对独立服务器清单。
2. 显式重新安装新版脚本，检查本地配置、自定义计划、管理区块和手工钥匙。
3. 逐台核对脚本版本、完整指纹、验证模式、列表 ID 和序号；等待一段时间不是所有服务器升级完成的证据。
4. 再切换新的签名文档格式并按确认流程启用 ON。新版 OFF 可以解析新文档但不验签；旧 v1 客户端会拒绝新格式并保留旧钥匙，不能把它视为已得到保护。
5. 另开 SSH 会话验证登录。回滚旧 Worker 可能重新发布历史钥匙；ON 客户端有序号防回滚，但不要依赖普通模式抵抗历史重放。

## 客户端操作边界

仅操作当前用户 `$HOME/.ssh/authorized_keys` 的唯一配对管理区块。临时文件、锁、备份、同目录替换和写前快照检查避免可观察到的并发覆盖；不同编辑器不共享锁时仍无操作系统级原子比较交换保证。

`-p yes/no` 是显式 root 操作，可与普通部署、`--install`、`-c` 组合，不能与只更新钥匙的 `-o` 组合。只修改 PermitRootLogin，先验证公钥，再备份和验证 `sshd -t/-T`，最后替换配置；不改 PasswordAuthentication，不主动 reload/restart。默认部署不会改变登录策略。

支持没有 Include/Match 的简单配置，以及仅包含标准 `Include /etc/ssh/sshd_config.d/*.conf`（或相对路径 `sshd_config.d/*.conf`）的配置。标准目录及文件必须安全、可读取，目录清单和文件内容在提交前复查。主文件或包含文件出现 Match、嵌套 Include，或其他 Include 写法时明确拒绝自动改策略，交由管理员检查；不会声称几个模拟连接就覆盖所有条件规则。

普通部署会区分缺少 sshd 程序与现有配置无效。root 可按需安装 openssh-server，`-c` 时可按需安装 cron/crontabs；`-n` 跳过服务端检查/安装，`-o` 不执行这类系统操作。脚本不会主动执行服务 reload/restart，但发行版软件包的安装钩子可能启动服务或生成主机密钥。包安装不是可整体回滚的事务；后续失败会报告，已有钥匙和策略在验证前不改写。

目标为 Linux dash、Bash POSIX 与 BusyBox ash。测试不等于真实服务器登录、SELinux、发行版服务管理或自定义 AuthorizedKeysFile 已验证。异常强制终止可能留下锁，人工确认原进程状态后再处理。

## 测试

```sh
npm test
npm run build:test
npx wrangler deploy --dry-run --config cf-worker/wrangler.toml
```

测试只使用临时 HOME、命令替身、公开测试 SSH 钥匙及临时无身份/无访问权限的 GPG 测试钥匙。真实浏览器测试仅访问 localhost。`build:test` 产物标记为测试，生产验证拒绝它；上线必须重新生产构建。

### 真实 WKD / HKPS 集成测试

CI 的 `Live public GPG discovery (external network)` 是独立任务，与 `npm test` 中不访问外部密钥服务的核心测试分开。它使用真实 GnuPG/dirmngr，在全新的临时钥匙环中通过 WKD、keys.openpgp.org 和 keyserver.ubuntu.com 发现公共证书，再用实际客户端的证书检查函数验证完整主指纹和指定签名子钥；不执行安装器、不改系统信任、不安装 SSH 服务。

`tests/fixtures/live-discovery.json` 是**仅用于测试的固定公开身份**。Fork 或部署本项目时不应把它改成自己的邮箱/指纹；生产配置只修改 `deployment.json` 与 `keys/`。测试身份不作为服务器 SSH 授权密钥，也不会写入生成的安装默认值。只有维护集成测试本身（例如测试证书到期）时才需要更换此夹具。

每个来源有独立的结果、有限超时与重试；网络/服务不可用和证书验证失败会明确报告并使该任务失败，不会静默跳过后标为通过。CI 摘要只保留来源、固定指纹与结果，不上传证书或其他 UID 信息。没有该身份签署的 SSH 公钥文档，因此此测试不声称完成了用户真实业务文档验签；签名验签和错误场景仍由隔离的临时测试钥匙覆盖。

可显式运行同一外网测试：

```sh
node scripts/test-live-discovery.mjs
```

运行需要允许 dirmngr 创建本地 socket 并访问这些 HTTPS/HKPS 服务。受限环境中仅 HTTP 下载成功不代表 GPG 发现流程通过。

## License

Apache-2.0，见 [LICENSE](LICENSE)。
