import {validateSignature} from './signed-release.js';

export const escapeHTML = value => String(value).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

export function commandsFor(config) {
  const fetch = `curl -fsSL '${config.baseUrl}/script.sh' | sh -s --`;
  const installed = 'sh "$HOME/.conf-sshd/conf-sshd.sh"';
  return [
    {id:'install',title:'部署密钥并设置定期更新',description:`部署当前用户公钥并安装固定客户端；发现旧脚本先备份并保留本地配置。保留已有计划，新计划为 ${config.defaultCron || '*/15 * * * *'}。root 可按需安装 SSH Server 与 cron，非 root 缺少依赖时退出。`,command:`${fetch} --install --download-script -c`},
    {id:'deploy-once',title:'部署一次，不设置定期更新',description:'与原版不带 -c 的用法一致：检查 SSH Server、按权限处理缺失依赖并部署公钥，不新增定时任务。',command:fetch},
    {id:'keys-only',title:'只更新密钥，跳过 SSH Server 检查',description:'单独使用 -o，仅同步当前用户公钥，跳过 SSH Server 检查与软件包配置；不设置定时任务。日常同步优先使用下方已安装的本地脚本。',command:`${fetch} -o`},
    {id:'root-on',title:'允许 root 密码登录并部署密钥',description:'须以 root 执行。设置 PermitRootLogin yes 并部署公钥；其他 SSH 认证设置仍可能限制密码登录，不自动重载服务。',command:`${fetch} -p yes`},
    {id:'help',title:'查看帮助',description:'下载当前脚本并显示参数，不建立信任；执行前仍应检查下载内容。',command:`${fetch} -h`},
    {id:'once',title:'使用本地脚本同步一次',description:'须先安装。使用固定客户端与本地信任设置，仅同步公钥，不检查 SSH Server、不更换脚本或定时计划。',command:`${installed} -o`,advanced:true},
    {id:'preview',title:'预览公钥同步',description:'须先安装。使用本地客户端检查更新并预览将要修改的文件，不应用更新。',command:`${installed} -o --dry-run`,advanced:true},
    {id:'cron-custom',title:'自定义定期更新计划',description:'须先安装。示例每 6 小时同步一次；cron 表达式必须加引号。只管理此脚本自己的计划。',command:`${installed} -c '0 */6 * * *'`,advanced:true},
    {id:'cron-stop',title:'停止定期更新',description:'须先安装。仅移除此脚本的定时计划，保留本地脚本、公钥与信任配置。',command:`${installed} -c false`,advanced:true},
    {id:'skip-sshd-install',title:'跳过 SSH Server 自动安装',description:'使用 -n 跳过 SSH Server 的检查与自动安装，继续部署公钥。需要严格的日常密钥同步时使用 -o。',command:`${fetch} -n`,advanced:true},
    {id:'root-off',title:'禁止 root 密码登录并部署密钥',description:'须先安装并以 root 执行。校验并设置 PermitRootLogin prohibit-password，然后部署公钥；不自动重载服务。',command:`${installed} -p no`,advanced:true},
    {id:'reinstall',title:'更新脚本：明确重新安装',description:'代替原 -u 自更新入口：主动下载并重装，备份旧脚本，保留本地配置与既有计划。首次安装或明确重装都会信任你执行的脚本，推荐先独立核验安装脚本；启用或更换信任须在服务器本地终端确认完整指纹。',command:`${fetch} --install --download-script`,advanced:true},
    {id:'status',title:'查看本地安装状态',description:'须先安装。查看客户端与定时计划状态，不更改配置。',command:`${installed} --status`,advanced:true},
    {id:'uninstall',title:'停止同步并卸载',description:'须先安装。移除脚本及其定时任务，保留公钥与 SSH 配置。',command:`${installed} --uninstall`,advanced:true},
  ];
}

function signingConfigured(config) {
  return Boolean(config.signedRelease || config.clientDefaults?.gpgVerification === 'on');
}

export function pathsFor(config) {
  const baseUrl = config.baseUrl || '';
  return [
    {id:'keys',title:'获取 SSH 公钥',description:'当前公钥文档。开启本地验签后，须与对应独立签名一并核验。',url:`${baseUrl}/ssh.keys`},
    {id:'script',title:'获取 Shell 脚本',description:'显式脚本地址，浏览器与命令行均返回脚本文本。',url:`${baseUrl}/script.sh`},
    {id:'root-script',title:'使用 Curl 获取脚本',description:'兼容原版根地址入口：Curl 默认请求返回 Shell 脚本；显式请求 text/html 时返回首页。',url:`${baseUrl}/`},
    {id:'homepage',title:'使用浏览器访问本页面',description:'同一根地址在浏览器中展示首页，可查看发布状态与复制命令。',url:`${baseUrl}/`},
    ...(signingConfigured(config) ? [{id:'signature',title:'获取公钥文档独立签名',description:'与 /ssh.keys 原始字节配对。当前来源没有可用签名时返回 404，不代表公钥被撤销。',url:`${baseUrl}/ssh.keys.sig`},
    {id:'certificate',title:'获取公开签名证书',description:'配置后提供公开证书，否则返回 404。安装时仍须按独立可信的完整指纹核验。',url:`${baseUrl}/public-key.gpg`}] : []),
  ];
}

function renderPaths(paths) {
  return paths.map(path => `<article class="command-card path-card"><div class="card-heading"><h3>${escapeHTML(path.title)}</h3></div><p class="command-description">${escapeHTML(path.description)}</p>${codeBlock(`path-${path.id}`,path.url,`复制“${path.title}”地址`)}</article>`).join('\n');
}

function codeBlock(id, text, label) {
  return `<div class="code-block"><pre tabindex="0"><code id="${id}">${escapeHTML(text)}</code></pre><button type="button" class="copy-button" data-copy-target="${id}" aria-label="${escapeHTML(label)}" title="${escapeHTML(label)}"></button></div>`;
}
export function renderCommands(commands) {
  const card = command => `<article class="command-card"><div class="card-heading"><h3>${escapeHTML(command.title)}</h3></div><p class="command-description">${escapeHTML(command.description)}</p>${codeBlock(`command-${command.id}`,command.command,`复制“${command.title}”命令`)}</article>`;
  return commands.filter(c=>!c.advanced).map(card).join('\n') + '<details class="advanced-commands"><summary>更多用法与维护</summary><div class="command-list">' + commands.filter(c=>c.advanced).map(card).join('\n') + '</div></details>';
}

/** The homepage projects metadata only. Key material remains confined to the APIs. */
export function renderPage(template, snapshot) {
  const {revision, publishedAt, keys = [], commands = [], testFixture, repositoryUrl, source = {type:'repository'}} = snapshot;
  const unavailable = source.type === 'unavailable' || source.type === 'pending';
  const revoked = source.type === 'explicit-empty' || (!unavailable && snapshot.allowEmpty === true && (snapshot.keyCount ?? keys.length) === 0);
  const sourceLabel = source.type === 'fallback' ? `备用源：${source.url}` : source.type === 'gist' ? `Gist：${source.url || '已配置来源'}` : source.type === 'git' ? `Git：${source.url || '已配置来源'}` : unavailable ? '等待可用公钥源' : 'Git 仓库清单';
  const sourceStatus = source.type === 'pending' ? '待获取' : source.type === 'unavailable' ? '暂不可用' : revoked ? '明确撤销' : source.type === 'fallback' ? '备用源可用' : '可用';
  const notice = unavailable ? '公钥源暂不可用，未发布撤销指令；现有服务器保留上次成功密钥。' : revoked ? '此发布明确撤销全部受管理公钥；客户端仍须按本地信任设置验证，手工公钥与已有会话不受影响。' : source.type === 'fallback' ? '当前使用按配置顺序选中的首个有效备用源；后续请求会重新获取，来源可用不表示客户端已验证。' : '此处仅展示来源与发布元数据；是否接受公钥，由服务器上的客户端按本地信任设置判断。';
  // Presence is distinct from parsed document metadata and from cryptographic trust.
  let signaturePresent = false;
  if (!unavailable) {
    if (typeof snapshot.signatureAvailable === 'boolean') signaturePresent = snapshot.signatureAvailable;
    else if (snapshot.signedDocument && snapshot.keysText === snapshot.signedDocument) {
      try { signaturePresent = Boolean(validateSignature(snapshot.signature)); } catch { /* No usable detached signature. */ }
    }
  }
  const certificatePresent = typeof snapshot.publicCertificateAvailable === 'boolean' ? snapshot.publicCertificateAvailable : typeof snapshot.publicCertificate === 'string' && snapshot.publicCertificate.length > 0;
  const certificateStatus = certificatePresent ? '公开证书已提供（安装时核验）' : '未提供公开证书';
  const signatureEnabled = signingConfigured(snapshot);
  const signatureStatus = signaturePresent ? '签名包已提供（待客户端验证）' : '未提供签名包';
  const keyCount = unavailable ? 0 : (snapshot.keyCount ?? keys.length);
  const publicSource = {type:source.type, ...(source.url ? {url:source.url} : {})};
  const publicData = {schema:2,revision,publishedAt,keyCount,sha256:snapshot.sha256 || null,keyRevision:snapshot.keyRevision || snapshot.sha256 || null,source:publicSource,sourceStatus,signatureEnabled,signaturePresent,signatureStatus,certificatePresent,certificateStatus,repositoryUrl,testFixture:Boolean(testFixture)};
  const replacements = {
    RELEASE_JSON:JSON.stringify(publicData).replace(/</g,'\\u003c').replace(/\u2028/g,'\\u2028').replace(/\u2029/g,'\\u2029'),
    COMMANDS_HTML:renderCommands(commands),PATHS_HTML:renderPaths(pathsFor(snapshot)),REVISION:escapeHTML(revision.slice(0,12)),PUBLISHED_AT:escapeHTML(publishedAt),KEY_COUNT:String(keyCount),
    REPOSITORY_URL:escapeHTML(repositoryUrl),RELEASE_LABEL:testFixture ? '测试预览' : unavailable ? '等待发布源' : '发布元数据',
    PREVIEW_NOTICE:testFixture ? '<p class="preview-notice" role="note">测试预览：这里使用公开测试数据，不能部署到真实服务器。</p>' : '',
    SIGNATURE_SECTION_START:'',SIGNATURE_SECTION_END:'',PATHS_INDEX:signatureEnabled ? '04' : '03',
    VERIFICATION_DEFAULT:snapshot.clientDefaults?.gpgVerification === 'on' ? '本仓库默认开启客户端验签；既有服务器仍按本地已保存的设置执行。' : '客户端验签默认关闭，可在服务器本地明确启用；既有服务器仍按本地已保存的设置执行。',
    CERTIFICATE_LINK:certificatePresent ? '<a class="text-link" href="/public-key.gpg">公开签名证书 <span aria-hidden="true">↗</span></a>' : '',
    SOURCE_LABEL:escapeHTML(sourceLabel),SOURCE_STATUS:escapeHTML(sourceStatus),SIGNATURE_STATUS:escapeHTML(signatureStatus),CERTIFICATE_STATUS:escapeHTML(certificateStatus),CONTENT_REVISION:escapeHTML((snapshot.keyRevision || snapshot.sha256)?.slice(0,12) || '—'),KEYS_NOTICE:escapeHTML(notice),
  };
  if (!signatureEnabled) template = template.replace(/@@SIGNATURE_SECTION_START@@[\s\S]*?@@SIGNATURE_SECTION_END@@/g, '');
  return template.replace(/@@([A-Z_]+)@@/g, (_, token) => {
    if (!Object.hasOwn(replacements, token)) throw Error(`Unresolved page template token: ${token}`);
    return replacements[token];
  });
}
