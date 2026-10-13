import {validateSignature} from './signed-release.js';

export const escapeHTML = value => String(value).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

export function commandsFor(config) {
  const fetch = `curl -fsSL '${config.baseUrl}/script.sh' | sh -s --`;
  const installed = 'sh "$HOME/.conf-sshd/conf-sshd.sh"';
  return [
    {id:'install',title:'安装或重新安装',description:`下载并安装客户端，再同步公钥与设置计划；发现旧版本时先备份并保留本地配置。保留已有计划，新安装计划为 ${config.defaultCron || '*/15 * * * *'}。首次安装或明确重装都会信任你执行的脚本，推荐先独立核验安装脚本；启用或更换信任须在服务器本地终端确认完整指纹。`,command:`${fetch} --install --download-script -c`},
    {id:'once',title:'同步一次公钥',description:'使用已安装的固定脚本与本地信任设置同步公钥，不更换脚本或定时计划。',command:`${installed} -o`},
    {id:'help',title:'查看帮助',description:'下载当前脚本并显示参数，不建立信任；执行前仍应检查下载内容。',command:`${fetch} -h`},
    {id:'preview',title:'预览公钥同步',description:'使用已安装的脚本与本地信任设置检查更新，预览将要修改的文件，不应用更新。',command:`${installed} -o --dry-run`},
    {id:'root-off',title:'禁止 root 使用密码登录',description:'仅 root 可执行。使用已安装的脚本校验并修改 SSH 配置，不自动重载服务。',command:`${installed} -p no`,advanced:true},
    {id:'root-on',title:'允许 root 使用密码登录',description:'仅 root 可执行，涉及登录安全；实际登录仍受其他 SSH 认证设置限制，不自动重载服务。',command:`${installed} -p yes`,advanced:true},
    {id:'uninstall',title:'停止同步并卸载',description:'移除脚本及其定时任务，保留公钥与 SSH 配置。',command:`${installed} --uninstall`,advanced:true},
  ];
}

function codeBlock(id, text, label) {
  return `<div class="code-block"><pre tabindex="0"><code id="${id}">${escapeHTML(text)}</code></pre><button type="button" class="copy-button" data-copy-target="${id}" aria-label="${escapeHTML(label)}" title="${escapeHTML(label)}"></button></div>`;
}
export function renderCommands(commands) {
  const card = command => `<article class="command-card"><div class="card-heading"><h3>${escapeHTML(command.title)}</h3></div><p class="command-description">${escapeHTML(command.description)}</p>${codeBlock(`command-${command.id}`,command.command,`复制“${command.title}”命令`)}</article>`;
  return commands.filter(c=>!c.advanced).map(card).join('\n') + '<details class="advanced-commands"><summary>高级命令</summary><div class="command-list">' + commands.filter(c=>c.advanced).map(card).join('\n') + '</div></details>';
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
  const signatureStatus = signaturePresent ? '签名包已提供（待客户端验证）' : '未提供签名包';
  const keyCount = unavailable ? 0 : (snapshot.keyCount ?? keys.length);
  const publicSource = {type:source.type, ...(source.url ? {url:source.url} : {})};
  const publicData = {schema:2,revision,publishedAt,keyCount,sha256:snapshot.sha256 || null,keyRevision:snapshot.keyRevision || snapshot.sha256 || null,source:publicSource,sourceStatus,signaturePresent,signatureStatus,certificatePresent,certificateStatus,repositoryUrl,testFixture:Boolean(testFixture)};
  const replacements = {
    RELEASE_JSON:JSON.stringify(publicData).replace(/</g,'\\u003c').replace(/\u2028/g,'\\u2028').replace(/\u2029/g,'\\u2029'),
    COMMANDS_HTML:renderCommands(commands),REVISION:escapeHTML(revision.slice(0,12)),PUBLISHED_AT:escapeHTML(publishedAt),KEY_COUNT:String(keyCount),
    REPOSITORY_URL:escapeHTML(repositoryUrl),RELEASE_LABEL:testFixture ? '测试预览' : unavailable ? '等待发布源' : '发布元数据',
    PREVIEW_NOTICE:testFixture ? '<p class="preview-notice" role="note">测试预览：这里使用公开测试数据，不能部署到真实服务器。</p>' : '',
    CERTIFICATE_LINK:certificatePresent ? '<a class="text-link" href="/public-key.gpg">公开签名证书 <span aria-hidden="true">↗</span></a>' : '',
    SOURCE_LABEL:escapeHTML(sourceLabel),SOURCE_STATUS:escapeHTML(sourceStatus),SIGNATURE_STATUS:escapeHTML(signatureStatus),CERTIFICATE_STATUS:escapeHTML(certificateStatus),CONTENT_REVISION:escapeHTML((snapshot.keyRevision || snapshot.sha256)?.slice(0,12) || '—'),KEYS_NOTICE:escapeHTML(notice),
  };
  return template.replace(/@@([A-Z_]+)@@/g, (_, token) => {
    if (!Object.hasOwn(replacements, token)) throw Error(`Unresolved page template token: ${token}`);
    return replacements[token];
  });
}
