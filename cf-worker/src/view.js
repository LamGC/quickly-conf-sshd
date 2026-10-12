export const escapeHTML = value => String(value).replace(/[&<>"']/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));

export function commandsFor(config) {
  const fetch = `curl -fsSL '${config.baseUrl}/script.sh' | sh -s --`;
  return [
    {id:'install',title:'安装并定时同步',description:`更新当前用户的公钥并设置定时同步；保留已有自定义计划，新安装计划为 ${config.defaultCron || '*/15 * * * *'}。`,command:`${fetch} -c`},
    {id:'once',title:'仅更新一次公钥',description:'更新为当前发布的公钥，不设置定时任务。',command:`${fetch} -o`},
    {id:'help',title:'查看帮助',description:'先了解全部参数与行为，不修改配置。',command:`${fetch} -h`},
    {id:'preview',title:'预览公钥更新',description:'校验当前发布并预览将要修改的文件，不应用更新。',command:`${fetch} -o --dry-run`},
    {id:'update',title:'单独更新已安装脚本',description:'显式更新客户端脚本；定时公钥同步不会更新可执行代码。',command:'sh "$HOME/.conf-sshd/conf-sshd.sh" -u',advanced:true},
    {id:'root-off',title:'禁止 root 使用密码登录',description:'仅 root 可执行。校验并修改 SSH 配置，不自动重载服务。',command:`${fetch} -p no`,advanced:true},
    {id:'root-on',title:'允许 root 使用密码登录',description:'仅 root 可执行，涉及登录安全；实际登录仍受其他 SSH 认证设置限制，不自动重载服务。',command:`${fetch} -p yes`,advanced:true},
    {id:'uninstall',title:'停止同步并卸载',description:'移除脚本及其定时任务，保留公钥与 SSH 配置。',command:'sh "$HOME/.conf-sshd/conf-sshd.sh" --uninstall',advanced:true},
  ];
}

function codeBlock(id, text, label) {
  return `<div class="code-block"><pre tabindex="0"><code id="${id}">${escapeHTML(text)}</code></pre><button type="button" class="copy-button" data-copy-target="${id}" aria-label="${escapeHTML(label)}" title="${escapeHTML(label)}"></button></div>`;
}
export function renderKeys(keys) {
  return keys.length ? keys.map((key,i) => `<article class="key-card"><div class="card-heading"><h3>${escapeHTML(key.label)}</h3><span class="key-type">${escapeHTML(key.type)}</span></div><p class="fingerprint">${escapeHTML(key.fingerprint)}</p>${codeBlock(`key-${i}`,key.text,`复制第 ${i + 1} 个公钥`)}</article>`).join('\n') : '<p class="empty-state">此版本明确撤销全部受管理公钥，手工管理的公钥仍保留。</p>';
}
export function renderCommands(commands) {
  const card = command => `<article class="command-card"><div class="card-heading"><h3>${escapeHTML(command.title)}</h3></div><p class="command-description">${escapeHTML(command.description)}</p>${codeBlock(`command-${command.id}`,command.command,`复制“${command.title}”命令`)}</article>`;
  return commands.filter(c=>!c.advanced).map(card).join('\n') + '<details class="advanced-commands"><summary>高级命令</summary><div class="command-list">' + commands.filter(c=>c.advanced).map(card).join('\n') + '</div></details>';
}


/** All visible keys/metadata and clipboard data come from one resolved response snapshot. */
export function renderPage(template, snapshot) {
  const {revision, publishedAt, keys = [], commands = [], testFixture, repositoryUrl, source = {type:'repository'}} = snapshot;
  const unavailable = source.type === 'unavailable' || source.type === 'pending';
  const sourceLabel = source.type === 'fallback' ? `备用源：${source.url}` : source.type === 'explicit-empty' ? '仓库清单（明确撤销）' : unavailable ? '等待可用公钥源' : '仓库清单';
  const sourceStatus = source.type === 'fallback' ? '备用源可用' : source.type === 'explicit-empty' ? '明确撤销' : unavailable ? '暂不可用' : '可用';
  const notice = unavailable ? '公钥源暂不可用，未发布撤销指令；现有服务器保留上次成功密钥。' : source.type === 'fallback' ? '当前使用按配置顺序选中的首个有效备用源；后续请求会重新获取。' : source.type === 'explicit-empty' ? '此版本明确撤销全部受管理公钥；手工公钥与已有会话不受影响。' : '';
  const publicData = {schema:1,revision,publishedAt,keyCount:keys.length,sha256:snapshot.sha256 || null,keyRevision:snapshot.sha256 || null,source,sourceStatus,keys,commands,baseUrl:snapshot.baseUrl,repositoryUrl,testFixture:Boolean(testFixture)};
  const replacements = {
    RELEASE_JSON:JSON.stringify(publicData).replace(/</g,'\\u003c').replace(/\u2028/g,'\\u2028').replace(/\u2029/g,'\\u2029'),
    KEYS_HTML:unavailable ? '<p class="empty-state">当前无法获取有效公钥。请稍后重试或检查备用源配置。</p>' : renderKeys(keys),
    COMMANDS_HTML:renderCommands(commands),REVISION:escapeHTML(revision.slice(0,12)),PUBLISHED_AT:escapeHTML(publishedAt),KEY_COUNT:String(keys.length),
    REPOSITORY_URL:escapeHTML(repositoryUrl),RELEASE_LABEL:testFixture ? '测试预览' : unavailable ? '公钥暂不可用' : '已发布',
    PREVIEW_NOTICE:testFixture ? '<p class="preview-notice" role="note">测试预览：这里使用公开测试密钥，不能部署到真实服务器。</p>' : '',
    SOURCE_LABEL:escapeHTML(sourceLabel),SOURCE_STATUS:escapeHTML(sourceStatus),CONTENT_REVISION:escapeHTML(snapshot.sha256?.slice(0,12) || '—'),KEYS_NOTICE:escapeHTML(notice),
  };
  return template.replace(/@@([A-Z_]+)@@/g, (_, token) => {
    if (!Object.hasOwn(replacements, token)) throw Error(`Unresolved page template token: ${token}`);
    return replacements[token];
  });
}
