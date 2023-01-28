// 改成你自己的 Github 用户名，注意是登录 Github 的那个用户名.
const githubUserName = "LamGC";
// 改成你 Fork 后的仓库名，记得要开启 Github Pages 功能.
const githubInstSshProjectName = "quickly-conf-sshd";
// 如果可以，建议在此设置备用的 SSH 公钥, 以防 Github 无法使用.
const backupSshKeys = ``;
// Worker 的访问地址, 如果不填的话默认为请求的地址, 填了就会用这里的地址(要去 Worker 的触发器那绑定, 否则无效).
const defaultBaseUrl = "";
// Cron 表达式, 默认 1 天执行一次更新.
const cronExpression = "0 0 0 * * ?";

// 下面的东西一般不用改.
const baseRepoPageUrl = `https://${githubUserName.toLowerCase()}.github.io/${githubInstSshProjectName}/`;
const installScriptUrl = `${baseRepoPageUrl}/conf-sshd.sh`;
// 如果出现 Github 无法使用的情况, 可以修改 sshKeyUrl 来变更位置.
// 也可以添加额外的 SSH 公钥地址(比如 KeyBase).
const sshKeyUrls = [
  `https://github.com/${githubUserName}.keys`
];

// 下面是脚本的占位符.
const SCRIPT_PH_SSH_KEY_URL = "{{ SSH_KEY_URL }}"
const SCRIPT_PH_SCRIPT_URL = "{{ SCRIPT_URL }}"
const SCRIPT_PH_DEFAULT_CRON = "{{ DEFAULT_CRON }}"


async function sendScriptContent(baseUrl) {
  let scriptResp = await fetch(new Request(installScriptUrl));
  if (scriptResp.ok) {
    let scriptContent = await scriptResp.text();

    scriptContent = scriptContent.replace(SCRIPT_PH_SSH_KEY_URL, `${baseUrl}/ssh.keys`)
                  .replace(SCRIPT_PH_SCRIPT_URL, `${baseUrl}/script.sh`)
                  .replace(SCRIPT_PH_DEFAULT_CRON, cronExpression)

    return new Response(scriptContent, {
      headers: {
        "content-type": "text/plain; charset=utf-8"
      }
    });
  } else {
    return new Response("Failed to get install script.", {
      status: 500,
      statusText: "Failed to get install script",
      headers: {
        "content-type": "text/plain; charset=utf-8"
      }
    });
  }
}

export default {
  async fetch(request, env) {
    const { pathname, host } = new URL(request.url);
    const baseUrl = defaultBaseUrl || `https://${host}`;
    if (pathname === "/ssh.keys") {
      for (let url of sshKeyUrls) {
        let response = await fetch(new Request(url));
        if (response.ok) {
          let keys = await response.text()
          return new Response(keys, {
            headers: {
              "content-type": "text/plain; charset=utf-8"
            }
          });
        }
      }
      if (backupSshKeys.length > 0) {
        return new Response(backupSshKeys, {
          headers: {
            "content-type": "text/plain; charset=utf-8"
          }
        });
      } else {
        return new Response("Failed to get keys.", {
          status: 500,
          statusText: "Failed to get keys",
          headers: {
            "content-type": "text/plain; charset=utf-8"
          }
        });
      }
    } else if (pathname === "/") {
      const userAgent = request.headers.get("User-Agent");
      if (userAgent != null && userAgent.match(/curl|libcurl/) !== null) {
        return await sendScriptContent();
      } else {
        return new Response("", {
          status: 301,
          statusText: "Redirect",
          headers: {
            "Location": baseRepoPageUrl
          }
        });
      }
    } else if (pathname === "/script.sh") {
      return await sendScriptContent();
    } else {
      return new Response("Not found.", {
        status: 404,
        statusText: "Not Found"
      })
    }
  }
}
