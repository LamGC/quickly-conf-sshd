const githubUserName = "LamGC";
const githubInstSshProjectName = "quickly-conf-sshd";

// 一般不用改.
const baseUrl = `https://${githubUserName.toLowerCase()}.github.io/${githubInstSshProjectName}/`;
const installScriptUrl = `${baseUrl}/conf-sshd.sh`;
// 如果出现 Github 无法使用的情况, 可以修改 sshKeyUrl 来变更位置.
const sshKeyUrls = [
  `https://github.com/${githubUserName}.keys`
];
// 建议在此设置备用的 SSH 公钥, 以防 Github 无法使用.
const backupSshKeys = ``;

function getUserAgent(request) {
  return request.headers.get("User-Agent");
}

async function sendScriptContent() {
  let scriptResp = await fetch(new Request(installScriptUrl));
  if (scriptResp.ok) {
    let scriptContent = await scriptResp.text();
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
    const { pathname } = new URL(request.url);
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
      const userAgent = getUserAgent(request);
      if (userAgent != null && userAgent.match(/curl|libcurl/) !== null) {
        return await sendScriptContent();
      } else {
        return new Response("", {
          status: 301,
          statusText: "Redirect",
          headers: {
            "Location": baseUrl
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
