const githubUserName = "LamGC";
const githubInstSshProjectName = "quickly-conf-sshd";

// 一般不用改.
const baseUrl = `https://${githubUserName.toLowerCase()}.github.io/${githubInstSshProjectName}/`;
const installScriptUrl = `${baseUrl}/conf-sshd.sh`;
// 如果出现 Github 无法使用的情况, 可以修改 sshKeyUrl 来变更位置.
const sshKeyUrl = `https://github.com/${githubUserName}.keys`;
// 建议在此设置备用的 SSH 公钥, 以防 Github 无法使用.
const backupSshKeys = ``;

function getUserAgent(request) {
  return request.headers.get("User-Agent");
}

export default {
  async fetch(request, env) {
    const { pathname } = new URL(request.url);
    if (pathname === "/ssh.keys") {
      let response = await fetch(new Request(sshKeyUrl));
      if (response.ok) {
        return new Response(response.text(), {
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
      if (userAgent.match(/curl|libcurl/) !== null) {
        return new Response("", {
          status: 301,
          statusText: "Redirect",
          headers: {
            "Location": installScriptUrl
          }
        });
      } else {
        return new Response("", {
          status: 301,
          statusText: "Redirect",
          headers: {
            "Location": baseUrl
          }
        });
      }
    }
  }
}
