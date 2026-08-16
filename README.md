# 隐匣

隐匣是一个无依赖、可直接部署到 Cloudflare Pages 的浏览器端加密密码库。账户、密码和备忘录在写入浏览器存储前会先用主密码加密，主密码和明文数据不会上传。

## 部署到 Cloudflare Pages

1. 将此目录推送到 GitHub 或 GitLab 仓库。
2. 在 Cloudflare 控制台进入 **Workers & Pages → Create → Pages → Connect to Git**。
3. 选择仓库；构建命令留空，输出目录填写 `.`。
4. 部署完成后，务必只通过 Cloudflare 提供的 HTTPS 地址访问。

也可以使用 Wrangler：

```powershell
npx wrangler pages deploy . --project-name yinbox
```

## 建议启用 Cloudflare Access（第二道门）

保险箱本身已有主密码和本地加密。若还希望未授权访客连页面都无法打开，可在 Cloudflare Zero Trust 中给 Pages 域名添加 Access Application，并使用邮箱一次性验证码、GitHub 或其他身份提供商。不要在 HTML 或 JavaScript 中写死一个“访问密码”，因为静态页面源码对访客可见。

## 数据与备份

- 数据只保存在当前浏览器的 `localStorage`，不会自动跨设备同步。
- 清理浏览器数据前，请点击侧栏的“导出加密备份”。
- 在另一台设备上点击“导入备份”，再用原主密码解锁即可。
- 忘记主密码后无法恢复数据，这是端到端加密的安全边界。

## 安全实现

- AES-256-GCM 认证加密，每次保存使用新的随机 IV。
- PBKDF2-SHA256，600,000 次迭代和随机 128 位盐。
- 主密码不写入存储；是否正确由解密认证决定。
- 5 分钟无操作自动锁定，连续输错会延迟再次尝试。
- `_headers` 提供 CSP、禁止嵌入、防 MIME 猜测、最小权限等安全响应头。
- 所有用户内容通过 DOM 文本节点渲染，避免注入 HTML。

没有任何软件能承诺“绝对不会被破解”。请使用独一无二且足够长的主密码，保护好设备，并开启 Cloudflare Access。
