# 隐匣

隐匣是一个部署在 Cloudflare Pages、使用私有 R2 跨设备同步数据的轻量密码库。R2 是云端主存储，浏览器中的加密副本仅用于离线使用和迁移旧数据。

## 部署到 Cloudflare Pages

1. 在 Cloudflare 控制台创建名为 `password-manager` 的 R2 bucket。
2. 将此目录推送到 GitHub 或 GitLab 仓库。
3. 在 Cloudflare 控制台进入 **Workers & Pages → Create → Pages → Connect to Git**。
4. 选择仓库；构建命令留空，输出目录填写 `.`。
5. 在 Pages 项目的 **Settings → Bindings** 添加 R2 binding：变量名填写 `VAULT_BUCKET`，bucket 选择 `password-manager`。
6. 在 Pages 项目的 **Settings → Variables and Secrets** 添加两个加密 Secret：
   - `VAULT_PASSWORD`：页面访问密码，至少 12 位。升级旧项目时，请设置为你原来使用的主密码。
   - `SESSION_SECRET`：用于签名登录会话的随机字符串，建议至少 32 位，且不要与访问密码相同。
7. 重新部署，并且只通过 Cloudflare 提供的 HTTPS 地址访问。

也可以使用 Wrangler：

```powershell
npx wrangler r2 bucket create password-manager
npx wrangler pages secret put VAULT_PASSWORD --project-name password-manager
npx wrangler pages secret put SESSION_SECRET --project-name password-manager
npx wrangler pages deploy . --project-name password-manager
```

仓库中的 `wrangler.toml` 已声明相同的 R2 binding。

## 登录保护

不需要 Cloudflare Access。访问密码保存在 Cloudflare 的加密 Secret 中，不会写入 HTML 或 JavaScript。Pages Function 校验成功后会设置 `HttpOnly`、`Secure`、`SameSite=Strict` 会话 Cookie；未登录请求无法读取或修改 `/api/vault`。

## 数据与备份

- R2 的 `vault/data.json` 是云端主数据，包含账户、密码、网址和备忘录的普通 JSON；bucket 必须保持私有。
- 每次保存、编辑、删除和添加星标后，页面会自动把最新数据同步到 R2。
- 新设备输入相同的 `VAULT_PASSWORD` 后，会从 R2 载入相同数据，不依赖旧设备。
- 首次部署 R2 版本时，原浏览器中的已有数据不会被清除；请先在原设备解锁一次，页面会自动把旧数据上传到 R2。
- 仍建议定期点击顶部“备份”，保存独立的加密备份文件。
- 修改 Cloudflare 中的 `VAULT_PASSWORD` 后，原浏览器本地副本仍使用旧密码加密；如需改密码，建议先导出备份并重新初始化本地副本。

## 安全实现

- 浏览器离线副本使用 AES-256-GCM 与 PBKDF2-SHA256 加密。
- R2 按当前要求保存普通 JSON，因此必须保持 bucket 私有，并使用足够强的 `VAULT_PASSWORD`。
- 访问密码只保存在 Cloudflare 加密 Secret 中。
- R2 API 使用服务端签名的安全会话 Cookie 保护。
- 5 分钟无操作自动锁定，连续输错会延迟再次尝试。
- `_headers` 提供 CSP、禁止嵌入、防 MIME 猜测、最小权限等安全响应头。
- 所有用户内容通过 DOM 文本节点渲染，避免注入 HTML。

没有任何软件能承诺“绝对不会被破解”。请使用独一无二且足够长的访问密码，不要公开 R2 bucket，并定期导出备份。

## 旧版本迁移到 R2

1. 部署新版本前不要清理原浏览器数据。
2. 将 `VAULT_PASSWORD` 设置为旧版本正在使用的主密码。
3. 完成 R2 binding 和两个 Secret 后部署新版本。
4. 在原来保存过数据的浏览器打开新版，输入旧主密码解锁。
5. 顶部状态显示“R2 已同步”后，旧数据已经上传。
6. 在另一台设备打开相同网址，输入相同密码；首次连接时需要输入两次确认，随后即可读取 R2 数据。
