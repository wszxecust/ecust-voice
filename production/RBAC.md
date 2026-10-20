# RBAC 权限配置

系统使用两级角色：

| 能力 | 管理员 `admin` | 使用人员 `user` |
| --- | --- | --- |
| 查看校园数据、原帖、趋势、账本 | ✓ | ✓ |
| 发起事件研究、查看/导出自己的报告 | ✓ | ✓ |
| 管理自己的研究任务 | ✓ | ✓ |
| 提交个人评分反馈 | ✓ | ✓ |
| 手动触发全局采集 | ✓ | — |
| 查看/修改模型与检索配置 | ✓ | — |
| 测试模型连接、拉取模型列表 | ✓ | — |
| 启停系统、子服务、Forum 服务 | ✓ | — |
| 修改采集源、计价等全局设置 | ✓ | — |
| 创建/关闭公共投票、人工复核、公共议题写操作 | ✓ | — |

权限在后端强制执行。前端隐藏管理员操作仅用于界面简化，不作为安全边界。

## 账号配置

### 主账号

现有配置保持兼容。主账号默认是管理员：

```env
WEB_AUTH_USERNAME=admin
WEB_AUTH_PASSWORD=replace-with-a-strong-password
WEB_AUTH_PRIMARY_ROLE=admin
```

如确需把主账号设为使用人员，可将 `WEB_AUTH_PRIMARY_ROLE=user`。

### 附加账号

旧格式仍然可用，旧格式账号默认是 `user`：

```env
WEB_AUTH_ACCOUNTS={"teacher01":"password-a","teacher02":"password-b"}
```

推荐新格式，明确写出密码和角色：

```env
WEB_AUTH_ACCOUNTS={"teacher01":{"password":"password-a","role":"user"},"ops01":{"password":"password-b","role":"admin"}}
```

也可以用 `WEB_AUTH_ROLES` 单独覆盖角色：

```env
WEB_AUTH_ROLES={"teacher01":"user","ops01":"admin"}
```

支持的角色只有 `admin` 和 `user`。无法识别的角色不会获得管理员权限。

## 安全行为

- 登录成功后，用户名和角色写入签名 Flask Session。
- Flask 本身执行登录门禁，不依赖 Nginx 单独兜底。
- 匿名公开投票 `/pulse/poll/<token>` 保持公开。
- 管理员 API 对普通用户返回 HTTP 403。
- 未登录 API 请求返回 HTTP 401。
- 已保存的 API Key 和数据库密码不再通过 `/api/config` 回传浏览器。
- 研究任务日志、Forum 历史和 WebSocket 订阅按当前账号校验任务归属。
