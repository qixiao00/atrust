# AD description 到飞书 user_id 资源关联同步

专用脚本：`sync_ad_description_to_feishu_user_id.py`

用途：把 AD 域用户当前关联的应用/应用分类授权，同步追加到飞书用户目录中对应用户。匹配规则固定为：

- AD 用户字段：`description`
- 飞书用户字段：`user_id`
- 两边字段值都形如 `HCXXXXXXXX`
- AD `description` 为空的用户会跳过，不参与迁移

脚本默认 dry-run，不会修改线上授权。确认 `reassociate_users.csv` 后，再执行真实授权。

## 1. 配置连接信息

脚本默认读取本地配置文件：

```text
atrust_feishu_config.json
```

当前配置文件已包含：

- OpenAPI API ID
- OpenAPI API Secret
- AD 目录：`ad13382`
- 飞书目录：`feishu86454`
- `max_ops_per_second`: `8`

还需要把 `base_url` 补成实际 aTrust 控制台地址，也就是你平时浏览器打开 aTrust 管理后台时使用的协议、IP/域名和端口。只填到端口即可，不要带 `/api/...` 这类接口路径。例如：

```json
{
  "base_url": "https://atrust.example.com:4433",
  "api_id": "...",
  "api_secret": "...",
  "ad_domain": "ad13382",
  "feishu_domain": "feishu86454",
  "insecure": true,
  "max_ops_per_second": 8.0
}
```

常见填写示例：

- 如果控制台地址是 `https://10.10.10.10:4433/console`，则填 `"base_url": "https://10.10.10.10:4433"`
- 如果控制台地址是 `https://atrust.company.com:4433`，则填 `"base_url": "https://atrust.company.com:4433"`
- 如果控制台就是标准 HTTPS 端口 443，也可以填 `"base_url": "https://atrust.company.com"`

如果运行时报 `HTTP 401`、`AuthFailed.OpenAPI` 或 `openAPI请求失败，配置获取失败`，说明已经连到 aTrust 了，但 OpenAPI 鉴权没有通过。请重点检查：

- `api_id` 和 `api_secret` 是否从同一个 OpenAPI 应用复制，是否多复制了空格。
- 这个 OpenAPI 应用是否已启用，且有调用用户查询、资源查询和授权接口的权限。
- 当前 `base_url` 是否指向生成这组 `api_id` / `api_secret` 的同一套 aTrust 环境。

注意：`HTTP 401` 发生在接口鉴权阶段，通常还没有进入“按工号查用户”的业务查询逻辑。即使界面上能看到这个用户，只要 OpenAPI 应用鉴权失败，脚本也拿不到用户列表。

`atrust_feishu_config.json` 已加入 `.gitignore`，不会被提交。

## 2. 批量统计和生成计划

```powershell
python .\sync_ad_description_to_feishu_user_id.py `
  --output-dir ".\output-ad-description-to-feishu"
```

如果没有在配置文件里写 `base_url`，也可以运行时传：

```powershell
python .\sync_ad_description_to_feishu_user_id.py `
  --base-url "https://atrust.example.com:4433" `
  --output-dir ".\output-ad-description-to-feishu"
```

重点看控制台输出：

- `AD users skipped because description is empty`：AD 没有工号、已跳过的用户数
- `Users needing resource reassociation`：需要重新关联资源的用户数
- `Grant rows planned`：计划追加的授权明细行数

## 3. 确认输出文件

输出目录里重点确认这两个文件：

- `reassociate_users.csv`：需要重新关联资源的用户清单，一行一个用户
- `copied_grants.csv`：计划追加的资源授权明细，一行一条应用或应用分类授权

如果需要排除某些用户，可以从 `reassociate_users.csv` 删除对应行后再执行。

## 4. 批量确认后执行

执行阶段会读取上一步生成的 CSV，不会重新扫描用户目录和资源授权，尽量节省 aTrust OPS。

```powershell
python .\sync_ad_description_to_feishu_user_id.py `
  --output-dir ".\output-ad-description-to-feishu" `
  --execute
```

执行结果：

- `assigned_grants.csv`：已提交追加授权的明细
- `failed_grants.csv`：失败的用户授权记录

## 单用户验证

脚本：`sync_one_ad_description_to_feishu.py`

如果你是在 Windows PowerShell 里执行，需要使用仓库根目录下的真实脚本名：

```powershell
python .\sync_one_ad_description_to_feishu.py `
  --ad-description "HC21120015" `
  --output-dir ".\output-one-ad-description-to-feishu"
```

注意：PowerShell 的换行符是反引号 `` ` ``，反引号必须是每一行最后一个字符，后面不能再有空格。否则建议直接写成一行：

```powershell
python .\sync_one_ad_description_to_feishu.py --ad-description "HC21120015" --output-dir ".\output-one-ad-description-to-feishu"
```

如果脚本提示 `No Feishu user found where user_id=HC21120015.`，说明 AD 用户已经查到了，但飞书目录里没有任何用户的 `user_id` 字段等于这个值。请先确认飞书用户在 aTrust 里存放工号的字段名；如果工号实际在 `name`、`displayName`、`externalId`、`email`、`phone` 或 `description` 等字段里，可以加 `--feishu-match-field` 指定字段，例如：

```powershell
python .\sync_one_ad_description_to_feishu.py --ad-description "HC21120015" --feishu-match-field "name" --output-dir ".\output-one-ad-description-to-feishu"
```

先 dry-run 验证某个工号：

```powershell
python .\sync_one_ad_description_to_feishu.py `
  --ad-description "HCXXXXXXXX" `
  --output-dir ".\output-one-ad-description-to-feishu"
```

确认后只给这个用户追加授权：

```powershell
python .\sync_one_ad_description_to_feishu.py `
  --ad-description "HCXXXXXXXX" `
  --output-dir ".\output-one-ad-description-to-feishu" `
  --execute
```

输出文件：

- `single_user_match.csv`：AD 用户和飞书用户的匹配结果
- `single_user_grants.csv`：该 AD 用户的授权明细
- `single_user_failed.csv`：执行失败记录

## 可选参数

只处理部分应用：

```powershell
python .\sync_ad_description_to_feishu_user_id.py ... --resource-id-file .\resource_ids.txt
```

只处理部分应用分类：

```powershell
python .\sync_ad_description_to_feishu_user_id.py ... --resource-group-id-file .\resource_group_ids.txt
```

只同步应用，不同步应用分类：

```powershell
python .\sync_ad_description_to_feishu_user_id.py ... --skip-resource-groups
```

只同步直接授权，不同步角色继承授权：

```powershell
python .\sync_ad_description_to_feishu_user_id.py ... --direct-only
```
