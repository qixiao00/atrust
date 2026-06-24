# AD description 到飞书 description 资源授权同步

当前只保留这一套正式流程：使用 **AD 域控用户的 `description` 字段** 匹配 **飞书用户目录的 `description` 字段**，并把 AD 用户已有的应用/应用分类授权追加到对应飞书用户。

历史 demo、旧版 `user_id` 匹配脚本、单用户直连扫描脚本已经放入：

```text
archive/legacy_scripts/
```

## 目录结构

```text
scripts/01_precheck/generate_ad_authorized_grants.py   # 前置脚本：扫描并生成 CSV
scripts/02_test/migrate_one_user_from_csv.py           # 测试脚本：从 CSV 迁移一个用户
scripts/03_production/migrate_all_from_csv.py          # 正式脚本：从 CSV 迁移全部用户
```

每类脚本默认把产物放到自己的目录：

```text
output-precheck-ad-description-to-feishu-description/
output-test-one-user-from-csv/
output-production-from-csv/
```

## 1. 配置连接信息

脚本默认读取本地配置文件：

```text
atrust_feishu_config.json
```

需要配置：

```json
{
  "base_url": "https://atrust.example.com:4433",
  "api_id": "YOUR_API_ID",
  "api_secret": "YOUR_API_SECRET",
  "ad_domain": "ad13382",
  "feishu_domain": "feishu86454",
  "insecure": true,
  "max_ops_per_second": 8.0
}
```

`base_url` 填你平时浏览器打开 aTrust 管理后台时使用的协议、IP/域名和端口，只填到端口即可，不要带 `/api/...` 这类接口路径。

示例：

- 控制台地址是 `https://10.10.10.10:4433/console`，则填 `"base_url": "https://10.10.10.10:4433"`
- 控制台地址是 `https://atrust.company.com:4433`，则填 `"base_url": "https://atrust.company.com:4433"`
- 标准 HTTPS 端口 443，则填 `"base_url": "https://atrust.company.com"`

## 2. 前置脚本：生成 AD 授权资源明细 CSV

这个脚本会：

1. 拉取 AD 用户目录。
2. 拉取飞书用户目录。
3. 按 `AD.description -> 飞书.description` 匹配用户。
4. 扫描匹配成功的 AD 用户已有的资源授权。
5. 生成 `ad_authorized_grants.csv`，后续测试和正式脚本都直接读取这个 CSV，不再重复扫描资源授权。

运行：

```powershell
python .\scripts\01_precheck\generate_ad_authorized_grants.py
```

默认输出目录：

```text
output-precheck-ad-description-to-feishu-description/
```

重点输出文件：

- `ad_authorized_grants.csv`：AD 侧有授权资源的详细信息，包含 AD 用户、飞书用户、匹配字段、资源/应用分类、授权来源、有效期等字段。
- `matched_users_with_grants.csv`：匹配成功且有授权资源的用户汇总。
- `unmatched_ad_users.csv`：AD 有 description 但没有匹配到飞书 description 的用户。
- `ambiguous_ad_users.csv`：飞书侧 description 重复导致无法唯一匹配的用户。

## 3. 测试脚本：根据 CSV 迁移一个用户

先 dry-run，不会真实授权：

```powershell
python .\scripts\02_test\migrate_one_user_from_csv.py `
  --grant-csv ".\output-precheck-ad-description-to-feishu-description\ad_authorized_grants.csv" `
  --ad-description "HC21120015"
```

确认后执行真实授权：

```powershell
python .\scripts\02_test\migrate_one_user_from_csv.py `
  --grant-csv ".\output-precheck-ad-description-to-feishu-description\ad_authorized_grants.csv" `
  --ad-description "HC21120015" `
  --execute
```

默认输出目录：

```text
output-test-one-user-from-csv/
```

输出文件：

- `one_user_assigned_grants.csv`：dry-run 计划或真实已提交的授权明细。
- `one_user_failed.csv`：这个用户执行失败的错误信息。

## 4. 正式脚本：根据 CSV 迁移全部权限

先 dry-run，不会真实授权：

```powershell
python .\scripts\03_production\migrate_all_from_csv.py `
  --grant-csv ".\output-precheck-ad-description-to-feishu-description\ad_authorized_grants.csv"
```

确认后执行真实授权：

```powershell
python .\scripts\03_production\migrate_all_from_csv.py `
  --grant-csv ".\output-precheck-ad-description-to-feishu-description\ad_authorized_grants.csv" `
  --execute
```

默认输出目录：

```text
output-production-from-csv/
```

输出文件：

- `all_assigned_grants.csv`：dry-run 计划或真实已提交的授权明细。
- `all_failed.csv`：执行失败的用户和错误信息。

## 5. 常见问题

### HTTP 401 / AuthFailed.OpenAPI

如果运行时报 `HTTP 401`、`AuthFailed.OpenAPI` 或 `openAPI请求失败，配置获取失败`，说明已经连到 aTrust 了，但 OpenAPI 鉴权没有通过。请检查：

- `api_id` 和 `api_secret` 是否从同一个 OpenAPI 应用复制，是否多复制了空格。
- 这个 OpenAPI 应用是否已启用，且有调用用户查询、资源查询和授权接口的权限。
- 当前 `base_url` 是否指向生成这组 `api_id` / `api_secret` 的同一套 aTrust 环境。

### 匹配不到用户

当前流程固定按 `AD.description -> 飞书.description` 匹配。若匹配不到，请检查：

- AD 用户的 `description` 是否为空。
- 飞书用户的 `description` 是否和 AD `description` 完全一致。
- 飞书侧是否存在多个相同 `description`，如果重复会进入 `ambiguous_ad_users.csv`。
