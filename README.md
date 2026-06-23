# aTrust AD 到飞书资源授权同步

本仓库包含脚本：`atrust_feishu_resource_sync.py`。

脚本用途：

1. 通过 aTrust OpenAPI 读取 AD 用户目录和飞书用户目录。
2. 按工号、手机号、邮箱等稳定字段匹配同一个用户。
3. 找出 AD 用户已经关联的应用和应用分类，包含直接授权和角色授权。
4. 将同样的资源授权追加关联到匹配到的飞书用户。
5. 输出匹配成功、未匹配、重复匹配、计划同步和同步失败结果。

脚本默认是 dry-run，不会修改线上授权。确认 CSV 结果无误后，再加 `--execute` 执行真实授权。

## 运行前准备

需要准备以下信息：

- aTrust OpenAPI 的 `api_id`
- aTrust OpenAPI 的 `api_secret`
- aTrust 控制台基础地址，例如 `https://atrust.example.com:4433`
- AD 用户目录的 `directoryDomain`
- 飞书用户目录的 `directoryDomain`
- 两边用户都存在、且能唯一识别同一个人的字段，例如 `externalId`、`phone`、`email`

`directoryDomain` 可以在 aTrust 用户目录配置或接口返回结果中确认，示例值类似 `custom01339`。

## 先 dry-run

```powershell
python .\atrust_feishu_resource_sync.py `
  --base-url "https://atrust.example.com:4433" `
  --api-id "YOUR_API_ID" `
  --api-secret "YOUR_API_SECRET" `
  --ad-domain "AD_DIRECTORY_DOMAIN" `
  --feishu-domain "FEISHU_DIRECTORY_DOMAIN" `
  --match-fields "externalId,phone,email" `
  --insecure `
  --output-dir ".\output"
```

如果 aTrust 证书已被当前机器信任，可以去掉 `--insecure`。

## 确认后执行

```powershell
python .\atrust_feishu_resource_sync.py `
  --base-url "https://atrust.example.com:4433" `
  --api-id "YOUR_API_ID" `
  --api-secret "YOUR_API_SECRET" `
  --ad-domain "AD_DIRECTORY_DOMAIN" `
  --feishu-domain "FEISHU_DIRECTORY_DOMAIN" `
  --match-fields "externalId,phone,email" `
  --insecure `
  --output-dir ".\output" `
  --execute
```

## 输出文件

脚本会在 `--output-dir` 目录下生成以下 CSV 文件：

- `matched_users.csv`：AD 用户和飞书用户的匹配结果
- `unmatched_ad_users.csv`：在飞书目录中找不到匹配用户的 AD 用户
- `ambiguous_ad_users.csv`：匹配字段在飞书目录中不唯一的 AD 用户
- `copied_grants.csv`：dry-run 计划复制或实际已复制的资源授权明细
- `failed_grants.csv`：实际执行时失败的用户授权记录

## 限定资源范围

如果只想处理部分应用，可以准备一个 UTF-8 文本文件，每行一个应用 ID：

```powershell
python .\atrust_feishu_resource_sync.py ... --resource-id-file .\resource_ids.txt
```

如果只想处理部分应用分类，可以准备一个 UTF-8 文本文件，每行一个应用分类 ID：

```powershell
python .\atrust_feishu_resource_sync.py ... --resource-group-id-file .\resource_group_ids.txt
```

如果不需要同步应用分类，只同步应用：

```powershell
python .\atrust_feishu_resource_sync.py ... --skip-resource-groups
```

如果只想复制直接授权，不复制通过角色获得的授权：

```powershell
python .\atrust_feishu_resource_sync.py ... --direct-only
```

## Demo 脚本

如果你只想验证“某一个 AD 域用户名的权限，是否能直接迁移到飞书用户”，可以用这个最小 demo：

```powershell
python .\demo_migrate_by_username.py `
  --base-url "https://atrust.example.com:4433" `
  --api-id "YOUR_API_ID" `
  --api-secret "YOUR_API_SECRET" `
  --ad-domain "AD_DIRECTORY_DOMAIN" `
  --feishu-domain "FEISHU_DIRECTORY_DOMAIN" `
  --ad-username "zhangsan" `
  --match-field "name" `
  --insecure `
  --output-dir ".\output-demo"
```

默认是 dry-run，只会生成报告，不会真实授权。确认无误后再加 `--execute`。

如果飞书用户名和 AD 用户名不同，可以单独指定：

```powershell
python .\demo_migrate_by_username.py ... `
  --ad-username "zhangsan" `
  --feishu-username "zhang.san"
```

## 两阶段匹配

如果你要先按 `AD_no` 和 AD 域账号用户名做全量匹配，再人工确认后迁移，用这个脚本：

```powershell
python .\demo_match_ad_no_then_migrate.py `
  --base-url "https://atrust.example.com:4433" `
  --api-id "YOUR_API_ID" `
  --api-secret "YOUR_API_SECRET" `
  --ad-domain "AD_DIRECTORY_DOMAIN" `
  --feishu-domain "FEISHU_DIRECTORY_DOMAIN" `
  --ad-field "name" `
  --feishu-field "AD_no" `
  --insecure `
  --output-dir ".\output-ad-no-demo"
```

第一步只会生成 `review_matches.csv`，你确认后再用同一个输出目录里的清单执行迁移：

```powershell
python .\demo_match_ad_no_then_migrate.py `
  --base-url "https://atrust.example.com:4433" `
  --api-id "YOUR_API_ID" `
  --api-secret "YOUR_API_SECRET" `
  --ad-domain "AD_DIRECTORY_DOMAIN" `
  --feishu-domain "FEISHU_DIRECTORY_DOMAIN" `
  --ad-field "name" `
  --feishu-field "AD_no" `
  --insecure `
  --output-dir ".\output-ad-no-demo" `
  --execute `
  --confirmed-file ".\output-ad-no-demo\review_matches.csv"
```

如果你截图里的字段实际叫 `ad_account`，把 `--feishu-field` 改成 `ad_account` 就行。

## 匹配字段说明

`--match-fields` 会按顺序尝试匹配，例如：

```text
externalId,phone,email,name
```

建议把最稳定、最唯一的字段放前面。手机号会自动去掉空格、短横线、区号符号等非数字字符后比较；其他字段会去掉首尾空格并忽略大小写。

如果飞书目录中同一个匹配值对应多个用户，脚本不会自动授权，会把对应 AD 用户写入 `ambiguous_ad_users.csv`，等待人工确认。

## 注意事项

- 首次运行建议只 dry-run，先检查 `matched_users.csv` 和 `copied_grants.csv`。
- `--execute` 会真实追加飞书用户的资源授权，请确认输出结果后再执行。
- 脚本使用追加授权，不会删除飞书用户已有授权。
- 如果 AD 用户没有任何应用或应用分类授权，不会出现在 `copied_grants.csv` 中。

## AD 资源关联用户分析脚本

如果客户当前只需要先分析 AD 域中“哪些用户关联了资源”，以及这些用户里手机号、邮箱的覆盖情况，可以使用新增的只读脚本：

```powershell
python .\analyze_ad_resource_users.py `
  --base-url "https://atrust.example.com:4433" `
  --api-id "YOUR_API_ID" `
  --api-secret "YOUR_API_SECRET" `
  --ad-domain "AD_DIRECTORY_DOMAIN" `
  --insecure `
  --output-dir ".\output-ad-analysis"
```

这个脚本不会迁移授权，也不会修改线上配置。它会先读取 AD 用户目录，再扫描应用和应用分类授权关系，筛出存在资源关联的 AD 用户。默认会同时统计直接授权和角色授权。

输出文件：

- `ad_resource_users.csv`：所有有关联资源的 AD 用户清单，包含授权数量、手机号、邮箱、邮箱格式、重复手机号/邮箱标记。
- `ad_resource_users_with_phone_or_email.csv`：在有关联资源的 AD 用户中，手机号或邮箱至少有一个不为空的用户明细。
- `ad_resource_user_grants.csv`：有关联资源 AD 用户的授权明细，一行一条应用或应用分类授权。
- `summary.json`：统计结论，包括 AD 总人数、有关联资源用户数、手机号覆盖率、邮箱覆盖率、手机号邮箱同时具备比例、两者都缺失比例、重复手机号/邮箱值数量、授权来源统计等。

如果只想分析部分应用或应用分类，可以沿用 ID 文件参数：

```powershell
python .\analyze_ad_resource_users.py ... --resource-id-file .\resource_ids.txt
python .\analyze_ad_resource_users.py ... --resource-group-id-file .\resource_group_ids.txt
```

如果只分析应用授权，不分析应用分类：

```powershell
python .\analyze_ad_resource_users.py ... --skip-resource-groups
```

如果只统计直接授权，不统计角色继承授权：

```powershell
python .\analyze_ad_resource_users.py ... --direct-only
```

## 最新两阶段脚本

现在正确的是“AD -> 派拉 SSO”的这个脚本：

```powershell
python .\demo_ad_to_para_then_migrate.py `
  --base-url "https://atrust.example.com:4433" `
  --api-id "YOUR_API_ID" `
  --api-secret "YOUR_API_SECRET" `
  --source-domain "AD_DIRECTORY_DOMAIN" `
  --target-domain "PARA_DIRECTORY_DOMAIN" `
  --source-field "name" `
  --target-field "AD_no" `
  --insecure `
  --max-ops-per-second 8 `
  --output-dir ".\output-ad-to-para-demo"
```

确认后再执行：

```powershell
python .\demo_ad_to_para_then_migrate.py `
  --base-url "https://atrust.example.com:4433" `
  --api-id "YOUR_API_ID" `
  --api-secret "YOUR_API_SECRET" `
  --source-domain "AD_DIRECTORY_DOMAIN" `
  --target-domain "PARA_DIRECTORY_DOMAIN" `
  --source-field "name" `
  --target-field "AD_no" `
  --insecure `
  --max-ops-per-second 8 `
  --output-dir ".\output-ad-to-para-demo" `
  --execute `
  --confirmed-file ".\output-ad-to-para-demo\review_matches.csv"
```

如果目标字段不是 `AD_no`，改成客户实际字段名，比如 `ad_account`。
