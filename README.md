# aTrust AD 到飞书资源授权同步

当前项目只保留一条正式流程：

```text
AD 用户 description  ->  飞书用户 description
```

两边 `description` 都按工号匹配，例如 `HCXXXXXXXX`。AD 侧 `description` 为空的账号不会迁移。

旧脚本和旧说明已放到 `archive/`，根目录只保留当前流程使用的文件。

## 文件结构

```text
atrust_feishu_config.json          本地连接配置
atrust_common.py                   公共 API/CSV 工具模块
01_prepare_ad_authorized_grants.py 前置脚本：扫描 AD 授权并生成 CSV
02_test_migrate_one_user.py        测试脚本：按 CSV 迁移一个用户
03_migrate_all_from_csv.py         正式脚本：按 CSV 批量迁移全部用户
outputs/precheck/                  前置脚本产物
outputs/test/                      测试脚本产物
outputs/formal/                    正式脚本产物
archive/                           旧脚本归档
```

## 配置

默认读取：

```text
atrust_feishu_config.json
```

确认 `base_url` 已填写真实 aTrust 地址：

```json
{
  "base_url": "https://atrust.example.com:4433",
  "api_id": "1027079",
  "api_secret": "已配置",
  "ad_domain": "ad13382",
  "feishu_domain": "feishu86454",
  "insecure": true,
  "max_ops_per_second": 8.0
}
```

## 1. 前置脚本

默认只找 10 个“AD 侧有授权资源且能匹配到飞书用户”的用户，生成样本 CSV 后停止，用来先确认字段和授权数据。

```powershell
python .\01_prepare_ad_authorized_grants.py
```

默认产物：

```text
outputs/precheck/ad_authorized_grants_10.csv
outputs/precheck/authorized_users_10.csv
outputs/precheck/summary_10.json
```

确认样本无误后，生成全量 CSV：

```powershell
python .\01_prepare_ad_authorized_grants.py --full
```

全量产物：

```text
outputs/precheck/ad_authorized_grants.csv
outputs/precheck/authorized_users.csv
outputs/precheck/unmatched_ad_users.csv
outputs/precheck/ambiguous_ad_users.csv
outputs/precheck/summary.json
```

`ad_authorized_grants.csv` 保留 AD 侧有授权资源的详细信息，包括 AD 用户、飞书用户、匹配字段、应用/应用分类、授权来源、有效期等字段。后续测试和正式迁移都只基于这个 CSV 执行，不再重复扫描资源授权。

## 2. 测试脚本

先用 10 人样本 CSV 测试一个用户。默认 dry-run，只写结果文件，不修改线上授权。

```powershell
python .\02_test_migrate_one_user.py --ad-description "HCXXXXXXXX"
```

真正给这个用户追加授权：

```powershell
python .\02_test_migrate_one_user.py --ad-description "HCXXXXXXXX" --execute
```

测试产物：

```text
outputs/test/test_user_grants.csv
outputs/test/test_failed.csv
```

如果要从全量 CSV 测试某个用户：

```powershell
python .\02_test_migrate_one_user.py `
  --ad-description "HCXXXXXXXX" `
  --input-csv ".\outputs\precheck\ad_authorized_grants.csv"
```

## 3. 正式脚本

正式脚本默认读取全量 CSV：

```text
outputs/precheck/ad_authorized_grants.csv
```

先 dry-run 看统计：

```powershell
python .\03_migrate_all_from_csv.py
```

确认后批量追加授权：

```powershell
python .\03_migrate_all_from_csv.py --execute
```

正式产物：

```text
outputs/formal/all_grants_result.csv
outputs/formal/all_failed.csv
outputs/formal/summary.json
```

## 可选范围控制

前置脚本可以限制只扫描部分应用或应用分类：

```powershell
python .\01_prepare_ad_authorized_grants.py --resource-id-file .\resource_ids.txt
python .\01_prepare_ad_authorized_grants.py --resource-group-id-file .\resource_group_ids.txt
python .\01_prepare_ad_authorized_grants.py --skip-resource-groups
python .\01_prepare_ad_authorized_grants.py --direct-only
```
