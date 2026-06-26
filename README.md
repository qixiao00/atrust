# aTrust AD 到飞书资源授权同步

当前只保留一条正式流程：

```text
AD 用户 description  ->  飞书用户 user_id / externalId / external_id
```

AD 侧 `description` 按工号匹配，例如 `HCXXXXXXXX`。飞书侧优先用 `user_id` 匹配；匹配不到再按 `externalId` / `external_id` 匹配。AD 侧 `description` 为空的账号不会迁移。

飞书用户目录会通过 aTrust 用户目录接口一次全量拉取到本地内存后建索引，不会按 AD 用户逐个查询飞书用户。

旧脚本已移动到 `archive/`。根目录里真正使用的是：

```text
atrust_feishu_config.json          连接配置
atrust_common.py                   公共 API/CSV 工具模块
01_prepare_ad_authorized_grants.py 前置脚本
02_test_migrate_one_user.py        测试脚本
03_migrate_all_from_csv.py         正式脚本
```

## 配置

脚本默认读取：

```text
atrust_feishu_config.json
```

需要确认里面的 `base_url` 是真实 aTrust 地址：

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

## 执行顺序

1. 先跑前置样本，确认字段和 CSV 结构。
2. 样本确认没问题后，跑前置全量，生成正式迁移用的 CSV。
3. 用测试脚本迁移一个用户。
4. 测试通过后，用正式脚本批量迁移。

## 1. 前置脚本

### 1.1 样本模式

直接运行：

```powershell
python .\01_prepare_ad_authorized_grants.py
```

样本模式的含义：

- 不是取“前 10 个 AD 用户”
- 不是取“前 10 个匹配成功的用户”
- 是持续扫描资源授权关系，直到找到 10 个“AD 侧确实有授权资源、且能通过 AD description 匹配到飞书 user_id 或外部 ID”的用户，然后停止
- 如果前 1000 个 AD 用户都没有授权资源，脚本会继续找，直到找到 10 个有授权资源的用户，或者可扫描范围结束

样本模式只用于确认字段和数据形态，不作为正式迁移依据。

样本产物目录：

```text
outputs/precheck/
```

样本产物：

```text
ad_authorized_grants_10.csv  10 个有授权 AD 用户的授权样本明细
authorized_users_10.csv      这 10 个有授权 AD 用户的用户级汇总
summary_10.json              样本模式统计
```

样本模式会清理同目录下旧的全量产物，避免误把历史 `ad_authorized_grants.csv` 当成这次生成的文件。

### 1.2 全量模式

确认样本无误后，生成正式迁移用的全量 CSV：

```powershell
python .\01_prepare_ad_authorized_grants.py --full
```

全量产物目录：

```text
outputs/precheck/
```

全量产物：

```text
ad_authorized_grants.csv  正式迁移依据，一行一条 AD 侧授权明细
authorized_users.csv      有授权且可匹配到飞书用户的 AD 用户汇总
unmatched_ad_users.csv    AD description 无法匹配到飞书 user_id / externalId / external_id 的用户
ambiguous_ad_users.csv    飞书匹配标识不唯一，无法安全迁移的 AD 用户
summary.json              全量统计
```

## 2. 测试脚本

默认读取样本 CSV：

```text
outputs/precheck/ad_authorized_grants_10.csv
```

先 dry-run 一个用户：

```powershell
python .\02_test_migrate_one_user.py --ad-description "HCXXXXXXXX"
```

真正给这个用户追加授权：

```powershell
python .\02_test_migrate_one_user.py --ad-description "HCXXXXXXXX" --execute
```

如果要基于全量 CSV 测试某个用户：

```powershell
python .\02_test_migrate_one_user.py `
  --ad-description "HCXXXXXXXX" `
  --input-csv ".\outputs\precheck\ad_authorized_grants.csv"
```

测试产物目录：

```text
outputs/test/
```

测试产物：

```text
test_user_grants.csv  本次选中用户将要迁移或已迁移的授权明细
test_failed.csv       单用户迁移失败记录；无失败时只有表头
```

## 3. 正式脚本

正式脚本默认读取：

```text
outputs/precheck/ad_authorized_grants.csv
```

先 dry-run 看统计：

```powershell
python .\03_migrate_all_from_csv.py
```

确认后正式批量追加授权：

```powershell
python .\03_migrate_all_from_csv.py --execute
```

正式产物目录：

```text
outputs/formal/
```

正式产物：

```text
all_grants_result.csv  全量 CSV 中所有授权行的计划/执行结果
all_failed.csv         执行失败的用户记录；无失败时只有表头
summary.json           正式脚本统计
```

## CSV 字段说明

### ad_authorized_grants_10.csv / ad_authorized_grants.csv

这两个文件字段一致，区别是：

- `ad_authorized_grants_10.csv`：样本，只包含找到的 10 个有授权 AD 用户
- `ad_authorized_grants.csv`：全量，正式迁移依据

字段含义：

```text
ad_user_id           AD 用户在 aTrust 中的内部 ID
ad_user_name         AD 用户账号名
ad_display_name      AD 用户显示名
ad_description       AD 用户 description，也就是匹配用工号
feishu_user_id       飞书用户在 aTrust 中的内部 ID，授权接口使用这个 ID
feishu_user_name     飞书用户账号名
feishu_display_name  飞书用户显示名
feishu_description   飞书用户 description，仅用于人工参考，不再作为默认匹配字段
feishu_user_id_value  飞书用户目录中的 user_id/use_id 字段值
feishu_external_id    飞书用户目录中的 externalId/external_id 字段值
match_source_field   固定为 description，表示 AD 匹配字段
match_target_field   飞书侧实际命中的字段，通常是 user_id、externalId 或 external_id
match_value          两边匹配命中的工号
grant_kind           resource 表示应用，resourceGroup 表示应用分类
resource_id          应用或应用分类 ID
resource_name        应用或应用分类名称
grant_source_type    AD 侧授权来源类型；user 是直接授权，band 是角色/用户组继承授权，department/dept/org/organization 等表示 AD 组织架构来源
grant_source_id      授权来源 ID；直接授权时通常是 AD 用户 ID，继承授权时是角色/用户组 ID
grant_source_name    授权来源名称
effective_time       授权生效时间；为空表示源授权未返回该值
expire_time          授权过期时间；为空表示源授权未返回该值
```

### authorized_users_10.csv / authorized_users.csv

用户级汇总，一行一个 AD 用户。

```text
ad_user_id            AD 用户在 aTrust 中的内部 ID
ad_user_name          AD 用户账号名
ad_display_name       AD 用户显示名
ad_description        AD 用户 description
feishu_user_id        飞书用户在 aTrust 中的内部 ID
feishu_user_name      飞书用户账号名
feishu_display_name   飞书用户显示名
feishu_description    飞书用户 description，仅用于人工参考
feishu_user_id_value   飞书用户目录中的 user_id/use_id 字段值
feishu_external_id     飞书用户目录中的 externalId/external_id 字段值
match_target_field     飞书侧实际命中的字段
match_value           两边匹配命中的工号
grant_count           该用户授权明细总行数
resource_count        应用授权数量
resource_group_count  应用分类授权数量
```

### unmatched_ad_users.csv

只在 `--full` 时生成。表示无法通过 AD `description` 找到唯一飞书用户的 AD 用户。

```text
ad_user_id       AD 用户在 aTrust 中的内部 ID
ad_user_name     AD 用户账号名
ad_display_name  AD 用户显示名
ad_description   AD 用户 description
reason           未匹配原因，例如 empty_ad_description 或 no_feishu_identifier_match
checked_feishu_fields  本次检查过的飞书字段
```

### ambiguous_ad_users.csv

只在 `--full` 时生成。表示飞书侧 `user_id` 或外部 ID 匹配不唯一，脚本不会迁移这些用户。

```text
ad_user_id       AD 用户在 aTrust 中的内部 ID
ad_user_name     AD 用户账号名
ad_display_name  AD 用户显示名
ad_description   AD 用户 description
reason           歧义原因
duplicate_keys   重复的匹配键
```

### test_user_grants.csv

测试脚本输出，字段基本来自授权 CSV，额外有：

```text
status  dry_run 表示仅计划，assigned 表示已调用授权接口
```

### test_failed.csv / all_failed.csv

失败记录。无失败时文件只有表头。

```text
ad_user_id       AD 用户在 aTrust 中的内部 ID
ad_user_name     AD 用户账号名
ad_description   AD 用户 description
feishu_user_id   飞书用户在 aTrust 中的内部 ID
feishu_user_name 飞书用户账号名
error            接口返回或脚本捕获的错误
```

`all_failed.csv` 还会包含：

```text
grant_rows  这个用户本次计划迁移的授权行数
```

## 范围控制

前置脚本可以限制只扫描部分应用或应用分类：

```powershell
python .\01_prepare_ad_authorized_grants.py --resource-id-file .\resource_ids.txt
python .\01_prepare_ad_authorized_grants.py --resource-group-id-file .\resource_group_ids.txt
python .\01_prepare_ad_authorized_grants.py --skip-resource-groups
python .\01_prepare_ad_authorized_grants.py --direct-only
```

## 授权来源说明

前置脚本默认会纳入三类 AD 侧授权来源：

```text
user  用户直接授权
band  角色/用户组继承授权
AD 组织架构授权  通过 AD 部门/组织节点继承的授权
```

角色授权是否会迁移：

- 会。脚本会读取 AD 用户的 `roleIdList`，再和资源授权里的 `entityType=band` 匹配。
- 迁移时不会在飞书侧创建或绑定同名角色。
- 迁移结果是把角色继承得到的应用/应用分类授权，作为资源授权追加给对应飞书用户。

组织架构授权如何处理：

- 不会迁移 AD 组织架构本身，也不会尝试把 AD 组织节点映射成飞书组织节点。
- 因为 AD 和飞书的组织树不一致，正式脚本只会逐个给飞书用户追加资源授权。
- 前置脚本会把 AD 资源授权里的组织/部门 entityType 展开到 AD 用户，得到“这个 AD 用户实际继承到了哪些资源”。
- 展开后的结果写入 `ad_authorized_grants*.csv`，后续测试/正式脚本只根据 CSV 里的 `feishu_user_id` 对飞书用户逐一授权。
- CSV 中仍然看 `grant_source_type` 字段；如果来源是 AD 组织架构授权，这里会显示 aTrust 返回的组织/部门类型，例如 `department`、`dept`、`org` 或 `organization`。

如果 aTrust 环境里的 AD 组织 entityType 不是默认值，可以在前置脚本指定：

```powershell
python .\01_prepare_ad_authorized_grants.py `
  --org-entity-types "department,dept,org,organization"
```

如果 AD 用户目录里保存 AD 部门/组织 ID 的字段名不是默认值，可以指定：

```powershell
python .\01_prepare_ad_authorized_grants.py `
  --org-user-fields "departmentId,deptId,orgId,organizationId"
```

如果只想临时排除 AD 组织架构来源的资源：

```powershell
python .\01_prepare_ad_authorized_grants.py --skip-org-grants
```
