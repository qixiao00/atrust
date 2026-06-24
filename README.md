# aTrust AD description 到飞书 description 资源授权同步

当前仓库只保留一套主流程：

```text
AD 用户 description 字段  ->  飞书用户 description 字段
```

目标是把 AD 用户已有的 aTrust 应用/应用分类授权，追加同步到 description 匹配的飞书用户。

## 当前脚本目录

```text
scripts/01_precheck/generate_ad_authorized_grants.py
scripts/02_test/migrate_one_user_from_csv.py
scripts/03_production/migrate_all_from_csv.py
```

- `01_precheck`：前置扫描，生成 `ad_authorized_grants.csv`。
- `02_test`：从 CSV 迁移一个用户，用于小范围验证。
- `03_production`：从 CSV 迁移全部用户，用于正式执行。

历史脚本已经归档到：

```text
archive/legacy_scripts/
```

详细运行说明见：

```text
RUN_AD_DESCRIPTION_TO_FEISHU.md
```
