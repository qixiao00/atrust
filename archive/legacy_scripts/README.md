# Legacy scripts

这些脚本是历史验证/迁移脚本，当前正式流程不再直接使用。

当前使用的流程只保留：

1. `scripts/01_precheck/generate_ad_authorized_grants.py`
2. `scripts/02_test/migrate_one_user_from_csv.py`
3. `scripts/03_production/migrate_all_from_csv.py`

当前流程固定使用 `AD.description -> 飞书.description` 作为用户匹配规则。
