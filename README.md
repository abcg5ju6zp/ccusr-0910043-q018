# 规则表达式引擎

本项目提供可嵌入服务端的规则解析、类型检查、属性解析和表达式评估能力。生产源码位于 `lib/rule_engine/`，核心回归测试位于 `tests/`。

## 安装

`python3 -m pip install --break-system-packages --no-build-isolation -e .`

## 测试

`python3 -m pytest -q`

## 构建

`python3 -m compileall -q lib/rule_engine`

`python3 -m build --wheel --no-isolation`

## 使用

调用方创建规则并传入普通 Python 对象即可完成本地评估，不需要外部服务。

## 可移植规则档案

`rule_engine.archive` 把规则从测试环境安全转交到隔离生产环境。档案是规范化的
JSON（键排序、UTF-8、无冗余空白），内容寻址并用本地信任密钥签名：

- **负载**：表达式文本与语法版本、上下文选项白名单（`regex_flags`、
  `default_timezone`、`mapping_attribute_lookup`、`default_value`、
  `decimal_context`）、符号清单（内置/外部）、引擎兼容版本区间、扩展声明。
  档案只含规则数据，不包含业务对象；`resolver`/`type_resolver` 等环境代码
  永不导出，由导入方自行提供。
- **签名**：`KeyRing` 管理可轮换的本地信任密钥（`hmac-sha256`，装了
  `cryptography` 时也可用 `ed25519`）。轮换把旧密钥降级为仅可验证；
  撤销立即生效且 fail-closed。
- **导入**：`ArchiveImporter` 依次验证信封结构 → 完整性（内容摘要 + 签名，
  密钥须未撤销未过期）→ 能力边界（引擎版本区间、选项白名单、内置符号、
  扩展关键性）→ 语义复验（按声明选项重解析表达式，符号清单必须完全一致），
  然后裁决 `ACCEPT` / `QUARANTINE` / `MIGRATE`。旧格式先验签再做确定性迁移；
  未知关键扩展隔离、非关键扩展剥离并记录；重复导入按 `archive_id` 幂等，
  返回首次裁决的副本，不改变任何状态。

```python
from rule_engine import archive, Rule, Context

key_ring = archive.KeyRing()
key_ring.generate()                       # 本地信任密钥，to_dict()/from_dict() 持久化
data = archive.export_rule(Rule("user['age'] >= 18"), key_ring)

report = archive.ArchiveImporter(key_ring).import_archive(data)
if report.accepted:
    rule = report.materialize()           # 隔离的档案绝不会到达这里
```
