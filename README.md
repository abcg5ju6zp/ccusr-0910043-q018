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

## 规则档案（测试环境 → 隔离生产环境）

单纯复制表达式文本无法证明解析选项、自定义符号与类型元数据没有被改动。
`rule_engine.archive` 子系统提供**可移植、带签名**的规则档案：

* 档案是自描述 JSON 信封，规范清单（manifest）完整保存表达式文本、解析上下文
  选项（正则选项、默认时区、default_value、decimal 上下文、resolver 模式）、
  外部符号清单及其类型声明（含 OBJECT/自引用模式）以及兼容引擎版本；
* 清单用本地 Ed25519 信任密钥签名，支持多密钥共同签名、带外安装新公钥、
  撤销旧密钥，以及由在信锚点签发的密钥背书证书（导入方显式开启才生效）；
* 档案只包含声明性元数据，**不包含任何业务对象或运行期数据**；自定义
  resolver、非 null 默认值、任意时区等无法可移植表达的内容在导出时即被拒绝；
* 导入流水线固定为：信封/版本边界 → 信任验证 → 清单结构 → 引擎能力边界 →
  重建上下文并重解析（符号集合、严格符号类型、symbols/types 段一致性、
  内建符号能力）→ 重复导入检测，结论只有 `ACCEPT` / `QUARANTINE` / `MIGRATE`。

```python
import rule_engine
from rule_engine import Context, Rule, DataType
from rule_engine.archive import RuleArchive, SigningKey, LocalKeyring, ImportDecision

# 测试环境：生成/持有签名密钥
signing_key = SigningKey.generate()

context = Context(regex_flags=0, type_resolver={'name': DataType.STRING})
archive = RuleArchive.export(Rule('name == "alice"', context=context), signing_key)
payload = archive.to_bytes()          # 可随审批流转交，不包含业务数据

# 生产环境：只信任带外安装的公钥
keyring = LocalKeyring()
keyring.add_public_key(signing_key.public_pem(), label='test-env')
report = RuleArchive.from_bytes(payload).import_rule(keyring)
if report.decision is ImportDecision.ACCEPT:
    rule = report.require_accepted()  # 非 ACCEPT 时抛出，杜绝静默激活
    rule.matches({'name': 'alice'})
# QUARANTINE：签名无法验证、密钥已撤销、能力不满足、符号/类型漂移、重复冲突、
#             未知扩展等；MIGRATE：签名时代之前的旧文本，须显式迁移并重新签名
```

旧纯文本格式只能得到 `MIGRATE`，必须在调用方显式提供解析选项后重新签名：

```python
archive = RuleArchive.migrate('name == "alice"', Context(type_resolver={'name': DataType.STRING}), signing_key)
```

重复导入按规则**语义指纹**（不含导出时间戳）判重：同内容重新导出幂等，
同 id 但语义不同则隔离。密钥撤销后，任何仅由旧密钥背书的档案立即无法激活。

