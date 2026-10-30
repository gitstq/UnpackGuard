<div align="center">

# 🛡️ UnpackGuard

**像有人要攻击你一样去解压压缩包 —— 零依赖 · 离线优先的安全解压与归档审计引擎**

[简体中文](#简体中文) | [繁體中文](./README.zh-TW.md) | [English](./README.en.md)

[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](./LICENSE)
[![Zero dependencies](https://img.shields.io/badge/dependencies-0-brightgreen.svg)](./pyproject.toml)
[![Offline](https://img.shields.io/badge/network-none-lightgrey.svg)](#设计思路与迭代规划)

</div>

---

## 🎉 项目介绍

> 你收到一个压缩包。它可能来自用户上传、CI 产物、邮件附件、或者一个你不太熟悉的开源仓库。
> 你双击解压的那一刻，它可能往 `../../` 里写了一句话反弹 shell。

现代开发流程里，「下载 → 解压 → 运行」是一个被严重低估的攻击面。**Zip-Slip 路径穿越**、**压缩炸弹**、**NTFS 备用数据流**、**伪装后缀的可执行马**、**Trojan Source 双向控制字符**……绝大多数解压器默认选择「照做」，把这些风险原封不动地落到你的磁盘上。

**UnpackGuard** 是为这条链路设计的守卫。它不是又一个解压工具，而是一个**先审计、再执行**的解压引擎：

* 🧭 **看得清**：不解压也能把归档里每一个成员的名称、体积、压缩比、权限、时间戳、嵌套层级全部列出来；
* 🚦 **审得准**：26 条内置规则按 CVSS 式严重度分级，从信息提示到 critical 一网打尽，并输出 **0–100 安全评分**；
* 🧱 **拦得住**：任何一种危险书写形态都有对应的策略开关，默认全部收敛到「绝不越界」的安全行为；
* 🔌 **接得上**：`--json` 给脚本消费，`--sarif` 直接喂给 GitHub code scanning，`--fail-level` 提供 CI 可用的退出码；
* 📦 **零依赖**：只依赖 Python 标准库，`pip install` 之后立刻可用，**不联网、不上传、无遥测**。

### 💡 灵感来源与差异化

社区已有不少优秀的归档工具（WinRAR、7-Zip、`unzip`、以及近期很火的 `HatchZip`），但它们主要解决的是**「怎么把东西解开」**，尤其是磁盘空间不够时的原地解压。它们的默认行为是「信任归档作者写的路径」。

UnpackGuard 解决的则是另一半问题：**「这个包值不值得信任，以及解开之后会不会伤到我」**。

| 维度 | 传统解压器 | UnpackGuard |
| --- | --- | --- |
| 默认对待 `../` | 直接拼接写出 | 默认拒绝，或按策略改写入política可控目录 |
| 压缩炸弹 | 解到磁盘写满为止 | 先算压缩比/总体积，超阈值即告警并中止 |
| 符号链接 | 原样创建 | 默认拒绝，尤其拦截指向外部的链接目标 |
| NTFS 流 / 保留设备名 | 交给文件系统 | 剥离或改写后再落盘 |
| GBK/Big5 乱码文件名 | 显示为一坨乱码 | 自动识别编码并还原可读名称 |
| 机器可读报告 | 无 | JSON + SARIF 2.1.0 + CI 退出码 |
| 依赖 | 各不相同 | **零依赖，纯标准库** |

> 本项目**仅在归档提取这一通用领域做参考**，全部代码 100% 自研实现，不复制任何第三方项目的源码。

---

## ✨ 核心特性

- 🔍 **26 条规则的安全审计**：`UPG001`–`UPG026`，覆盖路径穿越、绝对路径、盘符/UNC、NTFS ADS、符号链接逃逸、压缩炸弹、敏感路径（`.git` / `.ssh` / 私钥）、setuid 位、双重后缀伪装、不可见双向控制字符等。
- 🧮 **0–100 安全评分 + A~F 等级**：每条规则带权重，单条规则封顶计权，避免一条规则刷屏掩盖其它风险。
- 🧯 **策略化解压**：`--flat`、`--strip N`、`--encoding`、`--allow-links`、`--no-perms` 等细粒度开关，默认保守。
- 📐 **体积预算与容量预估**：`plan` 子命令按 4 KiB 对齐估算真实占盘量，含 worst-case 与剩余空间校验。
- 🧬 **嵌套归档识别**：通过 magic bytes 识别包中包（`-1` 层>ZIP/7z/RAR/tar…），层级超阈值即告警。
- 🈶 **乱码文件名修复**：内置 GB18030 / Big5 / Shift-JIS / CP437 候选编码评分 heuristics，自动把「╓╨╬─.txt」还原回「中文合同.txt」。
- 🔐 **流式写入 + 边写边刹车**：解包过程中实时累计字节数，超过 `--max-total-size` 立刻中止，不会先把磁盘写满再报错。
- 🧾 **结构化输出**：`--json` / `--sarif`（SARIF 2.1.0）/ 纯文本三种渲染器。
- 🚦 **CI 友好**：`--fail-level critical|high|medium|low|none` 精确控制流水线门禁。
- 🧪 **零依赖 + 全离线**：只用 `zipfile` / `tarfile` / `gzip` / `bz2` / `lzma`，无网络请求。
- 🐍 **Python 3.9+，纯标准库，114 个单元测试**（`unittest`，无需 pytest）。

---

## 🚀 快速开始

### 环境要求

- Python **3.9 或更高版本**
- 无其它依赖（Linux / macOS / Windows 通吃）

### 安装

```bash
# 方式一：从 PyPI 安装（推荐）
pip install unpackguard

# 方式二：从源码安装（可编辑模式，便于二次开发）
git clone https://github.com/gitstq/UnpackGuard.git
cd UnpackGuard
pip install -e .

# 方式三：零安装，直接跑仓库里的包
python -m unpackguard --help
```

### 一行上手

```bash
# 1) 这是什么格式？（不信任扩展名，只看 magic bytes）
unpackguard sniff download.bin

# 2) 列出成员，不落盘
unpackguard inspect download.zip --limit 50

# 3) 安全扫描
unpackguard scan download.zip

# 4) 预估体积是否装得下
unpackguard plan huge.tar.gz --dest ./out

# 5) 安全解压
unpackguard extract download.zip --dest ./out --max-total-size 1GiB
```

---

## 📖 详细使用指南

### 命令总览

| 命令 | 作用 | 典型场景 |
| --- | --- | --- |
| `sniff` | magic bytes 识别真实格式 | CI 下载物扩展名不可信 |
| `inspect` | 枚举成员元信息 | 先看清单再决定要不要解 |
| `scan` | 安全审计（默认命令） | 门禁检查、人工复核 |
| `plan` | 体积/空间预算 | 磁盘快满时的保护 |
| `extract` | 按策略落盘 | 真正的解包动作 |

> 不带子命令时，默认执行 `scan`。`unpackguard foo.zip` == `unpackguard scan foo.zip`。

### 1. 扫描并输出人类可读报告

```bash
$ unpackguard scan sample.zip
UnpackGuard scan: sample.zip
  format    ZIP archive
  members   19 (19 files)
  expands   262 B

  score     0/100  grade 🔴 F  worst=critical
  findings  🚨 1  🔴 5  🟡 10  🔵 6  ℹ️ 0

Findings
  🚨 CRITICAL
    UPG001 [a/b/../../escape.txt]
      'a/b/../../escape.txt' contains a '..' component
      remedy: reject or extract with --no-traversal dropped components
```

### 2. CI 门禁

```bash
# 出现 high 及以上风险就失败（默认），失败的退出码是 2
unpackguard scan artifact.zip --fail-level high

# 只看最关键的问题
unpackguard scan artifact.zip --fail-level critical --quiet

# 完全交给其它系统判断，永远返回 0
unpackguard scan artifact.zip --fail-level none --json > report.json
```

### 3. 生成 SARIF 报告并上传 GitHub code scanning

```bash
unpackguard scan artifact.zip --sarif > unpackguard.sarif
```

```yaml
- name: UnpackGuard audit
  run: unpackguard scan artifact.zip --sarif > unpackguard.sarif
- name: Upload SARIF
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: unpackguard.sarif
```

### 4. 修复 GBK/Big5 乱码文件名

很多老归档把 UTF-8 标志位留空，直接解出来就是乱码。UnpackGuard 会按编码评分自动还原：

```bash
$ unpackguard inspect legacy.zip
NAME                     TYPE   SIZE     PACKED   NOTE
中文合同.txt              file   8 B      -        gb18030
報告-2026.pdf            file   8 B      -        big5
plain.txt                file   8 B      -        -
```

也可以强制指定：

```bash
unpackguard inspect legacy.zip --encoding gbk
```

### 5. 常见使用组合

```bash
# 扁平化：忽略目录结构，同名自动去重后缀
unpackguard extract drop.zip --dest ./out --flat

# 去掉最外层目录（等价于 tar --strip-components=1）
unpackguard extract release.tar.gz --dest ./out --strip 1

# 允许符号链接（仅在完全信任来源时）
unpackguard extract trusted.tar --dest ./out --allow-links

# 严格模式：任何 ../ 或绝对路径直接拒绝写出（而不是改写）
unpackguard extract hostile.zip --dest ./out --reject-absolute --reject-traversal

# 限制资源：最多写 100MB、最多 5000 个文件
unpackguard extract drop.zip --dest ./out --max-total-size 100MiB --max-files 5000

# 先看看会写哪些文件，什么都不落盘
unpackguard extract drop.zip --dest ./out --dry-run
```

### 6. 作为 Python 库使用

```python
from unpackguard.reader import open_archive
from unpackguard.rules import ScanConfig, scan_archive
from unpackguard.safety import PathPolicy
from unpackguard.extract import ExtractConfig, extract_archive
from unpackguard.sniff import sniff_file

fmt = sniff_file("upload.zip")
archive = open_archive("upload.zip", fmt)

result = scan_archive(archive, ScanConfig(max_ratio=100), PathPolicy())
print(result.score, result.grade, result.worst)
for finding in result.findings:
    print(f"{finding.rule} {finding.severity} {finding.member}: {finding.detail}")

if result.score >= 90:
    outcome = extract_archive(archive, "./out", PathPolicy(),
                              ExtractConfig(max_total_bytes=512 * 1024 * 1024))
    print(outcome.written, outcome.skipped, outcome.aborted)
```

### 7. 退出码约定

| 退出码 | 含义 |
| --- | --- |
| `0` | 没有达到 `--fail-level` 阈值的发现（或 `plan` 判定空间足够） |
| `1` | 运行时/用法错误（含 `plan` 判定空间不足） |
| `2` | 命中 `--fail-level` 阈值 |
| `3` | 归档无法解析 |

### 8. 规则一览

| 规则 | 说明 | 默认严重度 |
| --- | --- | --- |
| `UPG001` | 成员路径包含 `..` 父目录穿越（Zip-Slip） | critical |
| `UPG002` | POSIX 绝对路径（`/etc/cron.d/...`） | high |
| `UPG003` | Windows 盘符 / UNC 路径 | high |
| `UPG004` | NTFS 备用数据流（NTFS ADS） | high |
| `UPG005` | 符号链接 / 硬链接成员 | high |
| `UPG006` | 链接目标指向归档之外 | critical |
| `UPG007` | Windows 保留设备名（NUL / CON / COM1…） | medium |
| `UPG008` | 成员名含控制字符 | high |
| `UPG009` | 规范化后仍指向归档之外 | critical |
| `UPG010` | 单成员压缩比超阈值（压缩炸弹特征） | high |
| `UPG011` | 累计解压体积超预算 / 成员数超限 | high |
| `UPG012` | 嵌套归档层数超过阈值 | medium |
| `UPG013` | 可执行文件或脚本载荷 | medium |
| `UPG014` | 写入敏感目录（`.git` / `.ssh` / `.aws` …） | high |
| `UPG015` | 非 UTF-8 的遗留编码文件名 | low |
| `UPG016` | 重复成员名 | medium |
| `UPG017` | 大小写不敏感文件系统上的名字碰撞 | medium |
| `UPG018` | setuid / setgid 权限位 | high |
| `UPG019` | 全局可写条目 | low |
| `UPG020` | 加密成员（无法审计内容） | medium |
| `UPG021` | 不合理的时间戳 | low |
| `UPG022` | 特殊文件（FIFO / 字符设备 / 块设备） | medium |
| `UPG023` | 疑似凭据文件名（id_rsa / .env …） | medium |
| `UPG024` | 双向控制字符 / 零宽字符 / 同形异义字 | high |
| `UPG025` | 双重后缀伪装（`invoice.pdf.exe`） | medium |
| `UPG026` | 结尾句点或空格（Windows 会截断） | low |

完整机器可读版本：`unpackguard scan --list-rules`。

---

## 💡 设计思路与迭代规划

### 设计理念

1. **默认保守，按需放开。** 任何可能造成「写到目的地之外」的成员，默认都不会被原样接受。想要宽松行为必须显式给出开关。
2. **读永不产生副作用。** `sniff` / `inspect` / `scan` / `plan` 四个子命令都不写任何文件，可以放心对不可信输入执行。
3. **判决与执行分离。** `safety`（能不能写）与 `extract`（怎么写）是两层独立模块；`rules` 只做观察到的 ERROR:uncate 判断，不碰文件系统。
4. **Minimum trust surface。** 只依赖标准库意味着供应链攻击面几乎为零；这也让它在离线环境、容器最小镜像里都能跑。
5. **机器优先。** 每个结果都能序列化成 JSON / SARIF，方便进入既有安全流水线。

### 技术选型

* **Python 标准库**：`zipfile` / `tarfile` / `gzip` / `bz2` / `lzma` 原生支持 ZIP（含 ZIP64）、TAR 全系、gz/bz2/xz 流，足够覆盖绝大多数归档场景，且天然跨平台。
* **dataclass + slots**：核心数据结构内存友好、可序列化、易测试。
* **unittest**：测试随 Python 自带，`python -m unittest` 即可跑，不必引入 pytest 破坏「零依赖」承诺。
* **为什么不做成 Rust / Go 单文件二进制？** 因为它首要应用场景是 CI 流水线与开发者本机，Python 的零门槛安装比二进制分发更重要；同时纯 Python 更容易被安全团队审计。

### 迭代规划

- [ ] `--recursive` 递归展开嵌套归档，并把内层成员合并进同一份评分；
- [ ] 7z / RAR 的只读解析（不依赖外部二进制）；
- [ ] 内置 CVE/CWE 映射字段，便于合规报表；
- [ ] 支持输出 CycloneDX / SPDX 风格的清单；
- [ ] 交互式 TUI（终端里逐条确认是否放行某个成员）；
- [ ] 可选的 YARA 风格自定义规则文件。

欢迎在 [Issues](https://github.com/gitstq/UnpackGuard/issues) 提出想法，或直接提 PR。

---

## 📦 打包与部署指南

本项目属于**工具库 / CLI 类**，按项目规范**无需发布 Release 二进制**，通过 PyPI 分发即可。

### 本地开发

```bash
git clone https://github.com/gitstq/UnpackGuard.git
cd UnpackGuard
python -m unittest discover -s tests -t .   # 跑测试，零依赖
python -m unpackguard --help                # 免安装运行
```

### 打包

```bash
pip install build
python -m build          # 产出 dist/unpackguard-*.whl 与 .tar.gz
```

### 安装到隔离环境

```bash
python -m venv .venv && source .venv/bin/activate
pip install dist/unpackguard-1.0.0-py3-none-any.whl
```

### 容器中使用

```dockerfile
FROM python:3.12-alpine
COPY dist/unpackguard-*.whl /tmp/
RUN pip install --no-cache-dir /tmp/unpackguard-*.whl
ENTRYPOINT ["unpackguard"]
```

### 兼容环境

| 平台 | 状态 | 说明 |
| --- | --- | --- |
| Linux | ✅ | 完整支持 |
| macOS | ✅ | 大小写不敏感文件系统建议加 `--case-insensitive-fs` |
| Windows | ✅ | Windows 保留设备名与非法字符会被自动清洗（建议配合 --sanitise-windows 使用） |

---

## 🤝 贡献指南

欢迎任何形式的贡献。

**提交规范**（遵循 Angular 约定）：

```
feat: 新增 XX 规则
fix: 修复 XX 边界情况
docs: 补充 XX 文档
refactor: 重构 XX 模块
test: 补充 XX 用例
```

**PR 流程**

1. Fork 仓库并新建分支：`git checkout -b feat/my-feature`
2. 保证 `python -m unittest discover -s tests -t .` 全绿
3. 新功能必须同时补充测试用例
4. 提交 PR，并在描述里说明动机与验证方式

**Issue 反馈规则**请尽量包含：操作系统、Python 版本、触发命令、以及能最小化复现的压缩包（或生成脚本）。

---

## 📄 开源协议

本项目基于 [MIT License](./LICENSE) 开源。你可以自由使用、修改、分发，用于商业项目亦可，但请保留版权声明。软件按「原样」提供，不含任何明示或暗示的担保。
