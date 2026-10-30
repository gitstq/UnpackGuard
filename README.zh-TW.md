<div align="center">

# 🛡️ UnpackGuard

**像有人要攻擊你一樣去解壓縮檔 —— 零依賴、離線優先的歸檔安全稽核與策略化解壓引擎**

[简体中文](./README.md) | [繁體中文](#繁體中文) | [English](./README.en.md)

[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue
.svg)](https://www.python.org/)
[![License: MIT](https://img.shields關.io/badge/license-MIT-green.svg)](./LICENSE)
[![Zero dependencies](https://img.shields.io/badge/dependencies-0-brightgreen.svg)](./pyproject.toml)
[![Offline](https://img.shields.io/badge/network-none-lightgrey.svg)](#設計思路與迭代規劃)

</div>

---

## 🎉 專案介紹

你收到一個壓縮檔。它可能來自使用者上傳、CI 產物、電子郵件附件，或是一個你還沒稽核過的開源專案。你雙擊解開的那一瞬間，它可能正往 `../../` 寫入一隻反彈 shell。

在現代開發流程裡，「下載 → 解壓縮 → 執行」是最被低估的攻擊面之一。Zip-Slip 路徑穿越、壓縮炸彈、NTFS 備用資料流、偽裝成文件的執行檔、Trojan Source 雙向控制字元……多數解壓工具預設選擇「照單全收」，把這些風險原封不動地寫進你的磁碟。

**UnpackGuard** 是這條流程上的守門人。它不是另一個解壓工具，而是**先稽核、再執行**的解壓引擎：

* 🧭 **看得清楚**：不必解開就能列出歸檔中每個成員的名稱、大小、壓縮比、權限、時間戳、巢狀層級；
* 🚦 **判定精準**：26 條內建規則依嚴重程度分級，從提示到 critical 一網打盡，並輸出 **0–100 安全評分**；
* 🧱 **預設就攔得住**：每種危險形態都有對應的策略開關，預設行為一律不外溢到目的目錄之外；
* 🔌 **接得上 CI**：`--json` 供腳本取用，`--sarif` 直接餵給 GitHub code scanning，`--fail-level` 提供可用於流水線的結束碼；
* 📦 **零依賴**：只依賴 Python 標準函式庫，安裝即用，**不連網、不上傳、無遙測**。

### 💡 靈感來源與差異化

社群已有不少優秀的歸檔工具（WinRAR、7-Zip、`unzip`，以及近期很熱門的 HatchZip），但它們主要解決的是「怎麼把東西解開」——HatchZip 更是專注於磁碟空間不足時的原地解壓。它們的預設行為是信任歸檔作者寫的路徑。

UnpackGuard 解決的是另外一半問題：**「這個壓縮檔值不值得信任？解開之後會不會傷到我？」**

| 面向 | 傳統解壓工具 | UnpackGuard |
| --- | --- | --- |
| `../` 成員 | 直接拼接寫出 | 預設拒絕，或依照策略改寫到受控目錄 |
| 壓縮炸彈 | 寫到磁碟滿才報錯 | 事先計算壓縮比與總量，超標即告警並中止 |
| 符號連結 | 原樣建立 | 預設拒絕，特別攔截指向外部的連結目標 |
| NTFS 備用資料流 / 保留裝置名 | 交給檔案系統處理 | 寫入前剝離或改寫 |
| GBK/Big5 亂碼檔名 | 顯示成一片亂碼 | 自動識別編碼並還原可讀檔名 |
| 機器可讀報表 | 無 | JSON + SARIF 2.1.0 + CI 結束碼 |
| 依賴套件 | 各異 | **零依賴，純標準函式庫** |

> 本專案僅借鏡「歸檔提取」這個通用問題域，全部程式碼皆自行撰寫，未複製任何第三方專案的原始碼。

---

## ✨ 核心特性

- 🔍 **26 條規則的安全稽核**：`UPG001`–`UPG026`，涵蓋路徑穿越、絕對路徑、磁碟機代號/UNC、NTFS ADS、符號連結逃逸、壓縮炸彈、敏感路徑（`.git` / `.ssh` / 私鑰）、setuid 位元、雙重副檔名偽裝、不可見雙向控制字元等。
- 🧮 **0–100 安全評分 + A~F 等級**：每條規則皆有權重，單一規則計分設有上限，避免單一雜訊規則蓋過其他風險。
- 🧯 **策略化解壓**：`--flat`、`--strip N`、`--encoding`、`--allow-links`、`--no-perms`、`--reject-absolute`、`--reject-traversal`，預設全部保守。
- 📐 **容量預估**：`plan` 子命令以 4 KiB 區塊對齊估算真實佔用，並給出最壞情況與剩餘空間檢查。
- 🧬 **巢狀歸檔辨識**：以 magic bytes 辨識包中包（ZIP / 7z / RAR / tar…），超過層數門檻即告警。
- 🈶 **亂碼檔名修復**：內建 GB18030 / Big5 / Shift-JIS / CP437 編碼評分啟發式，自動把「╓╨╬─.txt」還原成「中文合同.txt」。
- 🔐 **串流寫入並可隨時剎車**：解包時即時累計位元組，`--max-total-size` 超標立即中止，不會先把磁碟寫滿才報錯。
- 🧾 **結構化輸出**：純文字 / `--json` / `--sarif`（SARIF 2.1.0）三種渲染器。
- 🚦 **CI 友善**：`--fail-level critical|high|medium|low|none` 精準控制流水線閘門。
- 🧪 **零依賴 + 全離線**：僅用 `zipfile` / `tarfile` / `gzip` / `bz2` / `lzma`，114 個單元測試（`unittest`，無需 pytest）。

---

## 🚀 快速開始

### 環境需求

- Python **3.9 以上**
- 沒有其他依賴（Linux / macOS / Windows 皆可使用）

### 安裝

```bash
# 方法一：從 PyPI 安裝（推薦）
pip install unpackguard

# 方法二：從原始碼安裝（可編輯模式，方便二次開發）
git clone https://github.com/gitstq/UnpackGuard.git
cd UnpackGuard
pip install -e .

# 方法三：完全不安裝，直接執行套件
python -m unpackguard --help
```

### 五個最常用的指令

```bash
unpackguard sniff download.bin                        # 這到底是什麼格式？（看 magic bytes，不看副檔名）
unpackguard inspect download.zip                      # 列出成員，不寫入任何檔案
unpackguard scan download.zip                         # 安全稽核（預設指令）
unpackguard plan huge.tar.gz --dest ./out             # 預估磁碟空間是否足夠
unpackguard extract download.zip --dest ./out --max-total-size 1GiB
```

---

## 📖 詳細使用指南

| 指令 | 作用 | 典型場景 |
| --- | --- | --- |
| `sniff` | 以 magic bytes 識別真實格式 | 副檔名不可信時 |
| `inspect` | 列舉成員中繼資料 | 先看清單再決定要不要解 |
| `scan` | 安全稽核（預設指令） | CI 閘門、人工複核 |
| `plan` | 容量與可用空間預估 | 磁碟快滿時的保護 |
| `extract` | 依策略寫入磁碟 | 真正的解包動作 |

不带子命令时，`unpackguard foo.zip` 等同於 `unpackguard scan foo.zip`。

### 1. 閱讀掃描報告

```console
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
      remedy: drop it with --reject-traversal, or confirm you trust the source
```

### 2. CI 閘門

```bash
# 出現 high（含）以上風險就失敗，結束碼為 2（預設行為）
unpackguard scan artifact.zip --fail-level high

# 只看最嚴重的問題
unpackguard scan artifact.zip --fail-level critical --quiet

# 永遠回傳 0，把判斷交給其他系統
unpackguard scan artifact.zip --fail-level none --json > report.json
```

### 3. 產生 SARIF 並上傳 GitHub code scanning

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

### 4. 修復 GBK/Big5 亂碼檔名

許多久歸檔沒有設定 UTF-8 旗標，直接解出來就是亂碼。UnpackGuard 會依。

```console
$ unpackguard inspect legacy.zip
NAME                     TYPE   SIZE     PACKED   NOTE
中文合同.txt              file   8 B      -        gb18030
報告-2026.pdf            file   8 B      -        big5
plain.txt                file   8 B      -        -
```

也可強制指定編碼：

```bash
unpackguard inspect legacy.zip --encoding gbk
```

### 5. 常見組合

```bash
# 扁平化：忽略目錄結構，同名檔案自動加後綴
unpackguard extract drop.zip --dest ./out --flat

# 去掉最外層目錄（等同 tar --strip-components=1）
unpackguard extract release.tar.gz --dest ./out --strip 1

# 允許符號連結（僅在完全信任來源時）
unpackguard extract trusted.tar --dest ./out --allow-links

# 嚴格模式：不改写，直接拒絕寫出 ../ 與絕對路徑
unpackguard extract hostile.zip --dest ./out --reject-absolute --reject-traversal

# 限制資源：最多寫 100MB、最多 5000 個檔案
unpackguard extract drop.zip --dest ./out --max-total-size 100MiB --max-files 5000

# 先看會寫出哪些檔案，完全不落盤
unpackguard extract drop.zip --dest ./out --dry-run
```

### 6. 函式庫用法

```python
from unpackguard.extract import ExtractConfig, extract_archive
from unpackguard.reader import open_archive
from unpackguard.rules import ScanConfig, scan_archive
from unpackguard.safety import PathPolicy
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

### 7. 結束碼約定

| 結束碼 | 含義 |
| --- | --- |
| `0` | 未達到 `--fail-level` 閾值（或 `plan` 判定空間足夠） |
| `1` | 執行/用法錯誤（含 `plan` 判定空間不足） |
| `2` | 達到 `--fail-level` 閾值 |
| `3` | 歸檔無法解析 |

### 8. 規則一覽

| 規則 | 說明 | 預設嚴重程度 |
| --- | --- | --- |
| `UPG001` | 成員路徑包含 `..` 上層目錄穿越（Zip-Slip） | critical |
| `UPG002` | POSIX 絕對路徑（`/etc/cron.d/...`） | high |
| `UPG003` | Windows 磁碟機代號 / UNC 路徑 | high |
| `UPG004` | NTFS 備用資料流（ADS） | high |
| `UPG005` | 符號連結 / 硬連結成員 | high |
| `UPG006` | 連結目標指向歸檔之外 | critical |
| `UPG007` | Windows 保留裝置名（NUL / CON / COM1…） | medium |
| `UPG008` | 成員名稱含控制字元 | high |
| `UPG009` | 正規化後仍指向歸檔之外 | critical |
| `UPG010` | 單一成員壓縮比超過閾值（壓縮炸彈特徵） | high |
| `UPG011` | 累計解壓體積 / 成員數超過預算 | high |
| `UPG012` | 巢狀歸檔層數超過閾值 | medium |
| `UPG013` | 可執行檔或腳本酬載 | medium |
| `UPG014` | 寫入敏感目錄（`.git` / `.ssh` / `.aws`…） | high |
| `UPG015` | 非 UTF-8 的舊編碼檔名 | low |
| `UPG016` | 重複的成員名稱 | medium |
| `UPG017` | 大小寫不敏感檔案系統上的名稱衝撞 | medium |
| `UPG018` | setuid / setgid 權限位元 | high |
| `UPG019` | 全域可寫入項目 | low |
| `UPG020` | 加密成員（內容無法稽核） | medium |
| `UPG021` | 不合理的時間戳記 | low |
| `UPG022` | 特殊檔案（FIFO / 字元或區塊裝置） | medium |
| `UPG023` | 疑似憑證檔名（id_rsa / .env…） | medium |
| `UPG024` | 雙向控制字元 / 零寬字元 / 同形異義字 | high |
| `UPG025` | 雙重副檔名偽裝（`invoice.pdf.exe`） | medium |
| `UPG026` | 結尾句點或空格（Windows 會截斷） | low |

完整機器可讀版本請執行：`unpackguard scan --list-rules --json`。

---

## 💡 設計思路與迭代規劃

### 設計理念

1. **預設保守，按需放寬。** 任何可能寫出目的目錄之外的成員，預設都不會被原樣接受；想要寬鬆行為必須明確下指令。
2. **讀取永不產生副作用。** `sniff` / `inspect` / `scan` / `plan` 四個子命令都不寫任何檔案，可安心對不可信輸入執行。
3. **判決與執行分離。** `safety` 決定「能不能寫」，`extract` 決定「怎麼寫」，`rules` 只負責 observation，不碰檔案系統。
4. **最小信任面。** 僅依賴標準函式庫代表供應鏈攻擊面近乎為零，也能在離線環境與極簡容器映像中執行。
5. **機器優先。** 每個結果都能序列化成 JSON / SARIF，方便接入既有的安全流水線。

### 技術選型

* **Python 標準函式庫**：`zipfile` / `tarfile` / `gzip` / `bz2` / `lzma` 原生支援 ZIP（含 ZIP64）、TAR 全系列、gz/bz2/xz 串流，足以涵蓋絕大多數歸檔場景，且天然跨平台。
* **dataclass + slots**：核心資料結構省記憶體、可序列化、易測試。
* **unittest**：隨 Python 自帶，`python -m unittest` 即可執行，不必引入 pytest 而破壞「零依賴」的承諾。
* **為什麼不做成 Rust / Go 單一二進位檔？** 因為首要場景是 CI 與開發者本機，「pip 裝了就能跑」比二進位分發更重要；純 Python 也更容易被安全團隊逐行稽核。

### 迭代規劃

- [x] ZIP / TAR 系列稽核與策略化解壓
- [x] JSON + SARIF 輸出與 CI 友善結束碼
- [ ] `--recursive` 遞迴展開巢狀歸檔並合併評分
- [ ] 7z / RAR 唯讀解析（不依賴外部執行檔）
- [ ] 內建 CVE/CWE 對應欄位，利於合規報表
- [ ] 輸出 CycloneDX / SPDX 風格清單
- [ ] 互動式 TUI：逐條確認是否放行某個成員
- [ ] YARA 風格的自訂規則檔

歡迎到 [Issues](https://github.com/gitstq/UnpackGuard/issues) 提出想法，或直接送 PR。

---

## 📦 打包與部署指南

本專案屬於**工具函式庫 / CLI 類**，依專案規範**無需發布 Release 二進位檔**，透過 PyPI 分发即可。

### 本地開發

```bash
git clone https://github.com/gitstq/UnpackGuard.git
cd UnpackGuard
python -m unittest discover -s tests -t .   # 跑測試，零依賴
python -m unpackguard --help                # 免安裝執行
```

### 打包

```bash
pip install build
python -m build          # 產出 dist/unpackguard-<版本>-py3-none-any.whl 與 .tar.gz
```

### 安裝到隔離環境

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

### 相容環境

| 平台 | 狀態 | 說明 |
| --- | --- | --- |
| Linux | ✅ | 完整支援 |
| macOS | ✅ | APFS / HFS+ 建議加上 `--case-insensitive-fs` |
| Windows | ✅ | 保留 Device 名與非法字元會被自動清洗（建議搭配 `--sanitise-windows`） |

---

## 🤝 貢獻指南

歡迎任何形式的貢獻。

**提交規範**（遵循 Angular 約定）：

```
feat: 新增 XX 規則
fix: 修復 XX 邊界情況
docs: 補充 XX 文件
refactor: 重構 XX 模組
test: 補充 XX 案例
```

**PR 流程**

1. Fork 專案並建立分支：`git checkout -b feat/my-feature`
2. 確保 `python -m unittest discover -s tests -t .` 全綠
3. 新功能必須同時補上測試案例
4. 送出 PR，並在描述中說明動機與驗證方式

**Issue 回報**請盡量附上：作業系統、Python 版本、觸發指令，以及能最小化重現的壓縮檔（或產生該檔的腳本）。

---

## 📄 開源授權

本專案以 [MIT License] 開源。你可以自由使用、修改、散布，亦可用於商業專案，但請保留版權聲明。軟體依「原樣」提供，不含任何明示或暗示的保證。
