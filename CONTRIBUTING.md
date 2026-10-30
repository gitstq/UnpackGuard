MIT License
# 贡献指南 / Contributing

感谢你愿意改进 UnpackGuard。这里只有三条硬性约束，其余随意。

Thanks for improving UnpackGuard. Only three hard rules here — everything else is flexible.

---

## 🧪 本地开发 / Local setup

```bash
git clone https://github.com/gitstq/UnpackGuard.git
cd UnpackGuard
make test      # 跑单元测试，零依赖
make smoke     # 构造样例归档跑一遍端到端
make ci        # lint + test，等价于 CI
```

不需要 pytest / pyenv / tox；只要 Python 3.9+ 就够。

## 📐 提交信息 / Commit style

遵循 Angular 约定（English imperative after the colon）：

```
feat: 新增 XXX 规则
fix: 修复 XXX 边界情况
docs: 补充 XXX 文档
refactor: 重构 XXX 模块
test: 补充 XXX 用例
chore: 更新构建脚本
```

## ✅ PR 检查清单 / PR checklist

- [ ] `make ci` 全绿（Python 3.9–3.13 都要能跑）
- [ ] 新增规则必须同时补充单元测试，且在 `RULE_INDEX` 里登记独一无二的 id
- [ ] 新规则需要在三个 README（简中/繁中/English）的规则表格里同步更新
- [ ] 不引入任何第三方运行时依赖（dev  dependencies 只能放在 `optional-dependencies.dev`）
- [ ] 不新增网络请求：本项目必须保持「离线可用」

## 🐛 反馈 / Reporting issues

请尽量附上：操作系统、Python 版本、完整命令、`unpackguard scan <file> --json` 的输出，以及能最小化复现的压缩包（或生成脚本）。

Please include: OS, Python version, the exact command, the `--json` output, and a minimal reproducer (or the script that builds it).
