.PHONY: help install install-dev dev test smoke lint build clean ci

PYTHON ?= python3
PKG := unpackguard

help: ## 显示可用目标
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

install: ## 安装到当前环境（可编辑模式）
	$(PYTHON) -m pip install -e .

install-dev: ## 安装开发期依赖
	$(PYTHON) -m pip install --upgrade build twine

dev: install install-dev ## 一次性装好开发所需

test: ## 运行单元测试（零依赖，无需 pytest）
	$(PYTHON) -m unittest discover -s tests -t . -v

smoke: ## 端到端冒烟：构造样例归档并完整跑一遍
	$(PYTHON) scripts/smoke.py

lint: ## 语法/字节码检查
	$(PYTHON) -m compileall -q $(PKG) tests

build: clean ## 构建 wheel 与 sdist
	$(PYTHON) -m build

clean: ## 清理构建产物
	rm -rf build dist *.egg-info .pytest_cache
	find . -name '__pycache__' -type d -prune -exec rm -rf {} +

ci: lint test ## CI 本地等价
