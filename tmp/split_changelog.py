# -*- coding: utf-8 -*-
"""把 README.md 的「更新记录」整段迁移到 CHANGELOG.md（保留全部历史）。"""
src = open('README.md', encoding='utf-8').read()
marker = '## 更新记录'
i = src.index(marker)
live = src[:i].rstrip() + '\n'
history = src[i + len(marker):].lstrip('\n')
header = (
    '# MODPKICA Java 复刻版 —— 完整更新记录（CHANGELOG）\n\n'
    '> 本文件收录 v1.0 起全部版本变更；README 只保留近期摘要。\n'
    '> 版本号规则：`v1.28-r<N>`，r 编号随每次修复/功能轮递增，与 `Admin.VERSION` 对齐。\n\n'
    '## 更新记录\n\n'
)
open('CHANGELOG.md', 'w', encoding='utf-8').write(header + history)
open('tmp/readme_live.md', 'w', encoding='utf-8').write(live)
print('CHANGELOG.md 行数 =', (header + history).count('\n'))
print('README 保留部分行数 =', live.count('\n'))
print('历史首行 =', history.splitlines()[0][:80])
print('历史末行 =', history.rstrip().splitlines()[-1][:80])
