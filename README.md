# task26100386

PE 普通导入表取证库（纯 Python，无第三方依赖）。从可疑 Windows 程序中
提取导入信息，面向畸形区段、重叠地址与截断结构保留可追溯的部分证据。

## 用法

```python
from pe_imports import extract_imports

result = extract_imports(open("sample.exe", "rb").read())
for dll in result.dlls:
    print(dll.name, dll.name_status)
    for fn in dll.functions:
        print("  ", fn.name or f"#{fn.ordinal}", fn.status, fn.evidence)
```

- 支持 PE32 与 PE32+ 的普通导入目录（数据目录索引 1）。
- `ImportForensics.complete` 仅在找到完整全零描述符且无任何异常时为真。
- 每个对象的 `evidence` 保留全部文件片段（`Fragment(file_offset, data)`），
  跨区段对象会有多个片段；重复导入项不合并。
- 可读性分三级：`Status.COMPLETE` / `PARTIAL` / `UNREADABLE`。
- 歧义映射（一个字节落入多个来源）、虚拟补零、文件截断均不产生字节，
  也不充当字符串或表的结束标记。

## 测试

```bash
python3 -m pytest tests/ -q
```
