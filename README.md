# PE 普通导入表取证库

从可疑 Windows PE/COFF 程序（PE32 与 PE32+）中提取普通导入表信息，
供上层文件扫描流程调用。样本只读，结果全部保存在内存。

## 用法

```python
from pe_import_forensics import extract, Status

with open("sample.exe", "rb") as fh:
    result = extract(fh.read())

for dll in result.dlls:
    print(dll.dll_name, dll.status)
    for func in dll.functions:
        print("  ", func.name or f"ordinal={func.ordinal}", func.status)
        print("   evidence:", func.evidence.fragments)
```

## 结果模型

- `ImportResult`：顶层结果，`status` 区分 `COMPLETE` / `PARTIAL` /
  `UNREADABLE`，`anomalies` 记录结构异常（截断、越界、保留位等）。
- `DllImport`：一个导入描述符对应的 DLL，含名称、函数列表及证据。
- `ImportedFunction`：按名称（`hint` + `name`）或序号（`ordinal`）
  导入的函数；重复项不合并。
- `Evidence` / `Fragment`：支撑结论的原始文件偏移片段；跨多段文件
  位置的对象保留全部片段。

## 映射与容错规则

- 头部覆盖 `[0, SizeOfHeaders)`；区段跨度取 `VirtualSize` 与
  `SizeOfRawData` 的较大值，前 `SizeOfRawData` 字节映射文件内容，
  其余为虚拟补零（不产生字节，也不充当字符串/表结束符）。
- 任一字节落入多个映射来源即视为歧义，不可读取；地址计算不回绕，
  超出 32 位地址空间的区段记为异常并排除。
- 导入描述符按 20 字节解释，读取范围受目录 `Size` 约束，只有完整
  全零描述符正常结束；名称与 thunk 表不受该 `Size` 约束。
- 损坏限制在受影响分支：坏函数名、坏 DLL 名、坏 thunk 表均不影响
  其余可解析部分；描述符不可读时停止该表并保留已有证据。

## 测试

```sh
python3 -m pytest tests -q
```
