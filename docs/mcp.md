# GEF MCP Server

GEF MCP Server 提供了 GEF 调试器的 AI Agent 接口，通过 Model Context Protocol (MCP) 实现程序化调试和漏洞分析。

## 安装

### 依赖

```bash
pip install mcp
```

### 启动方式

#### 方式 1: 在 GDB 中使用（推荐）

```bash
# 启动 GDB 并加载 GEF
gdb ./target

# 在 GDB 中加载 MCP Server
source /path/to/gef/mcp/server.py
```

#### 方式 2: 独立运行

```bash
python -m gef.mcp --stdio
```

## 可用工具

### 1. execute_command
执行 GEF/GDB 命令并返回输出。

```python
execute_command(command="vmmap")
execute_command(command="hexdump $rsp 64")
```

### 2. get_registers
获取当前 CPU 寄存器状态。

```python
get_registers()
# 返回: {"registers": {"rax": "0x0", ...}, "pc": "0x400000", "sp": "0x7fffffffe000", "flags": {...}}
```

### 3. inspect_memory
读取并显示指定地址的内存内容。

```python
inspect_memory(address=0x400000, size=64)
# 返回: {"address": "0x400000", "hex": "...", "ascii": "...", "size": 64}
```

### 4. get_memory_map
获取当前进程的内存映射。

```python
get_memory_map()
# 返回: {"regions": [{"start": "0x400000", "end": "0x401000", "permissions": "r-xp", "name": "/path/to/binary", ...}]}
```

### 5. heap_analysis
分析当前堆状态。

```python
heap_analysis()
# 返回: {"chunks": [...], "top": "0x602000", "system_mem": 135168, ...}
```

### 6. stack_analysis
分析当前栈帧。

```python
stack_analysis()
# 返回: {"frames": [{"address": "0x400000", "function": "main", "offset": 0}, ...]}
```

### 7. breakpoint_set
在指定位置设置断点。

```python
breakpoint_set(location="0x400000", type="breakpoint")
breakpoint_set(location="main", type="breakpoint")
breakpoint_set(location="file.c:10", type="breakpoint")
```

### 8. continue_execution
继续程序执行。

```python
continue_execution()
# 返回: {"stopped": true, "reason": "breakpoint", "address": "0x400000"}
```

## 使用场景

### 1. AI 辅助漏洞分析
```python
# AI Agent 可以自动化执行以下流程
registers = get_registers()
memory = inspect_memory(registers["sp"], 256)
heap = heap_analysis()
stack = stack_analysis()
```

### 2. 自动化调试
```python
# 设置断点并继续执行
breakpoint_set("0x400000")
continue_execution()
# 检查寄存器状态
regs = get_registers()
```

### 3. 内存分析
```python
# 获取内存映射并分析特定区域
mmap = get_memory_map()
for region in mmap["regions"]:
    if "heap" in region["name"]:
        content = inspect_memory(int(region["start"], 16), 1024)
        # 分析堆内存
```

## 技术实现

### 架构
- 基于 MCP Python SDK
- 使用 GDB Python API 和 GEF 内部函数
- 结构化 JSON 输出
- 支持 stdio 传输

### 核心 API
- `gdb.execute()` - 执行 GDB 命令
- `gdb.parse_and_eval()` - 解析表达式
- `gdb.selected_inferior()` - 获取当前进程
- `gef.arch` - GEF 架构信息

## 开发

### 添加新工具

在 `mcp/tools.py` 中实现新函数：

```python
def my_new_tool(arg1: str, arg2: int = 10) -> Dict[str, Any]:
    """工具描述"""
    try:
        import gdb
        # 实现逻辑
        result = {"key": "value"}
        return result
    except Exception as e:
        return {"error": str(e)}
```

然后在 `TOOLS` 字典中注册：

```python
TOOLS = {
    "my_new_tool": {
        "function": my_new_tool,
        "description": "工具描述",
        "parameters": {
            "type": "object",
            "properties": {
                "arg1": {"type": "string", "description": "参数1"},
                "arg2": {"type": "integer", "description": "参数2", "default": 10},
            },
            "required": ["arg1"],
        },
    },
}
```

## 许可证

MIT License
