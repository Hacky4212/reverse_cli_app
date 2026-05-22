# reverse-tools

## 语言分层

- C：权限相关、底层相关。
- C++：性能敏感但不碰权限边界。
- Python：界面、交互、编排。

详细说明见 [docs/LANGUAGE_SPLIT.md](C:/Users/yangxu/Desktop/tools/reverse-tools/main/docs/LANGUAGE_SPLIT.md)。

一个工程化逆向分析框架。

定位：公司安全项目的底座。
Python 负责调度和报告。
C 负责更底层的文件探测能力。

## 当前能力

- 文件哈希
- 文件大小
- 熵值分析
- 可读字符串提取
- IOC 提取
- 可疑能力识别
- Ring0 驱动安全初筛
- BYOVD 线索识别
- Windows kernel 安全分析
- 混淆/随机地址感知分析
- 高熵区域定位
- PE 基础头解析
- ELF 基础头解析
- C native probe 接入
- 外部工具适配
- JSON 报告
- Markdown 报告
- 插件式分析流程
- 实时内核事件流

术语说明：

- PE：Windows 可执行文件
- ELF：Linux 可执行文件
- 熵：数据混乱程度
- IOC：攻击线索
- probe：探测程序
- BYOVD：滥用易受攻击驱动
- Ring0：内核权限层

## 目录结构

```text
reverse_framework/
  analyzers/        分析插件
  core/             上下文和流水线
  api.py            对外 API
  cli.py            Python 命令行入口
  reporting.py      报告生成
native/
  native_probe/     C 底层探测程序
  process_memory_reader/  C 实时进程内存读取程序
docs/               架构文档
tests/              基础测试
samples/            样本目录
reports/            输出报告
```

## 快速使用

当前机器没有 Python 时，可以用 PowerShell 入口：

```powershell
.\reverse-tools.ps1 .\samples\demo.bin
```

Python 入口：

```powershell
zriv shell
zriv -analyze file .\samples\demo.bin
```

## Demo 权限模型

- 登录账号默认从 `reverse-tools.users.json` 读取。
- 如果没有该文件，内置 `admin / admin` 可直接登录。
- `admin` 拥有全部权限。
- `restricted` 只允许 `analyze` 和 `gui`。
- `live` 和 `memory` 当前要求 `admin`。
- GUI 不提供 `live` 和 `memory`。
- GUI 只保留安全的静态分析入口。
- 领导二次确认不在这版 demo 内。

示例用户文件见 `reverse-tools.users.example.json`。

列出分析器：

```powershell
zriv --list-analyzers
```

指定输出目录：

```powershell
zriv -analyze file .\samples\demo.bin --out .\reports
```

指定配置：

```powershell
zriv -analyze file .\samples\demo.bin --config .\reverse-tools.example.json
```

## GUI

```powershell
zriv -gui
zriv shell
```

`reverse-tools-gui` is also available after installation.
Config is optional in the GUI; leave it blank unless you have a JSON file.
The GUI only exposes `Static EXE`, `Code Text`, and `Trace Evidence`.
Dynamic `live` and `memory` actions are CLI-only by design.

## Python API

```python
from pathlib import Path

from reverse_framework import analyze_target

result = analyze_target(Path("samples/demo.bin"))
print(result.findings["kernel_security"])
```

实时模式：

```powershell
zriv -live start --duration 30
```

按进程过滤：

```powershell
zriv -live start --pid 1234
```

按进程名或窗口名过滤：

```powershell
zriv -live start --process-name notepad.exe
zriv -live start --window-title "Untitled - Notepad"
```

实时模式输出 JSONL，适合界面层直接订阅。
建议管理员运行。

## C native probe

构建：

```powershell
cmake -S native\native_probe -B native\native_probe\build
cmake --build native\native_probe\build --config Release
```

Python 默认会自动查找：

```text
native/native_probe/build/Release/native_probe.exe
native/native_probe/build/Debug/native_probe.exe
native/native_probe/build/native_probe.exe
native/native_probe/build/native_probe
```

也可以在配置中指定：

```json
{
  "native_probe_enabled": true,
  "native_probe_path": "native/native_probe/build/Release/native_probe.exe",
  "native_probe_timeout": 30
}
```

PowerShell 入口可手动指定：

```powershell
.\reverse-tools.ps1 .\samples\demo.bin -NativeProbePath .\native\native_probe\build\Release\native_probe.exe
```

## C process memory reader

构建：

```powershell
cmake -S native\process_memory_reader -B native\process_memory_reader\build
cmake --build native\process_memory_reader\build --config Release
```

读取实时进程地址：

```powershell
zriv -memory read --pid 1234 --address 0x7FF00000 --size 64
```

也可以先按进程名或窗口名定位目标：

```powershell
zriv -memory read --address 0x7FF00000 --process-name notepad.exe
```

该能力当前要求 `admin`。

## Ring0 安全边界

本项目不实现 Ring0 注入、提权、渗透。

当前只做防御型检测：

- 识别疑似 `.sys` 驱动
- 识别内核设备名
- 识别 IOCTL 暴露面
- 识别内核内存访问线索
- 识别内核篡改线索
- 识别 BYOVD 相关名称
- 检查 PE 证书表线索
- 归一化模块地址视图

对应实现是 `kernel_security` 分析器。
混淆和地址归一化由 `obfuscation_profile` 和实时层协作处理。

## 实时内核监控

实时监控通过 `live` 模式提供。

它会订阅：

- 进程启动
- 进程退出
- 线程启动
- 线程退出
- 模块加载

输出是 JSONL，适合界面层直接消费。
地址会同时保留绝对值和相对视图。

## 插件开发

新增 analyzer：

1. 新建 `reverse_framework/analyzers/name.py`
2. 实现 `name` 和 `run(context)`
3. 在 `reverse_framework/analyzers/registry.py` 注册
4. 增加测试

## 底层能力边界

结论：Python 不适合承担全部底层逆向能力。

推荐分层：

- Python：编排、规则、报告
- C：格式解析、调试器、内存采集
- Ghidra/capa/YARA：成熟逆向能力
- 沙箱：动态行为分析

更多说明见 `docs/ARCHITECTURE.md`。
