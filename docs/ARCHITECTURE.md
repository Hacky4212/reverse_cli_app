# Architecture

## Language Split

- C: privilege-sensitive and low-level modules.
- C++: performance-sensitive modules without privilege boundaries.
- Python: UI, CLI, orchestration, and interaction.

本项目定位为逆向分析平台的工程底座。

核心原则：调度层保持轻量，底层能力外接。

## 分层

```text
CLI / UI / API
  |
reverse_framework.api
  |-- Pipeline
  `-- Live Monitor
  |
Analyzers
  |
Native Probe / External Tools
  |
Reports / Future Storage
```

## Python 层职责

- 样本接收
- 元数据提取
- 分析流水线
- 规则调度
- 报告生成
- 外部工具编排
- 对外稳定 API

## 实时层职责

- 订阅进程事件
- 订阅线程事件
- 订阅模块加载事件
- 输出 JSONL 流
- 归一化模块基址
- 给 UI 直接消费

## Native 层职责

- 文件格式解析
- 节区和头结构读取
- 调试器辅助能力
- 内存采集辅助能力
- 内核样本元数据读取
- 指令级分析前置处理

Native：本地编译程序。

## Ring0 安全边界

不在本项目中实现：

- Ring0 注入
- 内核提权
- 漏洞利用
- 驱动绕过
- 渗透执行链

允许实现：

- 驱动样本识别
- 内核 API 风险识别
- IOCTL 暴露面识别
- BYOVD 线索识别
- 签名和证书线索检查
- 内核调试实验室建议
- 混淆/随机地址感知分析

已内置的对应分析器：

- `kernel_security`
- `obfuscation_profile`

## 已接入 native_probe

`native/native_probe` 是 C 探测程序。

当前输出：

- 文件格式
- 文件大小
- magic 字节
- PE 头信息
- PE 节区信息
- ELF 头信息
- JSON 结果

Python 分析器：`native_probe`。

找不到二进制时：

- 不阻断流水线
- 写入 tool status
- 报告中标记 unavailable

## 外部工具建议

- Ghidra：反编译
- capa：能力识别
- YARA：规则匹配
- Rizin/radare2：命令行反汇编
- DIE：壳识别
- 沙箱：动态行为

## 数据模型

- finding：原始分析结果
- issue：需要关注的问题
- indicator：IOC 或线索
- addressing：地址归一化视图
- tool status：工具状态
- error：插件错误

## 生产化建议

- 样本库存对象存储
- 元数据进数据库
- 报告进搜索引擎
- 插件运行加超时隔离
- 外部工具放容器里
- 高风险样本放隔离环境
- 动态分析放沙箱
- 底层能力用 C/Rust 实现
