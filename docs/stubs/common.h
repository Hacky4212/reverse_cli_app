// common.h
#pragma once

// 1. 定义暗号 (IOCTL 码)
// FILE_DEVICE_UNKNOWN: 表示我们不是正规硬件
// 0x800: 我们自定义的操作码 (0x800 到 0xFFF 之间可以随便挑)
// METHOD_BUFFERED: 最安全的方式！系统会帮我们在内核里复制一份包裹，防止蓝屏
#define IOCTL_READ_MEMORY CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

// 2. 定义包裹结构体 (你要发给驱动的数据格式)
typedef struct _READ_REQUEST {
    ULONG ProcessId;       // 目标进程的 PID
    PVOID TargetAddress;   // 想要读取的内存地址
    int   ResultValue;     // 驱动读完数据后，装在这个变量里送回来
} READ_REQUEST, * PREAD_REQUEST;