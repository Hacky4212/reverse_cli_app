// main.cpp (Ring 3)
#include <windows.h>
#include <iostream>
#include "common.h"

int main() {
    // 1. 就像打开一个普通文本文件一样，打开我们的驱动设备
    // \\.\MyMemoryDriver 是驱动在系统里注册的虚拟名称
    HANDLE hDevice = CreateFile(L"\\\\.\\MyMemoryDriver", GENERIC_READ | GENERIC_WRITE,
        0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);

    if (hDevice == INVALID_HANDLE_VALUE) {
        std::cout << "无法连接到驱动！请确认驱动是否已加载。" << std::endl;
        return -1;
    }

    // 2. 准备要发送的包裹
    READ_REQUEST request;
    request.ProcessId = 8848;                     // 假设你查到了测试包的 PID 是 8848
    request.TargetAddress = (PVOID)0x00AABBCC;    // 假设这是你用 CE 找出的真实地址
    request.ResultValue = 0;                      // 清零等待接收

    // 3. 发射指令 (核心 API)
    DWORD bytesReturned = 0;
    BOOL bResult = DeviceIoControl(
        hDevice,                // 驱动句柄
        IOCTL_READ_MEMORY,      // 我们的暗号
        &request,               // 发送的包裹包
        sizeof(request),        // 发送包裹的大小
        &request,               // 接收的包裹 (我们把同一个包裹扔过去装数据)
        sizeof(request),        // 接收包裹的大小
        &bytesReturned,         // 实际返回的字节数
        NULL
    );

    if (bResult) {
        std::cout << "驱动越权读取成功！目标数据的值是: " << request.ResultValue << std::endl;
    }
    else {
        std::cout << "驱动读取失败！" << std::endl;
    }

    CloseHandle(hDevice);
    return 0;
}