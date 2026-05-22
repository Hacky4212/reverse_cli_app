// driver.c (Ring 0)
#include <ntifs.h>
#include "common.h"

// 这是一个统一的调度函数，负责拦截 Ring 3 发来的所有 IRP (请求包裹)
NTSTATUS DispatchIoctl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
    UNREFERENCED_PARAMETER(DeviceObject);
    NTSTATUS status = STATUS_SUCCESS;

    // 获取当前请求的信息包
    PIO_STACK_LOCATION irpStack = IoGetCurrentIrpStackLocation(Irp);

    // 如果暗号对上了，说明这是我们 Ring 3 发来的要求读内存的指令
    if (irpStack->Parameters.DeviceIoControl.IoControlCode == IOCTL_READ_MEMORY) {

        // SystemBuffer 就是系统帮我们把 Ring 3 的包裹复制进内核的数据
        PREAD_REQUEST request = (PREAD_REQUEST)Irp->AssociatedIrp.SystemBuffer;

        DbgPrint("[MyDriver] 收到指令！目标 PID: %d, 地址: %p\n", request->ProcessId, request->TargetAddress);

        // ========================================================
        // 在这里调用我们之前写的那个 PsLookupProcessByProcessId 
        // 以及 MmCopyVirtualMemory 去读取数据！
        // 假设我们读到了数据，存进了 ReadTemp 变量里
        // ========================================================
        int ReadTemp = 999; // 模拟读取成功

        // 把读出来的数据，塞回给 Ring 3 的包裹里
        request->ResultValue = ReadTemp;

        // 告诉系统我们往包裹里塞了多大的数据回去
        Irp->IoStatus.Information = sizeof(READ_REQUEST);
    }
    else {
        status = STATUS_INVALID_PARAMETER;
        Irp->IoStatus.Information = 0;
    }

    // 结束这个 IRP 请求，把包裹顺着原路发还给 Ring 3
    Irp->IoStatus.Status = status;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);

    return status;
}

// 驱动入口
NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
    UNREFERENCED_PARAMETER(RegistryPath);

    UNICODE_STRING devName;
    UNICODE_STRING symLinkName;
    PDEVICE_OBJECT deviceObject = NULL;

    RtlInitUnicodeString(&devName, L"\\Device\\MyMemoryDriver");
    RtlInitUnicodeString(&symLinkName, L"\\DosDevices\\MyMemoryDriver"); // 这就是给 Ring 3 用 CreateFile 找的名字

    // 1. 创建一个设备对象
    IoCreateDevice(DriverObject, 0, &devName, FILE_DEVICE_UNKNOWN, FILE_DEVICE_SECURE_OPEN, FALSE, &deviceObject);

    // 2. 创建符号链接 (打通 Ring 3 到 Ring 0 的隧道)
    IoCreateSymbolicLink(&symLinkName, &devName);

    // 3. 极其重要：告诉系统，如果 Ring 3 调用了 DeviceIoControl，就去执行我们的 DispatchIoctl 函数
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = DispatchIoctl;

    // 还需要设置打开和关闭设备的函数 (为了代码精简，这里省略了默认成功的占位函数)

    DbgPrint("[MyDriver] 狙击手已就位，等待 Ring 3 指令...\n");
    return STATUS_SUCCESS;
}