#include "rg_callout_internal.h"

PDEVICE_OBJECT RgGetDeviceObject(VOID);

DRIVER_INITIALIZE DriverEntry;
DRIVER_UNLOAD RgDriverUnload;

NTSTATUS
DriverEntry(
    _In_ PDRIVER_OBJECT DriverObject,
    _In_ PUNICODE_STRING RegistryPath)
{
    NTSTATUS status;

    UNREFERENCED_PARAMETER(RegistryPath);

    KeInitializeSpinLock(&g_RgConfigLock);
    RtlZeroMemory(&g_RgDnsConfig, sizeof(g_RgDnsConfig));
    g_RgDnsConfig.Version = RG_DNS_CONFIG_VERSION;
    g_RgDnsConfig.ProxyPort = 5353;
    g_RgDnsConfig.ProxyV4.S_un.S_addr = RtlUlongByteSwap(0x7F000001); /* 127.0.0.1 */
    IN6ADDR_SET_LOOPBACK(&g_RgDnsConfig.ProxyV6);

    DriverObject->DriverUnload = RgDriverUnload;
    DriverObject->MajorFunction[IRP_MJ_CREATE] = RgDeviceCreate;
    DriverObject->MajorFunction[IRP_MJ_CLOSE] = RgDeviceClose;
    DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = RgDeviceControl;

    status = RgCreateDevice(DriverObject);
    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = RgRegisterCallouts(RgGetDeviceObject());
    if (!NT_SUCCESS(status)) {
        RgDeleteDevice(DriverObject);
        return status;
    }

    return STATUS_SUCCESS;
}

VOID
RgDriverUnload(
    _In_ PDRIVER_OBJECT DriverObject)
{
    RgUnregisterCallouts();
    RgDeleteDevice(DriverObject);
}
