#include "rg_callout_internal.h"

static PDEVICE_OBJECT g_RgDeviceObject = NULL;

NTSTATUS RgCreateDevice(PDRIVER_OBJECT DriverObject)
{
    NTSTATUS status;
    UNICODE_STRING deviceName;
    UNICODE_STRING symLink;

    RtlInitUnicodeString(&deviceName, RG_CALLOUT_DEVICE_NAME);
    RtlInitUnicodeString(&symLink, RG_CALLOUT_DOS_DEVICE_NAME);

    status = IoCreateDevice(
        DriverObject,
        sizeof(RG_DEVICE_EXTENSION),
        &deviceName,
        FILE_DEVICE_UNKNOWN,
        FILE_DEVICE_SECURE_OPEN,
        FALSE,
        &g_RgDeviceObject);

    if (!NT_SUCCESS(status)) {
        return status;
    }

    status = IoCreateSymbolicLink(&symLink, &deviceName);
    if (!NT_SUCCESS(status)) {
        IoDeleteDevice(g_RgDeviceObject);
        g_RgDeviceObject = NULL;
        return status;
    }

    g_RgDeviceObject->Flags |= DO_BUFFERED_IO;
    g_RgDeviceObject->Flags &= ~DO_DEVICE_INITIALIZING;

    return STATUS_SUCCESS;
}

VOID RgDeleteDevice(PDRIVER_OBJECT DriverObject)
{
    UNICODE_STRING symLink;
    UNREFERENCED_PARAMETER(DriverObject);

    RtlInitUnicodeString(&symLink, RG_CALLOUT_DOS_DEVICE_NAME);
    IoDeleteSymbolicLink(&symLink);

    if (g_RgDeviceObject != NULL) {
        IoDeleteDevice(g_RgDeviceObject);
        g_RgDeviceObject = NULL;
    }
}

NTSTATUS RgDeviceCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS RgDeviceClose(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    UNREFERENCED_PARAMETER(DeviceObject);
    Irp->IoStatus.Status = STATUS_SUCCESS;
    Irp->IoStatus.Information = 0;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return STATUS_SUCCESS;
}

NTSTATUS RgDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp)
{
    NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
    PIO_STACK_LOCATION irpSp;
    ULONG code;
    PVOID buffer;
    ULONG inLen;
    ULONG outLen;
    ULONG bytesReturned = 0;

    UNREFERENCED_PARAMETER(DeviceObject);

    irpSp = IoGetCurrentIrpStackLocation(Irp);
    code = irpSp->Parameters.DeviceIoControl.IoControlCode;
    buffer = Irp->AssociatedIrp.SystemBuffer;
    inLen = irpSp->Parameters.DeviceIoControl.InputBufferLength;
    outLen = irpSp->Parameters.DeviceIoControl.OutputBufferLength;

    switch (code) {
    case IOCTL_RG_DNS_SET_CONFIG:
        if (buffer == NULL || inLen < sizeof(RG_DNS_REDIRECT_CONFIG)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        if (!RgValidateConfig((PRG_DNS_REDIRECT_CONFIG)buffer)) {
            status = STATUS_INVALID_PARAMETER;
            break;
        }
        RgApplyConfig((PRG_DNS_REDIRECT_CONFIG)buffer);
        status = STATUS_SUCCESS;
        break;

    case IOCTL_RG_DNS_GET_STATUS:
        if (buffer == NULL || outLen < sizeof(RG_DNS_REDIRECT_STATUS)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        {
            PRG_DNS_REDIRECT_STATUS st = (PRG_DNS_REDIRECT_STATUS)buffer;
            KIRQL irql;
            RtlZeroMemory(st, sizeof(RG_DNS_REDIRECT_STATUS));
            st->Version = RG_DNS_CONFIG_VERSION;
            st->DriverVersionMajor = 1;
            st->DriverVersionMinor = 0;
            st->DriverReady = TRUE;
            KeAcquireSpinLock(&g_RgConfigLock, &irql);
            st->Enabled = g_RgDnsConfig.Enabled;
            st->ProxyPort = g_RgDnsConfig.ProxyPort;
            KeReleaseSpinLock(&g_RgConfigLock, irql);
            bytesReturned = sizeof(RG_DNS_REDIRECT_STATUS);
            status = STATUS_SUCCESS;
        }
        break;

    case IOCTL_RG_DNS_GET_STATS:
        if (buffer == NULL || outLen < sizeof(RG_DNS_REDIRECT_STATS)) {
            status = STATUS_BUFFER_TOO_SMALL;
            break;
        }
        RtlCopyMemory(buffer, (PVOID)&g_RgDnsStats, sizeof(RG_DNS_REDIRECT_STATS));
        bytesReturned = sizeof(RG_DNS_REDIRECT_STATS);
        status = STATUS_SUCCESS;
        break;

    default:
        status = STATUS_INVALID_DEVICE_REQUEST;
        break;
    }

    Irp->IoStatus.Status = status;
    Irp->IoStatus.Information = bytesReturned;
    IoCompleteRequest(Irp, IO_NO_INCREMENT);
    return status;
}

PDEVICE_OBJECT RgGetDeviceObject(VOID)
{
    return g_RgDeviceObject;
}
