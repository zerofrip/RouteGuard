#pragma once

#include "../include/rg_callout_ioctl.h"
#include "../include/rg_callout_guids.h"

#include <fwpsk.h>
#include <fwpmk.h>

#define RG_DRIVER_TAG 'gRcR'

typedef struct _RG_DEVICE_EXTENSION {
    PDEVICE_OBJECT DeviceObject;
    UNICODE_STRING DeviceName;
    UNICODE_STRING SymbolicLink;
} RG_DEVICE_EXTENSION, *PRG_DEVICE_EXTENSION;

extern RG_DNS_REDIRECT_CONFIG g_RgDnsConfig;
extern RG_DNS_REDIRECT_STATS g_RgDnsStats;
extern KSPIN_LOCK g_RgConfigLock;

NTSTATUS RgCreateDevice(PDRIVER_OBJECT DriverObject);
VOID RgDeleteDevice(PDRIVER_OBJECT DriverObject);

NTSTATUS RgDeviceCreate(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS RgDeviceClose(PDEVICE_OBJECT DeviceObject, PIRP Irp);
NTSTATUS RgDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp);

BOOLEAN RgValidateConfig(_In_ PRG_DNS_REDIRECT_CONFIG Config);
VOID RgApplyConfig(_In_ PRG_DNS_REDIRECT_CONFIG Config);

NTSTATUS RgRegisterCallouts(PDEVICE_OBJECT DeviceObject);
VOID RgUnregisterCallouts(VOID);

VOID RgStatsIncrement(_Inout volatile LONG64* Counter);

BOOLEAN RgIsExcludedPid(_In_ UINT32 ProcessId);
BOOLEAN RgIsLoopbackV4(_In_ UINT32 Addr);
BOOLEAN RgIsLoopbackV6(_In_ const IN6_ADDR* Addr);

/* Callout classify entry points */
VOID NTAPI RgDatagramClassifyV4(
    _In_ const FWPS_INCOMING_VALUES0* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Inout_opt_ VOID* layerData,
    _In_opt_ const VOID* classifyContext,
    _In_ const FWPS_FILTER1* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* classifyOut);

VOID NTAPI RgDatagramClassifyV6(
    _In_ const FWPS_INCOMING_VALUES0* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Inout_opt_ VOID* layerData,
    _In_opt_ const VOID* classifyContext,
    _In_ const FWPS_FILTER1* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* classifyOut);

VOID NTAPI RgConnectRedirectClassifyV4(
    _In_ const FWPS_INCOMING_VALUES0* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Inout_opt_ VOID* layerData,
    _In_opt_ const VOID* classifyContext,
    _In_ const FWPS_FILTER1* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* classifyOut);

VOID NTAPI RgConnectRedirectClassifyV6(
    _In_ const FWPS_INCOMING_VALUES0* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Inout_opt_ VOID* layerData,
    _In_opt_ const VOID* classifyContext,
    _In_ const FWPS_FILTER1* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* classifyOut);

VOID NTAPI RgCommonNotify(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    _In_ const GUID* filterKey,
    _Inout_ FWPS_FILTER1* filter);
