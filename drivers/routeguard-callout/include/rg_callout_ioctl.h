/* Shared IOCTL definitions — routeguard-callout.sys + routeguard-service */
#pragma once

#include <wdm.h>

#define RG_CALLOUT_DEVICE_NAME      L"\\Device\\RouteGuardCallout"
#define RG_CALLOUT_DOS_DEVICE_NAME  L"\\DosDevices\\RouteGuardCallout"
#define RG_CALLOUT_USER_PATH        L"\\\\.\\RouteGuardCallout"

#define RG_IOCTL_DEVICE_TYPE 0x8000

#define IOCTL_RG_DNS_SET_CONFIG \
    CTL_CODE(RG_IOCTL_DEVICE_TYPE, 0x800, METHOD_BUFFERED, FILE_WRITE_DATA)

#define IOCTL_RG_DNS_GET_STATUS \
    CTL_CODE(RG_IOCTL_DEVICE_TYPE, 0x801, METHOD_BUFFERED, FILE_READ_DATA)

#define IOCTL_RG_DNS_GET_STATS \
    CTL_CODE(RG_IOCTL_DEVICE_TYPE, 0x802, METHOD_BUFFERED, FILE_READ_DATA)

#define RG_DNS_CONFIG_VERSION 1
#define RG_DNS_MAX_EXCLUDED_PIDS 16

#pragma pack(push, 1)

typedef struct _RG_DNS_REDIRECT_CONFIG {
    UINT32 Version;
    BOOLEAN Enabled;
    UINT16 ProxyPort;
    IN_ADDR ProxyV4;
    IN6_ADDR ProxyV6;
    UINT32 ExcludedPidCount;
    UINT32 ExcludedPids[RG_DNS_MAX_EXCLUDED_PIDS];
    UINT32 UpstreamPermitCount;
} RG_DNS_REDIRECT_CONFIG, *PRG_DNS_REDIRECT_CONFIG;

typedef struct _RG_DNS_REDIRECT_STATUS {
    UINT32 Version;
    BOOLEAN Enabled;
    BOOLEAN DriverReady;
    UINT16 ProxyPort;
    UINT32 DriverVersionMajor;
    UINT32 DriverVersionMinor;
} RG_DNS_REDIRECT_STATUS, *PRG_DNS_REDIRECT_STATUS;

typedef struct _RG_DNS_REDIRECT_STATS {
    UINT64 RedirectedV4;
    UINT64 RedirectedV6;
    UINT64 RedirectedTcpV4;
    UINT64 RedirectedTcpV6;
    UINT64 SkippedLoopback;
    UINT64 SkippedExcluded;
    UINT64 SkippedDisabled;
    UINT64 Errors;
} RG_DNS_REDIRECT_STATS, *PRG_DNS_REDIRECT_STATS;

#pragma pack(pop)
