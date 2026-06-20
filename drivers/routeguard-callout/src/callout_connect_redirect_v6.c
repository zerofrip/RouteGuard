#include "rg_callout_internal.h"

#ifndef FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_IP_REMOTE_ADDRESS
#define FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_IP_REMOTE_ADDRESS 2
#endif
#ifndef FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_IP_REMOTE_PORT
#define FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_IP_REMOTE_PORT 4
#endif

VOID NTAPI RgConnectRedirectClassifyV6(
    _In_ const FWPS_INCOMING_VALUES0* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Inout_opt_ VOID* layerData,
    _In_opt_ const VOID* classifyContext,
    _In_ const FWPS_FILTER1* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* classifyOut)
{
    UINT16 remotePort;
    UINT32 processId;
    RG_DNS_REDIRECT_CONFIG cfg;
    KIRQL irql;
    IN6_ADDR remoteAddr;

    UNREFERENCED_PARAMETER(layerData);
    UNREFERENCED_PARAMETER(classifyContext);
    UNREFERENCED_PARAMETER(filter);
    UNREFERENCED_PARAMETER(flowContext);

    if (classifyOut == NULL || inFixedValues == NULL) {
        return;
    }

    KeAcquireSpinLock(&g_RgConfigLock, &irql);
    RtlCopyMemory(&cfg, &g_RgDnsConfig, sizeof(cfg));
    KeReleaseSpinLock(&g_RgConfigLock, irql);

    if (!cfg.Enabled) {
        RgStatsIncrement((volatile LONG64*)&g_RgDnsStats.SkippedDisabled);
        classifyOut->actionType = FWP_ACTION_PERMIT;
        return;
    }

    RtlCopyMemory(
        &remoteAddr,
        inFixedValues->incomingValue[FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_IP_REMOTE_ADDRESS].value.byteArray16,
        sizeof(IN6_ADDR));
    remotePort = inFixedValues->incomingValue[FWPS_FIELD_ALE_CONNECT_REDIRECT_V6_IP_REMOTE_PORT].value.uint16;

    if (remotePort != 53) {
        classifyOut->actionType = FWP_ACTION_PERMIT;
        return;
    }

    if (RgIsLoopbackV6(&remoteAddr)) {
        RgStatsIncrement((volatile LONG64*)&g_RgDnsStats.SkippedLoopback);
        classifyOut->actionType = FWP_ACTION_PERMIT;
        return;
    }

    processId = 0;
    if (inMetaValues != NULL &&
        (inMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID)) {
        processId = (UINT32)inMetaValues->processId;
    }

    if (RgIsExcludedPid(processId)) {
        RgStatsIncrement((volatile LONG64*)&g_RgDnsStats.SkippedExcluded);
        classifyOut->actionType = FWP_ACTION_PERMIT;
        return;
    }

    RgStatsIncrement((volatile LONG64*)&g_RgDnsStats.RedirectedTcpV6);
    classifyOut->actionType = FWP_ACTION_PERMIT;
    classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
}
