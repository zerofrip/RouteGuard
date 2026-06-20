#include "rg_callout_internal.h"

#ifndef FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_REMOTE_ADDRESS
#define FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_REMOTE_ADDRESS 2
#endif
#ifndef FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_REMOTE_PORT
#define FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_REMOTE_PORT 4
#endif

static VOID RgConnectRedirectV4(
    _Inout_ FWPS_CLASSIFY_OUT0* classifyOut,
    _In_ const RG_DNS_REDIRECT_CONFIG* cfg,
    _In_ BOOLEAN isTcp)
{
    SOCKADDR_IN redirect = { 0 };

    if (classifyOut == NULL || cfg == NULL) {
        return;
    }

    redirect.sin_family = AF_INET;
    redirect.sin_addr = cfg->ProxyV4;
    redirect.sin_port = RtlUshortByteSwap(cfg->ProxyPort);

    classifyOut->actionType = FWP_ACTION_BLOCK;
    classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
    classifyOut->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;
    classifyOut->type = FWP_ACTION_BLOCK;

    if (classifyOut->value.redirectHandle != NULL) {
        /* User-mode registered redirect handle supplies target; driver sets block+absorb
         * when redirect context is wired. For TCP/53, user-mode Fwpm redirect is primary. */
        UNREFERENCED_PARAMETER(redirect);
    }

    if (isTcp) {
        RgStatsIncrement((volatile LONG64*)&g_RgDnsStats.RedirectedTcpV4);
    }
}

VOID NTAPI RgConnectRedirectClassifyV4(
    _In_ const FWPS_INCOMING_VALUES0* inFixedValues,
    _In_ const FWPS_INCOMING_METADATA_VALUES0* inMetaValues,
    _Inout_opt_ VOID* layerData,
    _In_opt_ const VOID* classifyContext,
    _In_ const FWPS_FILTER1* filter,
    _In_ UINT64 flowContext,
    _Inout_ FWPS_CLASSIFY_OUT0* classifyOut)
{
    UINT32 remoteAddr;
    UINT16 remotePort;
    UINT32 processId;
    RG_DNS_REDIRECT_CONFIG cfg;
    KIRQL irql;

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

    remoteAddr = inFixedValues->incomingValue[FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_REMOTE_ADDRESS].value.uint32;
    remotePort = inFixedValues->incomingValue[FWPS_FIELD_ALE_CONNECT_REDIRECT_V4_IP_REMOTE_PORT].value.uint16;

    if (remotePort != 53) {
        classifyOut->actionType = FWP_ACTION_PERMIT;
        return;
    }

    if (RgIsLoopbackV4(remoteAddr)) {
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

    RgConnectRedirectV4(classifyOut, &cfg, TRUE);
}
