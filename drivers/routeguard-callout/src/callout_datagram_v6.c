#include "rg_callout_internal.h"

#ifndef FWPS_FIELD_DATAGRAM_DATA_V6_IP_REMOTE_ADDRESS
#define FWPS_FIELD_DATAGRAM_DATA_V6_IP_REMOTE_ADDRESS 2
#endif
#ifndef FWPS_FIELD_DATAGRAM_DATA_V6_IP_REMOTE_PORT
#define FWPS_FIELD_DATAGRAM_DATA_V6_IP_REMOTE_PORT 4
#endif

static VOID RgPermitClassifyV6(_Inout_ FWPS_CLASSIFY_OUT0* classifyOut)
{
    classifyOut->actionType = FWP_ACTION_PERMIT;
    classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
}

static VOID RgRewriteDatagramV6(
    _Inout_opt_ VOID* layerData,
    _In_ UINT16 proxyPort,
    _In_ const IN6_ADDR* proxyAddr)
{
    NET_BUFFER_LIST* nbl;
    NET_BUFFER* nb;
    ULONG offset;
    PUCHAR p;
    USHORT* portField;

    if (layerData == NULL || proxyAddr == NULL) {
        return;
    }

    nbl = (NET_BUFFER_LIST*)layerData;
    nb = NET_BUFFER_LIST_FIRST_NB(nbl);
    if (nb == NULL) {
        return;
    }

    offset = NET_BUFFER_DATA_OFFSET(nb);
    p = NdisGetDataBuffer(nb, offset + 48, NULL, 1, 0);
    if (p == NULL) {
        return;
    }

    p += offset;
    /* IPv6 header is 40 bytes; dest at offset 24 */
    RtlCopyMemory(p + 24, proxyAddr, sizeof(IN6_ADDR));
    portField = (USHORT*)(p + 40 + 2);
    *portField = RtlUshortByteSwap(proxyPort);
}

VOID NTAPI RgDatagramClassifyV6(
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
        RgPermitClassifyV6(classifyOut);
        return;
    }

    RtlCopyMemory(
        &remoteAddr,
        inFixedValues->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V6_IP_REMOTE_ADDRESS].value.byteArray16,
        sizeof(IN6_ADDR));
    remotePort = inFixedValues->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V6_IP_REMOTE_PORT].value.uint16;

    if (remotePort != 53) {
        RgPermitClassifyV6(classifyOut);
        return;
    }

    if (RgIsLoopbackV6(&remoteAddr)) {
        RgStatsIncrement((volatile LONG64*)&g_RgDnsStats.SkippedLoopback);
        RgPermitClassifyV6(classifyOut);
        return;
    }

    processId = 0;
    if (inMetaValues != NULL &&
        (inMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID)) {
        processId = (UINT32)inMetaValues->processId;
    }

    if (RgIsExcludedPid(processId)) {
        RgStatsIncrement((volatile LONG64*)&g_RgDnsStats.SkippedExcluded);
        RgPermitClassifyV6(classifyOut);
        return;
    }

    RgRewriteDatagramV6(layerData, cfg.ProxyPort, &cfg.ProxyV6);
    RgStatsIncrement((volatile LONG64*)&g_RgDnsStats.RedirectedV6);

    classifyOut->actionType = FWP_ACTION_PERMIT;
    classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
    classifyOut->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;
}
