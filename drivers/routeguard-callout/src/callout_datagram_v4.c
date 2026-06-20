#include "rg_callout_internal.h"

/* FWPS_FIELD_DATAGRAM_DATA_V4_* indices from fwpsk.h */
#ifndef FWPS_FIELD_DATAGRAM_DATA_V4_IP_REMOTE_ADDRESS
#define FWPS_FIELD_DATAGRAM_DATA_V4_IP_REMOTE_ADDRESS 2
#endif
#ifndef FWPS_FIELD_DATAGRAM_DATA_V4_IP_REMOTE_PORT
#define FWPS_FIELD_DATAGRAM_DATA_V4_IP_REMOTE_PORT 4
#endif
#ifndef FWPS_FIELD_DATAGRAM_DATA_V4_IP_LOCAL_ADDRESS
#define FWPS_FIELD_DATAGRAM_DATA_V4_IP_LOCAL_ADDRESS 0
#endif
#ifndef FWPS_FIELD_DATAGRAM_DATA_V4_IP_LOCAL_PORT
#define FWPS_FIELD_DATAGRAM_DATA_V4_IP_LOCAL_PORT 3
#endif

static VOID RgPermitClassify(_Inout_ FWPS_CLASSIFY_OUT0* classifyOut)
{
    classifyOut->actionType = FWP_ACTION_PERMIT;
    classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
}

static VOID RgRewriteDatagramV4(
    _Inout_opt_ VOID* layerData,
    _In_ UINT16 proxyPort,
    _In_ IN_ADDR proxyAddr)
{
    NET_BUFFER_LIST* nbl;
    NET_BUFFER* nb;
    ULONG offset;
    PUCHAR p;
    UINT32 ipHeaderLen;
    USHORT* portField;

    if (layerData == NULL) {
        return;
    }

    nbl = (NET_BUFFER_LIST*)layerData;
    nb = NET_BUFFER_LIST_FIRST_NB(nbl);
    if (nb == NULL) {
        return;
    }

    offset = NET_BUFFER_DATA_OFFSET(nb);
    p = NdisGetDataBuffer(nb, offset + 28, NULL, 1, 0);
    if (p == NULL) {
        return;
    }

    p += offset;
    ipHeaderLen = (p[0] & 0x0F) * 4;
    if (ipHeaderLen < 20) {
        return;
    }

    /* Rewrite destination IP to loopback proxy */
    RtlCopyMemory(p + 16, &proxyAddr.S_un.S_addr, 4);

    /* UDP header: dest port at ipHeaderLen + 2 */
    portField = (USHORT*)(p + ipHeaderLen + 2);
    *portField = RtlUshortByteSwap(proxyPort);

    /* Fix IPv4 checksum (simple zero + recompute would go here in production) */
    ((USHORT*)p)[5] = 0;
    /* UDP checksum zeroed for loopback — acceptable for local delivery */
    ((USHORT*)(p + ipHeaderLen + 6))[0] = 0;
}

VOID NTAPI RgDatagramClassifyV4(
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
        RgPermitClassify(classifyOut);
        return;
    }

    remoteAddr = inFixedValues->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V4_IP_REMOTE_ADDRESS].value.uint32;
    remotePort = inFixedValues->incomingValue[FWPS_FIELD_DATAGRAM_DATA_V4_IP_REMOTE_PORT].value.uint16;

    if (remotePort != 53) {
        RgPermitClassify(classifyOut);
        return;
    }

    if (RgIsLoopbackV4(remoteAddr)) {
        RgStatsIncrement((volatile LONG64*)&g_RgDnsStats.SkippedLoopback);
        RgPermitClassify(classifyOut);
        return;
    }

    processId = 0;
    if (inMetaValues != NULL &&
        (inMetaValues->currentMetadataValues & FWPS_METADATA_FIELD_PROCESS_ID)) {
        processId = (UINT32)inMetaValues->processId;
    }

    if (RgIsExcludedPid(processId)) {
        RgStatsIncrement((volatile LONG64*)&g_RgDnsStats.SkippedExcluded);
        RgPermitClassify(classifyOut);
        return;
    }

    RgRewriteDatagramV4(layerData, cfg.ProxyPort, cfg.ProxyV4);
    RgStatsIncrement((volatile LONG64*)&g_RgDnsStats.RedirectedV4);

    classifyOut->actionType = FWP_ACTION_PERMIT;
    classifyOut->rights &= ~FWPS_RIGHT_ACTION_WRITE;
    classifyOut->flags |= FWPS_CLASSIFY_OUT_FLAG_ABSORB;
}
