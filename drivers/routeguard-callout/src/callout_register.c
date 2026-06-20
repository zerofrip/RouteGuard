#include "rg_callout_internal.h"

static UINT32 g_RgCalloutIds[4] = { 0 };

static const FWPS_CALLOUT1 g_RgCallouts[] = {
    {
        .calloutKey = &RG_CALLOUT_DNS_DATAGRAM_V4,
        .classifyFn = RgDatagramClassifyV4,
        .notifyFn = RgCommonNotify,
        .flowDeleteFn = NULL,
    },
    {
        .calloutKey = &RG_CALLOUT_DNS_DATAGRAM_V6,
        .classifyFn = RgDatagramClassifyV6,
        .notifyFn = RgCommonNotify,
        .flowDeleteFn = NULL,
    },
    {
        .calloutKey = &RG_CALLOUT_DNS_CONNECT_REDIRECT_V4,
        .classifyFn = RgConnectRedirectClassifyV4,
        .notifyFn = RgCommonNotify,
        .flowDeleteFn = NULL,
    },
    {
        .calloutKey = &RG_CALLOUT_DNS_CONNECT_REDIRECT_V6,
        .classifyFn = RgConnectRedirectClassifyV6,
        .notifyFn = RgCommonNotify,
        .flowDeleteFn = NULL,
    },
};

VOID NTAPI RgCommonNotify(
    _In_ FWPS_CALLOUT_NOTIFY_TYPE notifyType,
    _In_ const GUID* filterKey,
    _Inout_ FWPS_FILTER1* filter)
{
    UNREFERENCED_PARAMETER(notifyType);
    UNREFERENCED_PARAMETER(filterKey);
    UNREFERENCED_PARAMETER(filter);
}

NTSTATUS RgRegisterCallouts(PDEVICE_OBJECT DeviceObject)
{
    NTSTATUS status;
    UINT32 i;
    FWPS_CALLOUT1 callout;

    for (i = 0; i < ARRAYSIZE(g_RgCallouts); i++) {
        RtlCopyMemory(&callout, &g_RgCallouts[i], sizeof(FWPS_CALLOUT1));
        callout.flags = 0;

        status = FwpsCalloutRegister1(
            DeviceObject,
            &callout,
            &g_RgCalloutIds[i]);

        if (!NT_SUCCESS(status)) {
            while (i > 0) {
                i--;
                FwpsCalloutUnregisterById0(g_RgCalloutIds[i]);
                g_RgCalloutIds[i] = 0;
            }
            return status;
        }
    }
    return STATUS_SUCCESS;
}

VOID RgUnregisterCallouts(VOID)
{
    UINT32 i;
    for (i = 0; i < ARRAYSIZE(g_RgCalloutIds); i++) {
        if (g_RgCalloutIds[i] != 0) {
            FwpsCalloutUnregisterById0(g_RgCalloutIds[i]);
            g_RgCalloutIds[i] = 0;
        }
    }
}
