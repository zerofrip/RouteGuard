#include "rg_callout_internal.h"

RG_DNS_REDIRECT_CONFIG g_RgDnsConfig = { 0 };
RG_DNS_REDIRECT_STATS g_RgDnsStats = { 0 };
KSPIN_LOCK g_RgConfigLock;

static BOOLEAN RgIsLoopbackAddrV4(_In_ IN_ADDR addr)
{
    /* 127.0.0.0/8 */
    return (addr.S_un.S_un_b.s_b1 == 127);
}

BOOLEAN RgIsLoopbackV4(_In_ UINT32 Addr)
{
    IN_ADDR a;
    a.S_un.S_addr = Addr;
    return RgIsLoopbackAddrV4(a);
}

BOOLEAN RgIsLoopbackV6(_In_ const IN6_ADDR* Addr)
{
    if (Addr == NULL) {
        return FALSE;
    }
    /* ::1 */
    return (Addr->u.Word[0] == 0 &&
            Addr->u.Word[1] == 0 &&
            Addr->u.Word[2] == 0 &&
            Addr->u.Word[3] == 0 &&
            Addr->u.Word[4] == 0 &&
            Addr->u.Word[5] == 0 &&
            Addr->u.Word[6] == 0 &&
            Addr->u.Word[7] == 1);
}

BOOLEAN RgIsExcludedPid(_In_ UINT32 ProcessId)
{
    UINT32 i;
    KIRQL irql;
    BOOLEAN found = FALSE;

    KeAcquireSpinLock(&g_RgConfigLock, &irql);
    for (i = 0; i < g_RgDnsConfig.ExcludedPidCount && i < RG_DNS_MAX_EXCLUDED_PIDS; i++) {
        if (g_RgDnsConfig.ExcludedPids[i] == ProcessId) {
            found = TRUE;
            break;
        }
    }
    KeReleaseSpinLock(&g_RgConfigLock, irql);
    return found;
}

BOOLEAN RgValidateConfig(_In_ PRG_DNS_REDIRECT_CONFIG Config)
{
    if (Config == NULL || Config->Version != RG_DNS_CONFIG_VERSION) {
        return FALSE;
    }
    if (Config->ProxyPort == 0 || Config->ProxyPort == 53) {
        return FALSE;
    }
    if (!RgIsLoopbackAddrV4(Config->ProxyV4)) {
        return FALSE;
    }
    if (!RgIsLoopbackV6(&Config->ProxyV6)) {
        return FALSE;
    }
    if (Config->ExcludedPidCount > RG_DNS_MAX_EXCLUDED_PIDS) {
        return FALSE;
    }
    return TRUE;
}

VOID RgApplyConfig(_In_ PRG_DNS_REDIRECT_CONFIG Config)
{
    KIRQL irql;
    KeAcquireSpinLock(&g_RgConfigLock, &irql);
    RtlCopyMemory(&g_RgDnsConfig, Config, sizeof(RG_DNS_REDIRECT_CONFIG));
    KeReleaseSpinLock(&g_RgConfigLock, irql);
}

VOID RgStatsIncrement(_Inout volatile LONG64* Counter)
{
    if (Counter != NULL) {
        InterlockedIncrement64(Counter);
    }
}
