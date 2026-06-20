# routeguard-callout.sys — Signing & Deployment

## Test signing (dev VM)

```bat
bcdedit /set testsigning on
```

Build with WDK, sign with test certificate:

```bat
signtool sign /v /s PrivateCertStore /n "RouteGuard Test" /t http://timestamp.digicert.com routeguard-callout.sys
pnputil /add-driver routeguard-callout.inf /install
sc create RouteGuardCallout type= kernel start= demand binPath= "System32\drivers\routeguard-callout.sys"
sc start RouteGuardCallout
```

## Production (EV)

- EV code signing certificate required for Windows 10/11 driver load policy.
- Ship `routeguard-callout.sys` + `routeguard-callout.inf` alongside RouteGuard installer under `drivers\`.
- Optional HLK submission: WFP callout driver, network connectivity.

## Installer layout

```
RouteGuard/
  drivers/
    routeguard-callout.sys
    routeguard-callout.inf
    routeguard-callout.cat   (signed catalog)
```

MasselGUARD / RouteGuard installer should run `pnputil /add-driver` during elevated setup when `[routing.domain_dns] kernel_redirect = true`.

## Verification

Run `tests/scripts/dns_redirect_matrix.ps1` as Administrator after install.
