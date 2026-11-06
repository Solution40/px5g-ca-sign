# px5g `ca` and `sign` – proposal

> **Status: proposal.** A suggested extension to OpenWrt's `px5g-mbedtls`, not part of OpenWrt and not
> reviewed or approved by OpenWrt developers. Tested on one router (Cudy WR3000 v1, mediatek/filogic,
> OpenWrt 25.12.6, aarch64: ~26 KB built against the router's own mbedtls 3.6; OpenVPN 2.7 with mbed TLS
> accepts the client certificates) and with the included 50 checks. Use at your own risk.
>
> Written with the help of Claude (an AI assistant); reviewed and tested by the repository owner.

Two extra commands for OpenWrt's `px5g-mbedtls`, so a router can run its own small
certificate authority with only mbedtls (no OpenSSL):

```sh
# a CA (CA:TRUE, keyCertSign/cRLSign, optional name limits)
px5g ca -newkey ec -days 3650 -subj "/CN=Home CA/O=Home Access" \
    -keyout ca.key -out ca.crt \
    -addext "nameConstraints=permitted;DNS:lan,permitted;IP:192.168.0.0/255.255.0.0"

# a server certificate signed by that CA (CA:FALSE, digitalSignature, serverAuth)
px5g sign -CA ca.crt -CAkey ca.key -newkey ec -days 397 -subj /CN=router.lan \
    -addext subjectAltName=DNS:router.lan -addext subjectAltName=IP:192.168.1.1 \
    -keyout router.key -out router.crt

# a client certificate, e.g. for OpenVPN (clientAuth only: no subjectAltName needed)
px5g sign -CA vpn-ca.crt -CAkey vpn-ca.key -newkey ec -days 730 -subj /CN=anna-phone \
    -addext extendedKeyUsage=clientAuth -keyout anna-phone.key -out anna-phone.crt

# renew, keeping the existing key
px5g sign -CA ca.crt -CAkey ca.key -key router.key -days 397 -subj /CN=router.lan \
    -addext subjectAltName=DNS:router.lan -out router.crt
```

Options are the same as `selfsigned` (`-newkey rsa:N|ec`, `-pkeyopt ec_paramgen_curve:P-384`,
`-days`, `-subj`, `-keyout`, `-out`, `-der`, `-addext subjectAltName=…|extendedKeyUsage=…`), plus:

| option | command | what it does |
|---|---|---|
| `-key file` | ca, sign | use an existing key (PEM or DER) instead of making a new one |
| `-CA file`, `-CAkey file` | sign | the CA certificate and its key (checked: CA:TRUE, keyCertSign, key matches) |
| `-pathlen n` | ca | basicConstraints pathlen (default 0: may only sign end certificates) |
| `-addext nameConstraints=…` | ca | OpenSSL syntax: `[critical,]permitted;DNS:x,excluded;IP:addr/mask` (mask as `255.255.0.0` or `/16`, IPv6 too) |
| `-addext extendedKeyUsage=clientAuth` | all | new next to `serverAuth` and `any` |

`selfsigned` works exactly as before (same extensions, same order, still skips unknown options).

### Safety rules in `ca` and `sign` (from the security review)

- **Name limits are enforced when signing.** `sign` reads the CA's nameConstraints (DNS and IP,
  permitted and excluded, also from a CA made by OpenSSL) and refuses names outside them,
  including a CN that looks like a host name. Other name types (e-mail, URI) are refused under a
  CA with name limits. An empty `nameConstraints=` is an error; limiting only DNS or only IP
  gives a warning, because the other kind then stays unlimited.
- **The CA must be usable now:** an expired CA, a CA not valid yet, or a clock before 2024
  (router without NTP yet) is refused. A certificate never outlives its CA (end date capped).
- **A server certificate never gets the CA's own key** (`-key ca.key` is refused).
- **Every new certificate is checked by mbedtls against its CA before anything is written.**
  A CA name that cannot be copied exactly (escaped characters, multi-part names) is refused.
- **Files:** key and certificate go to new temporary files next to the target (no symlinks
  followed, mode always 600 for keys and 644 for certificates) and are renamed into place only
  when everything worked. On any error the old key and certificate stay as they were.
- **Input:** `sign` needs at least one subjectAltName, except for a client certificate (only
  `extendedKeyUsage=clientAuth`); `,` `+` `\` `"` `<` `>` are refused in
  `-subj`; `-days` 1–36500; RSA at least 2048 bits; `-pathlen` -1–8; unknown options are errors.
- P-384/P-521 CA keys sign with SHA-384/SHA-512; all return values are checked; the buffer that
  held the new private key is wiped.

## One thing found while testing: mbedtls and *critical* name limits

mbedtls does not process nameConstraints, so it **refuses to load a CA whose nameConstraints
is marked critical** (`MBEDTLS_ERR_X509_FEATURE_UNAVAILABLE`). That means `uclient-fetch
--ca-certificate` (ustream-mbedtls) cannot use such a CA. OpenSSL and the browsers apply
the name limits whether the extension is critical or not. So:

- `px5g ca` marks nameConstraints non-critical unless you write `critical,`.
- `px5g sign` still reads a CA with critical nameConstraints (also one made by OpenSSL),
  through `mbedtls_x509_crt_parse_der_with_ext_cb`.
- Home Access 26.11.35 makes its CA the same way (non-critical); see the Home Access notes.

## Test on a PC (Linux or WSL)

Ubuntu's `libmbedtls-dev` is still 2.28, so build mbedtls 3.6 (as in OpenWrt 25.12) yourself:

```sh
git clone --depth 1 -b v3.6.2 https://github.com/Mbed-TLS/mbedtls.git
git -C mbedtls submodule update --init --depth 1
make -C mbedtls lib -j4
gcc -Wall -Werror -O2 -Imbedtls/include -o px5g px5g-mbedtls.c \
    mbedtls/library/libmbedtls.a mbedtls/library/libmbedx509.a mbedtls/library/libmbedcrypto.a
mkdir t && cd t && sh ../test.sh ../px5g      # needs openssl on the PC to check the results
```

`test.sh` runs 50 checks: what is made (checked with `openssl verify -x509_strict -purpose
sslserver`), the name limits, keys and CA checks, file handling and input checks – one or more
per review finding. `testdata/` holds two throw-away test CAs (expired, and valid only from 2090);
never use them for anything else. All 50 pass here, also under AddressSanitizer.

## Test on the router (OpenWrt 25.12 SDK)

The WR3000 v1 is `mediatek/filogic` (aarch64). With the 25.12 SDK for that target:

```sh
cd openwrt-sdk-25.12*-mediatek-filogic*
./scripts/feeds update base && ./scripts/feeds install px5g-mbedtls
patch -p1 -d feeds/base < /path/to/0001-px5g-mbedtls-add-ca-and-sign.patch   # or copy px5g-mbedtls.c over it
make defconfig && make package/px5g-mbedtls/compile V=s
find bin -name 'px5g-mbedtls*.apk'
```

On the router (copy the .apk to /tmp first):

```sh
apk add --allow-untrusted /tmp/px5g-mbedtls-*.apk
px5g ca -newkey ec -subj /CN=test -keyout /tmp/ca.key -out /tmp/ca.crt
px5g sign -CA /tmp/ca.crt -CAkey /tmp/ca.key -newkey ec -subj /CN=test.lan \
    -addext subjectAltName=DNS:test.lan -keyout /tmp/t.key -out /tmp/t.crt
```

Keeping it installed is harmless: `selfsigned` (used by uhttpd) is unchanged. To go back to
the official build, reinstall px5g-mbedtls from the feed. The SDK and router steps could not be
run here (no OpenWrt SDK in this environment); the PC build is what was tested.

## Files

- `px5g-mbedtls.c` – the whole changed source (drop-in for `package/utils/px5g-mbedtls/`)
- `0001-px5g-mbedtls-add-ca-and-sign.patch` – the same as a diff against openwrt main
- `test.sh` – the checks above, `testdata/` – two throw-away CAs for the date checks

Same licence as px5g (LGPL-2.1). Prototype for discussion with the px5g maintainers, not merged anywhere.


## Files

| File | What |
|---|---|
| `0001-px5g-mbedtls-add-ca-and-sign.patch` | the change, against `package/utils/px5g-mbedtls/px5g-mbedtls.c` in OpenWrt master |
| `px5g-mbedtls.c` | the complete file with the change applied, for reading |
| `test.sh`, `testdata/` | the 50 checks: `sh test.sh /path/to/px5g` (needs `openssl` on the PC) |
| `LICENSE` | LGPL-2.1, as the original `px5g-mbedtls.c` |

## License

LGPL-2.1, like the original `px5g-mbedtls.c` (Copyright (C) 2009 Steven Barth, (C) 2014 Felix Fietkau);
the changes in this repository are under the same license.
