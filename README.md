# px5g `ca` and `sign` – proposal

> **Status: proposal.** A suggested extension to OpenWrt's `px5g-mbedtls`, not part of OpenWrt and not
> reviewed or approved by OpenWrt developers. In daily use on one router (Cudy WR3000 v1, mediatek/filogic,
> OpenWrt 25.12.6; OpenVPN 2.7 with mbed TLS accepts the client certificates it signs); the 50 checks
> pass on x86_64 and on emulated aarch64, MIPS (both byte orders) and ARMv7. Use at your own risk.
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

## Test on a PC (Linux or WSL)

Ubuntu's `libmbedtls-dev` is still 2.28, so build mbedtls 3.6.7 (as in OpenWrt 25.12) yourself:

```sh
git clone --depth 1 -b v3.6.7 https://github.com/Mbed-TLS/mbedtls.git
git -C mbedtls submodule update --init --depth 1
make -C mbedtls lib -j4
gcc -Wall -Werror -O2 -Imbedtls/include -o px5g px5g-mbedtls.c \
    mbedtls/library/libmbedtls.a mbedtls/library/libmbedx509.a mbedtls/library/libmbedcrypto.a
mkdir t && cd t && sh ../test.sh ../px5g      # needs openssl on the PC to check the results
```

`test.sh` runs 50 checks: what is made (checked with `openssl verify -x509_strict -purpose
sslserver`), the name limits, keys and CA checks, file handling and input checks – one or more
per review finding. `testdata/` holds two throw-away test CAs (expired, and valid only from 2090);
never use them for anything else. All 50 pass, also under AddressSanitizer and UBSan; no memory is
left allocated after a successful run (error paths exit straight away, as in the original px5g).

## Tested targets and size

Built like OpenWrt builds px5g-mbedtls: musl 1.2.5, dynamically linked to mbedtls 3.6 configured as in
OpenWrt 25.12, `-Os`, stripped. The 50 checks were run on each build (aarch64, MIPS and ARMv7 under
qemu-user; the aarch64 build also on the real router).

| Target (OpenWrt arch) | original px5g | with ca/sign | 50 checks |
|---|---:|---:|---|
| aarch64_cortex-a53 (mediatek/filogic) | 13.7 KB | 26.0 KB | pass (router + qemu) |
| mipsel_24kc (ramips/mt7621) | 12.0 KB | 25.6 KB | pass (qemu) |
| mips_24kc (ath79) | 12.0 KB | 25.6 KB | pass (qemu) |
| arm_cortex-a7_neon-vfpv4 (ipq40xx) | 11.3 KB | 23.4 KB | pass (qemu) |

(The official 25.12 aarch64 package is 16.3 KB; the difference to the 13.7 KB here comes from build
flags. The increase, about 12–14 KB, is what the change adds.)

## Try it on your own router (OpenWrt SDK)

Help with real MIPS and ARM routers is welcome. With the SDK for your target (25.12 or snapshot):

```sh
cd openwrt-sdk-*
./scripts/feeds update base && ./scripts/feeds install px5g-mbedtls
cp /path/to/px5g-ca-sign/px5g-mbedtls.c feeds/base/package/utils/px5g-mbedtls/
make defconfig && make package/px5g-mbedtls/compile V=s
find bin -name 'px5g-mbedtls*'
```

Install the package on the router (`apk add --allow-untrusted /tmp/px5g-mbedtls-*.apk` on 25.12,
`opkg install` on 24.10), then:

```sh
cd /tmp
px5g ca -newkey ec -days 30 -subj /CN=Test-CA -keyout t-ca.key -out t-ca.crt
px5g sign -CA t-ca.crt -CAkey t-ca.key -newkey ec -days 30 -subj /CN=test.lan \
    -addext subjectAltName=DNS:test.lan -keyout t.key -out t.crt
px5g sign -CA t-ca.crt -CAkey t-ca.key -newkey ec -days 30 -subj /CN=test-client \
    -addext extendedKeyUsage=clientAuth -keyout c.key -out c.crt
```

Copy `t-ca.crt`, `t.crt` and `c.crt` to a PC and check them with
`openssl verify -x509_strict -purpose sslserver -CAfile t-ca.crt t.crt` and `-purpose sslclient … c.crt`.
`selfsigned` (used by uhttpd) is unchanged, so keeping the package installed is harmless; reinstall
px5g-mbedtls from the feed to go back. Please report the target, the result and `ls -l /usr/sbin/px5g`.

## For the maintainer

`patches/` holds the change as a series for OpenWrt master (applies with `git am`):

1. `0001-px5g-mbedtls-add-ca-and-sign-commands.patch` – `ca` and `sign`, server and client certificates,
   safe file writing; `PKG_RELEASE` 14 → 15. Builds with `-Wall -Werror` on its own.
2. `0002-px5g-mbedtls-add-nameConstraints-to-ca.patch` – optional name limits for a CA, enforced by
   `sign`; `PKG_RELEASE` 15 → 16.

The patches carry no `Signed-off-by:` line yet. The author is happy for the px5g maintainer to take the
code over, change it as needed and submit it under their own name.

## Files

| File | What |
|---|---|
| `patches/0001-…`, `patches/0002-…` | the change as a patch series for OpenWrt master |
| `px5g-mbedtls.c` | the complete file with both patches applied, for reading |
| `test.sh`, `testdata/` | the 50 checks: `sh test.sh /path/to/px5g` (needs `openssl` on the PC) |
| `LICENSE` | LGPL-2.1, as the original `px5g-mbedtls.c` |

## License

LGPL-2.1, like the original `px5g-mbedtls.c` (Copyright (C) 2009 Steven Barth, (C) 2014 Felix Fietkau);
the changes in this repository are under the same license.
