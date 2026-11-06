/*
 * px5g - Embedded x509 key and certificate generator based on PolarSSL
 *
 *   Copyright (C) 2009 Steven Barth <steven@midlink.org>
 *   Copyright (C) 2014 Felix Fietkau <nbd@nbd.name>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License, version 2.1 as published by the Free Software Foundation.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA  02110-1301  USA
 */

#include <sys/types.h>
#include <sys/random.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <limits.h>
#include <unistd.h>
#include <fcntl.h>
#include <stdbool.h>
#include <errno.h>
#include <sys/stat.h>

#include <mbedtls/bignum.h>
#include <mbedtls/entropy.h>
#include <mbedtls/x509_crt.h>
#include <mbedtls/ecp.h>
#include <mbedtls/rsa.h>
#include <mbedtls/pk.h>
#include <mbedtls/asn1.h>
#include <mbedtls/oid.h>
#include <mbedtls/asn1write.h>
#include <mbedtls/pem.h>
#include <mbedtls/platform_util.h>

#define SET_OID(x, oid) \
	do { x.len = MBEDTLS_OID_SIZE(oid); x.p = (unsigned char *) oid; } while (0)

#define PX5G_VERSION "0.3"
#define PX5G_COPY "Copyright (c) 2009 Steven Barth <steven@midlink.org>"
#define PX5G_LICENSE "Licensed under the GNU Lesser General Public License v2.1"

static char buf[16384];

/* ca and sign: write into a new temporary file next to the target (mkstemp: no symlink is
 * followed, the mode is always set), and only rename them into place once everything worked */
static bool safe_files;
static struct { char *tmp, *path; } pending[2];
static int npending;

static void drop_pending(void)
{
	for (int i = 0; i < npending; i++)
		if (pending[i].tmp)
			unlink(pending[i].tmp);
}

static void commit_pending(void)
{
	for (int i = 0; i < npending; i++) {
		if (rename(pending[i].tmp, pending[i].path)) {
			fprintf(stderr, "error: cannot replace %s: %s\n", pending[i].path, strerror(errno));
			exit(1);
		}
		free(pending[i].tmp);
		pending[i].tmp = NULL;
	}
	npending = 0;
}

static int _urandom(void *ctx, unsigned char *out, size_t len)
{
	ssize_t ret;

	ret = getrandom(out, len, 0);
	if (ret < 0 || (size_t)ret != len)
		return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;

	return 0;
}

static void write_file(const char *path, size_t len, bool pem, bool cert)
{
	mode_t mode = S_IRUSR | S_IWUSR;
	const char *buf_start = buf;
	int fd = STDERR_FILENO;
	ssize_t written;
	int err;

	if (!pem)
		buf_start += sizeof(buf) - len;

	if (!len) {
		fprintf(stderr, "No data to write\n");
		exit(1);
	}

	if (cert)
		mode |= S_IRGRP | S_IROTH;

	if (path && safe_files) {
		char *tmp = malloc(strlen(path) + 8);
		if (!tmp || npending >= 2) {
			fprintf(stderr, "error: out of memory\n");
			exit(1);
		}
		sprintf(tmp, "%s.XXXXXX", path);
		fd = mkstemp(tmp);
		if (fd >= 0 && fchmod(fd, mode) < 0) {
			close(fd);
			unlink(tmp);
			fd = -1;
		}
		if (fd >= 0) {
			pending[npending].tmp = tmp;
			pending[npending++].path = (char *)path;
		}
	} else if (path) {
		fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, mode);
	}

	if (fd < 0) {
		fprintf(stderr, "error: I/O error\n");
		exit(1);
	}

	written = write(fd, buf_start, len);
	if (written != len) {
		fprintf(stderr, "writing key failed with: %s\n", strerror(errno));
		exit(1);
	}
	err = fsync(fd);
	if (err < 0) {
		fprintf(stderr, "syncing key failed with: %s\n", strerror(errno));
		exit(1);
	}
	if (path)
		close(fd);
}

static mbedtls_ecp_group_id ecp_curve(const char *name)
{
	const mbedtls_ecp_curve_info *curve_info;

	if (!strcmp(name, "P-256"))
		return MBEDTLS_ECP_DP_SECP256R1;
	else if (!strcmp(name, "P-384"))
		return MBEDTLS_ECP_DP_SECP384R1;
	else if (!strcmp(name, "P-521"))
		return MBEDTLS_ECP_DP_SECP521R1;
	curve_info = mbedtls_ecp_curve_info_from_name(name);
	if (curve_info == NULL)
		return MBEDTLS_ECP_DP_NONE;
	else
		return curve_info->grp_id;
}

static void write_key(mbedtls_pk_context *key, const char *path, bool pem)
{
	int len = 0;

	if (pem) {
		if (mbedtls_pk_write_key_pem(key, (void *) buf, sizeof(buf)) == 0)
			len = strlen(buf);
	} else {
		len = mbedtls_pk_write_key_der(key, (void *) buf, sizeof(buf));
		if (len < 0)
			len = 0;
	}

	write_file(path, len, pem, false);
}

static void gen_key(mbedtls_pk_context *key, bool rsa, int ksize, int exp,
		    mbedtls_ecp_group_id curve, bool pem)
{
	mbedtls_pk_init(key);
	if (rsa) {
		fprintf(stderr, "Generating RSA private key, %i bit long modulus\n", ksize);
		mbedtls_pk_setup(key, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA));
		if (!mbedtls_rsa_gen_key(mbedtls_pk_rsa(*key), _urandom, NULL, ksize, exp))
			return;
	} else {
		fprintf(stderr, "Generating EC private key\n");
		mbedtls_pk_setup(key, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY));
		if (!mbedtls_ecp_gen_key(curve, mbedtls_pk_ec(*key), _urandom, NULL))
			return;
	}
	fprintf(stderr, "error: key generation failed\n");
	exit(1);
}

int dokey(bool rsa, char **arg)
{
	mbedtls_pk_context key;
	unsigned int ksize = 2048;
	int exp = 65537;
	char *path = NULL;
	bool pem = true;
	mbedtls_ecp_group_id curve = MBEDTLS_ECP_DP_SECP256R1;

	while (*arg && **arg == '-') {
		if (!strcmp(*arg, "-out") && arg[1]) {
			path = arg[1];
			arg++;
		} else if (!strcmp(*arg, "-3")) {
			exp = 3;
		} else if (!strcmp(*arg, "-der")) {
			pem = false;
		}
		arg++;
	}

	if (*arg && rsa) {
		ksize = (unsigned int)atoi(*arg);
	} else if (*arg) {
		curve = ecp_curve((const char *)*arg);
		if (curve == MBEDTLS_ECP_DP_NONE) {
			fprintf(stderr, "error: invalid curve name: %s\n", *arg);
			return 1;
		}
	}

	gen_key(&key, rsa, ksize, exp, curve, pem);
	write_key(&key, path, pem);

	mbedtls_pk_free(&key);

	return 0;
}

enum cert_mode { MODE_SELFSIGNED, MODE_CA, MODE_SIGN };

/* nameConstraints, OpenSSL style: [critical,]permitted;DNS:lan,excluded;IP:10.0.0.0/255.0.0.0,... */
struct nc_item {
	bool excluded;
	unsigned char tag;		/* 0x82 dNSName, 0x87 iPAddress */
	unsigned char data[256];
	size_t len;
};

static int nc_parse(char *val, struct nc_item **items, int *n, bool *critical)
{
	char *tok, *save = NULL, *colon, *slash;
	struct nc_item *it;
	unsigned char mask[16];
	size_t alen, mlen;

	for (tok = strtok_r(val, ",", &save); tok; tok = strtok_r(NULL, ",", &save)) {
		while (*tok == ' ')
			tok++;
		if (!strcmp(tok, "critical")) {
			*critical = true;
			continue;
		}
		it = realloc(*items, sizeof(**items) * (*n + 1));
		if (!it) {
			fprintf(stderr, "error: out of memory\n");
			return 1;
		}
		*items = it;
		it = &(*items)[*n];
		memset(it, 0, sizeof(*it));
		if (!strncmp(tok, "permitted;", 10)) {
			tok += 10;
		} else if (!strncmp(tok, "excluded;", 9)) {
			it->excluded = true;
			tok += 9;
		} else {
			fprintf(stderr, "error: nameConstraints entry must start with permitted; or excluded;: %s\n", tok);
			return 1;
		}
		colon = strchr(tok, ':');
		if (!colon || !colon[1]) {
			fprintf(stderr, "error: invalid nameConstraints entry: %s\n", tok);
			return 1;
		}
		*colon++ = 0;
		if (!strcmp(tok, "DNS")) {
			it->tag = MBEDTLS_ASN1_CONTEXT_SPECIFIC | 2;
			it->len = strlen(colon);
			if (it->len >= sizeof(it->data)) {
				fprintf(stderr, "error: name too long: %s\n", colon);
				return 1;
			}
			memcpy(it->data, colon, it->len);
		} else if (!strcmp(tok, "IP")) {
			/* address/netmask (as OpenSSL) or address/prefixlen */
			it->tag = MBEDTLS_ASN1_CONTEXT_SPECIFIC | 7;
			slash = strchr(colon, '/');
			if (!slash) {
				fprintf(stderr, "error: IP constraint needs address/mask: %s\n", colon);
				return 1;
			}
			*slash++ = 0;
			alen = mbedtls_x509_crt_parse_cn_inet_pton(colon, it->data);
			if (!alen) {
				fprintf(stderr, "error: invalid IP address: %s\n", colon);
				return 1;
			}
			if (strchr(slash, '.') || strchr(slash, ':')) {
				mlen = mbedtls_x509_crt_parse_cn_inet_pton(slash, mask);
			} else {
				char *e;
				long bits = strtol(slash, &e, 10);
				mlen = alen;
				if (*e || bits < 0 || bits > (long)alen * 8) {
					mlen = 0;
				} else {
					memset(mask, 0, sizeof(mask));
					for (long b = 0; b < bits; b++)
						mask[b / 8] |= 0x80 >> (b % 8);
				}
			}
			if (mlen != alen) {
				fprintf(stderr, "error: invalid netmask: %s\n", slash);
				return 1;
			}
			memcpy(it->data + alen, mask, mlen);
			it->len = alen + mlen;
		} else {
			fprintf(stderr, "error: unsupported nameConstraints type (DNS and IP only): %s\n", tok);
			return 1;
		}
		(*n)++;
	}
	if (!*n) {
		fprintf(stderr, "error: nameConstraints without any permitted; or excluded; entry\n");
		return 1;
	}
	return 0;
}

static int nc_write_subtrees(unsigned char **p, unsigned char *start,
			     struct nc_item *items, int n, bool excluded)
{
	size_t len = 0, sub;
	int ret, i;

	for (i = n - 1; i >= 0; i--) {
		if (items[i].excluded != excluded)
			continue;
		sub = 0;
		MBEDTLS_ASN1_CHK_ADD(sub, mbedtls_asn1_write_raw_buffer(p, start, items[i].data, items[i].len));
		MBEDTLS_ASN1_CHK_ADD(sub, mbedtls_asn1_write_len(p, start, items[i].len));
		MBEDTLS_ASN1_CHK_ADD(sub, mbedtls_asn1_write_tag(p, start, items[i].tag));
		MBEDTLS_ASN1_CHK_ADD(sub, mbedtls_asn1_write_len(p, start, sub));
		MBEDTLS_ASN1_CHK_ADD(sub, mbedtls_asn1_write_tag(p, start, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));
		len += sub;
	}
	if (!len)
		return 0;
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(p, start, len));
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(p, start,
		MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | (excluded ? 1 : 0)));
	return (int)len;
}

static int nc_set(mbedtls_x509write_cert *cert, struct nc_item *items, int n, bool critical)
{
	unsigned char der[4096], *p = der + sizeof(der);
	size_t len = 0;
	int ret;

	MBEDTLS_ASN1_CHK_ADD(len, nc_write_subtrees(&p, der, items, n, true));
	MBEDTLS_ASN1_CHK_ADD(len, nc_write_subtrees(&p, der, items, n, false));
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_len(&p, der, len));
	MBEDTLS_ASN1_CHK_ADD(len, mbedtls_asn1_write_tag(&p, der, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE));

	return mbedtls_x509write_crt_set_extension(cert, MBEDTLS_OID_NAME_CONSTRAINTS,
			MBEDTLS_OID_SIZE(MBEDTLS_OID_NAME_CONSTRAINTS), critical, p, len);
}

/* mbedtls does not process nameConstraints; a CA carries them for the clients that do.
 * Accept the extension when reading our own CA, which is only used to sign. */
static unsigned char ca_nc[4096];
static size_t ca_nc_len;

static int ca_ext_cb(void *ctx, mbedtls_x509_crt const *crt, mbedtls_x509_buf const *oid,
		     int critical, const unsigned char *p, const unsigned char *end)
{
	if (MBEDTLS_OID_CMP(MBEDTLS_OID_NAME_CONSTRAINTS, oid))
		return -1;
	if ((size_t)(end - p) > sizeof(ca_nc))
		return -1;
	memcpy(ca_nc, p, end - p);
	ca_nc_len = end - p;
	return 0;
}

/* RFC 5280 4.2.1.10: "lan" matches lan and x.lan, ".lan" only x.lan; not case sensitive */
static bool nc_dns_match(const unsigned char *c, size_t clen, const char *name)
{
	size_t nlen = strlen(name);

	if (!clen)
		return true;
	if (c[0] == '.')
		return nlen > clen && !strncasecmp(name + nlen - clen, (const char *)c, clen);
	if (nlen == clen)
		return !strncasecmp(name, (const char *)c, clen);
	return nlen > clen && name[nlen - clen - 1] == '.' &&
	       !strncasecmp(name + nlen - clen, (const char *)c, clen);
}

static bool nc_ip_match(const unsigned char *c, size_t clen, const unsigned char *ip, size_t iplen)
{
	if (clen != 2 * iplen)
		return false;
	for (size_t i = 0; i < iplen; i++)
		if ((ip[i] & c[iplen + i]) != (c[i] & c[iplen + i]))
			return false;
	return true;
}

/* type: 2 dNSName, 7 iPAddress. Returns 0 when allowed, 1 when refused, -1 when unreadable */
static int nc_check(int type, const char *dns, const unsigned char *ip, size_t iplen)
{
	unsigned char *p = ca_nc, *end = ca_nc + ca_nc_len, *tend, *sub, *gn;
	size_t len, glen;
	int tag, excluded;
	bool have_permitted = false, permitted = false;

	if (!ca_nc_len)
		return 0;
	if (mbedtls_asn1_get_tag(&p, end, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE) || p + len != end)
		return -1;
	while (p < end) {
		tag = *p;
		if (tag != (MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 0) &&
		    tag != (MBEDTLS_ASN1_CONTEXT_SPECIFIC | MBEDTLS_ASN1_CONSTRUCTED | 1))
			return -1;
		excluded = tag & 1;
		if (mbedtls_asn1_get_tag(&p, end, &len, tag))
			return -1;
		tend = p + len;
		while (p < tend) {
			if (mbedtls_asn1_get_tag(&p, tend, &len, MBEDTLS_ASN1_CONSTRUCTED | MBEDTLS_ASN1_SEQUENCE))
				return -1;
			sub = p + len;
			gn = p;
			if (gn >= sub)
				return -1;
			tag = *gn & 0x1f;
			if (mbedtls_asn1_get_tag(&gn, sub, &glen, *gn))
				return -1;
			if (gn + glen < sub)	//minimum/maximum are not used by anyone (RFC 5280: must not be there)
				return -1;
			if (tag == type) {
				bool m = type == 2 ? nc_dns_match(gn, glen, dns) : nc_ip_match(gn, glen, ip, iplen);
				if (excluded && m)
					return 1;
				if (!excluded) {
					have_permitted = true;
					permitted |= m;
				}
			} else if (tag != 2 && tag != 7 && !excluded) {
				//e.g. rfc822Name or directoryName: fine as long as we do not issue that type
			}
			p = sub;
		}
	}
	return (have_permitted && !permitted) ? 1 : 0;
}

static int load_ca(mbedtls_x509_crt *crt, const char *path)
{
	static unsigned char raw[16384];
	mbedtls_pem_context pem;
	const unsigned char *der = raw;
	size_t len, used;
	FILE *f;
	int ret;

	f = fopen(path, "rb");
	if (!f)
		return -1;
	len = fread(raw, 1, sizeof(raw) - 1, f);
	fclose(f);
	raw[len] = 0;

	mbedtls_pem_init(&pem);
	if (strstr((char *)raw, "-----BEGIN CERTIFICATE-----")) {
		if (mbedtls_pem_read_buffer(&pem, "-----BEGIN CERTIFICATE-----",
				"-----END CERTIFICATE-----", raw, NULL, 0, &used)) {
			mbedtls_pem_free(&pem);
			return -1;
		}
		der = mbedtls_pem_get_buffer(&pem, &len);
	}
	ret = mbedtls_x509_crt_parse_der_with_ext_cb(crt, der, len, 1, ca_ext_cb, NULL);
	mbedtls_pem_free(&pem);
	return ret;
}

static void load_key(mbedtls_pk_context *key, const char *path)
{
	mbedtls_pk_init(key);
	if (mbedtls_pk_parse_keyfile(key, path, NULL, _urandom, NULL)) {
		fprintf(stderr, "error: cannot read key %s\n", path);
		exit(1);
	}
}

static time_t x509_time_epoch(const mbedtls_x509_time *t)
{
	struct tm tm = {
		.tm_year = t->year - 1900, .tm_mon = t->mon - 1, .tm_mday = t->day,
		.tm_hour = t->hour, .tm_min = t->min, .tm_sec = t->sec,
	};
	return timegm(&tm);
}

static int gencert(enum cert_mode mode, char **arg)
{
	mbedtls_pk_context key, cakey;
	mbedtls_x509_crt cacrt;
	mbedtls_x509write_cert cert;
	mbedtls_mpi serial;
	mbedtls_x509_san_list *san_list = NULL, *san_prev = NULL, *san_cur = NULL;
	/*support
	- MBEDTLS_X509_SAN_DNS_NAME
	- MBEDTLS_X509_SAN_IP_ADDRESS
	- MBEDTLS_X509_SAN_RFC822_NAME
	- MBEDTLS_X509_SAN_UNIFORM_RESOURCE_IDENTIFIER
	*/
	mbedtls_asn1_sequence *eku = NULL, **eku_tail = &eku, *ext_key_usage;
	bool eku_server = false;
	char *usage;
	char *sanval, *santype;
	uint8_t *ipaddr;
	size_t iplen;
	struct nc_item *nc = NULL;
	int nc_n = 0;
	bool nc_critical = false;

	char *subject = "", *subject_buf = NULL;
	char issuer[1024];
	unsigned int ksize = 2048;
	int exp = 65537;
	unsigned int days = 30;
	int pathlen = 0;
	char *keypath = NULL, *certpath = NULL, *inkey = NULL;
	char *capath = NULL, *cakeypath = NULL;
	bool pem = true;
	time_t from = time(NULL), to;
	char fstr[20], tstr[20], sstr[17];
	int len;
	bool rsa = true;
	mbedtls_ecp_group_id curve = MBEDTLS_ECP_DP_SECP256R1;
	mbedtls_pk_context *issuer_key = &key;

	while (*arg && **arg == '-') {
		if (!strcmp(*arg, "-der")) {
			pem = false;
		} else if (!strcmp(*arg, "-newkey") && arg[1]) {
			if (!strncmp(arg[1], "rsa:", 4)) {
				rsa = true;
				ksize = (unsigned int)atoi(arg[1] + 4);
				if (mode != MODE_SELFSIGNED && ksize < 2048) {
					fprintf(stderr, "error: RSA keys need at least 2048 bits\n");
					return 1;
				}
			} else if (!strcmp(arg[1], "ec")) {
				rsa = false;
			} else {
				fprintf(stderr, "error: invalid algorithm\n");
				return 1;
			}
			arg++;
		} else if (!strcmp(*arg, "-days") && arg[1]) {
			if (mode != MODE_SELFSIGNED) {
				char *e;
				long d = strtol(arg[1], &e, 10);
				if (*e || d < 1 || d > 36500) {
					fprintf(stderr, "error: -days must be 1 to 36500\n");
					return 1;
				}
				days = d;
			} else {
				days = (unsigned int)atoi(arg[1]);
			}
			arg++;
		} else if (!strcmp(*arg, "-pkeyopt") && arg[1]) {
			if (strncmp(arg[1], "ec_paramgen_curve:", 18)) {
				fprintf(stderr, "error: invalid pkey option: %s\n", arg[1]);
				return 1;
			}
			curve = ecp_curve((const char *)(arg[1] + 18));
			if (curve == MBEDTLS_ECP_DP_NONE) {
				fprintf(stderr, "error: invalid curve name: %s\n", arg[1] + 18);
				return 1;
			}
			arg++;
		} else if (!strcmp(*arg, "-keyout") && arg[1]) {
			keypath = arg[1];
			arg++;
		} else if (!strcmp(*arg, "-key") && arg[1] && mode != MODE_SELFSIGNED) {
			inkey = arg[1];
			arg++;
		} else if (!strcmp(*arg, "-CA") && arg[1] && mode == MODE_SIGN) {
			capath = arg[1];
			arg++;
		} else if (!strcmp(*arg, "-CAkey") && arg[1] && mode == MODE_SIGN) {
			cakeypath = arg[1];
			arg++;
		} else if (!strcmp(*arg, "-pathlen") && arg[1] && mode == MODE_CA) {
			char *e;
			pathlen = (int)strtol(arg[1], &e, 10);
			if (*e || pathlen < -1 || pathlen > 8) {
				fprintf(stderr, "error: -pathlen must be -1 (no limit) to 8\n");
				return 1;
			}
			arg++;
		} else if (!strcmp(*arg, "-out") && arg[1]) {
			certpath = arg[1];
			arg++;
		} else if (!strcmp(*arg, "-subj") && arg[1]) {
			if (arg[1][0] != '/' || strchr(arg[1], ';') ||
			    (mode != MODE_SELFSIGNED && strpbrk(arg[1], ",+\\\"<>"))) {
				fprintf(stderr, "error: invalid subject");
				return 1;
			}
			free(subject_buf);
			subject = subject_buf = calloc(strlen(arg[1]) + 1, 1);
			char *oldc = arg[1] + 1, *newc = subject, *delim;
			do {
				delim = strchr(oldc, '=');
				if (!delim) {
					fprintf(stderr, "error: invalid subject");
					return 1;
				}
				memcpy(newc, oldc, delim - oldc + 1);
				newc += delim - oldc + 1;
				oldc = delim + 1;

				delim = strchr(oldc, '/');
				if (!delim) {
					delim = arg[1] + strlen(arg[1]);
				}
				memcpy(newc, oldc, delim - oldc);
				newc += delim - oldc;
				*newc++ = ',';
				oldc = delim + 1;
			} while(*delim);
			arg++;
		} else if (!strcmp(*arg, "-addext") && arg[1]) {
			if (!strncmp(arg[1], "extendedKeyUsage=", strlen("extendedKeyUsage="))) {
				usage = arg[1] + strlen("extendedKeyUsage=");
				ext_key_usage = calloc(1, sizeof(mbedtls_asn1_sequence));
				ext_key_usage->buf.tag = MBEDTLS_ASN1_OID;
				if (!strcmp(usage, "serverAuth")) {
					SET_OID(ext_key_usage->buf, MBEDTLS_OID_SERVER_AUTH);
					eku_server = true;
				} else if (!strcmp(usage, "clientAuth")) {
					SET_OID(ext_key_usage->buf, MBEDTLS_OID_CLIENT_AUTH);
				} else if (!strcmp(usage, "any") || !strcmp(usage, "anyExtendedKeyUsage")) {
					SET_OID(ext_key_usage->buf, MBEDTLS_OID_ANY_EXTENDED_KEY_USAGE);
					eku_server = true;
				} else {
					// there are other extendedKeyUsage OIDs but none conceivably useful here
					fprintf(stderr, "error: unsupported extendedKeyUsage: %s\n", usage);
					return 1;
				}
				//append to the list, so that several usages can be given
				*eku_tail = ext_key_usage;
				eku_tail = &ext_key_usage->next;
			} else if (!strncmp(arg[1], "nameConstraints=", strlen("nameConstraints=")) && mode == MODE_CA) {
				if (nc_parse(arg[1] + strlen("nameConstraints="), &nc, &nc_n, &nc_critical))
					return 1;
			} else if (!strncmp(arg[1], "subjectAltName=", strlen("subjectAltName="))) {
				santype = arg[1] + strlen("subjectAltName=");
				sanval = strchr(santype, ':');
				if (!sanval || !sanval[1]) {
					fprintf(stderr, "error: invalid subjectAltName: %s\n", santype);
					return 1;
				}
				sanval++;
				//OpenSSL takes a comma separated list, here it would become one bogus name
				if (strchr(sanval, ',')) {
					fprintf(stderr, "error: give one subjectAltName entry per -addext: %s\n", santype);
					return 1;
				}
				//build sAN list
				san_cur = calloc(1, sizeof(mbedtls_x509_san_list));
				san_cur->next = NULL;
				if (!strncmp(santype, "DNS:", strlen("DNS:"))) {
					san_cur->node.type = MBEDTLS_X509_SAN_DNS_NAME;
					san_cur->node.san.unstructured_name.p = (unsigned char *) sanval;
					san_cur->node.san.unstructured_name.len = strlen(sanval);
				} else if (!strncmp(santype, "EMAIL:", strlen("EMAIL:")) || !strncmp(santype, "email:", strlen("email:"))) {
					san_cur->node.type = MBEDTLS_X509_SAN_RFC822_NAME;
					san_cur->node.san.unstructured_name.p = (unsigned char *) sanval;
					san_cur->node.san.unstructured_name.len = strlen(sanval);
				} else if (!strncmp(santype, "IP:", strlen("IP:"))) {
					ipaddr = calloc(1, 16);
					iplen = mbedtls_x509_crt_parse_cn_inet_pton(sanval, ipaddr);
					if (!iplen) {
						fprintf(stderr, "error: invalid IP address: %s\n", sanval);
						return 1;
					}
					san_cur->node.type = MBEDTLS_X509_SAN_IP_ADDRESS;
					san_cur->node.san.unstructured_name.p = ipaddr;
					san_cur->node.san.unstructured_name.len = iplen;
				} else if (!strncmp(santype, "URI:", strlen("URI:"))) {
					san_cur->node.type = MBEDTLS_X509_SAN_UNIFORM_RESOURCE_IDENTIFIER;
					san_cur->node.san.unstructured_name.p = (unsigned char *) sanval;
					san_cur->node.san.unstructured_name.len = strlen(sanval);
				} else {
					fprintf(stderr, "error: invalid subjectAltName type: %s\n", santype);
					return 1;
				}

				//append the new entry to our san_list linked list
				if (san_prev == NULL) {
					san_list = san_cur;
				} else {
					san_prev->next = san_cur;
				}
				san_prev = san_cur;
			} else {
				fprintf(stderr, "error: unsupported extension: %s\n", arg[1]);
				return 1;
			}
			arg++;
		} else if (mode != MODE_SELFSIGNED) {
			//selfsigned keeps skipping unknown options, as it always did
			fprintf(stderr, "error: unknown or incomplete option: %s\n", *arg);
			return 1;
		}
		arg++;
	}

	if (mode != MODE_SELFSIGNED) {
		safe_files = true;
		atexit(drop_pending);
		//a router that has not got the time yet starts in 1970 or at its build date
		if (from < 1704067200) {
			fprintf(stderr, "error: the clock is not set (before 2024); try again after NTP\n");
			return 1;
		}
	}
	if (nc_n) {
		bool dns = false, ip = false;
		for (int i = 0; i < nc_n; i++) {
			if (nc[i].excluded)
				continue;
			dns |= nc[i].tag == (MBEDTLS_ASN1_CONTEXT_SPECIFIC | 2);
			ip |= nc[i].tag == (MBEDTLS_ASN1_CONTEXT_SPECIFIC | 7);
		}
		if (dns && !ip)
			fprintf(stderr, "warning: only DNS names are limited; IP addresses stay unlimited (add permitted;IP:...)\n");
		if (ip && !dns)
			fprintf(stderr, "warning: only IP addresses are limited; DNS names stay unlimited (add permitted;DNS:...)\n");
	}
	//a server certificate needs a name to be checked against; a client certificate
	//(-addext extendedKeyUsage=clientAuth only, e.g. for OpenVPN) does not
	if (mode == MODE_SIGN && !san_list && (!eku || eku_server)) {
		fprintf(stderr, "error: sign needs at least one -addext subjectAltName=DNS:...|IP:... "
			"(not for a client certificate: -addext extendedKeyUsage=clientAuth)\n");
		return 1;
	}

	if (mode == MODE_SIGN) {
		if (!capath || !cakeypath) {
			fprintf(stderr, "error: sign needs -CA <ca.crt> and -CAkey <ca.key>\n");
			return 1;
		}
		mbedtls_x509_crt_init(&cacrt);
		if (load_ca(&cacrt, capath)) {
			fprintf(stderr, "error: cannot read CA certificate %s\n", capath);
			return 1;
		}
		if (!mbedtls_x509_crt_get_ca_istrue(&cacrt) ||
		    mbedtls_x509_crt_check_key_usage(&cacrt, MBEDTLS_X509_KU_KEY_CERT_SIGN)) {
			fprintf(stderr, "error: %s is not a CA certificate that may sign\n", capath);
			return 1;
		}
		load_key(&cakey, cakeypath);
		if (mbedtls_pk_check_pair(&cacrt.pk, &cakey, _urandom, NULL)) {
			fprintf(stderr, "error: %s does not belong to %s\n", cakeypath, capath);
			return 1;
		}
		if (mbedtls_x509_dn_gets(issuer, sizeof(issuer), &cacrt.subject) < 0) {
			fprintf(stderr, "error: cannot read the CA subject\n");
			return 1;
		}
		if (from < x509_time_epoch(&cacrt.valid_from)) {
			fprintf(stderr, "error: %s is not valid yet – is the clock right?\n", capath);
			return 1;
		}
		if (from >= x509_time_epoch(&cacrt.valid_to)) {
			fprintf(stderr, "error: %s has expired; make a new CA\n", capath);
			return 1;
		}
		//only issue names the CA is allowed to sign
		for (san_cur = san_list; san_cur; san_cur = san_cur->next) {
			int r = 0;
			const mbedtls_x509_buf *v = &san_cur->node.san.unstructured_name;
			char name[256];
			if (san_cur->node.type == MBEDTLS_X509_SAN_DNS_NAME) {
				snprintf(name, sizeof(name), "%.*s", (int)v->len, v->p);
				r = nc_check(2, name, NULL, 0);
			} else if (san_cur->node.type == MBEDTLS_X509_SAN_IP_ADDRESS) {
				r = nc_check(7, NULL, v->p, v->len);
			} else if (ca_nc_len) {
				r = -2;
			}
			if (r == 1) {
				fprintf(stderr, "error: %s may not sign %s (nameConstraints)\n", capath,
					san_cur->node.type == MBEDTLS_X509_SAN_DNS_NAME ? name : "this IP address");
				return 1;
			} else if (r) {
				fprintf(stderr, r == -2 ? "error: with nameConstraints on %s only DNS and IP names can be signed\n" :
						"error: cannot read the nameConstraints of %s\n", capath);
				return 1;
			}
		}
		//some clients still look at the CN: a CN that looks like a host name must be allowed too
		{
			const char *cn = !strncmp(subject, "CN=", 3) ? subject + 3 : strstr(subject, ",CN=");
			char name[256];
			if (cn && cn != subject + 3)
				cn += 4;
			if (cn) {
				snprintf(name, sizeof(name), "%.*s", (int)strcspn(cn, ","), cn);
				if (strchr(name, '.') && nc_check(2, name, NULL, 0)) {
					fprintf(stderr, "error: %s may not sign CN=%s (nameConstraints)\n", capath, name);
					return 1;
				}
			}
		}
		issuer_key = &cakey;
	}

	if (inkey) {
		load_key(&key, inkey);
	} else {
		gen_key(&key, rsa, ksize, exp, curve, pem);
	}
	if (keypath && mode == MODE_SELFSIGNED)
		write_key(&key, keypath, pem);
	if (mode == MODE_SIGN && !mbedtls_pk_check_pair(&cacrt.pk, &key, _urandom, NULL)) {
		fprintf(stderr, "error: the new certificate would use the CA's own key\n");
		return 1;
	}

	from = (from < 1000000000) ? 1000000000 : from;
	to = from + (time_t)days * 60 * 60 * 24;
	if (to < from)
		to = INT_MAX;
	if (mode == MODE_SIGN && to > x509_time_epoch(&cacrt.valid_to)) {
		//a certificate cannot outlive the CA that signed it
		to = x509_time_epoch(&cacrt.valid_to);
		fprintf(stderr, "note: validity shortened to the end of the CA certificate\n");
	}
	strftime(fstr, sizeof(fstr), "%Y%m%d%H%M%S", gmtime(&from));
	strftime(tstr, sizeof(tstr), "%Y%m%d%H%M%S", gmtime(&to));

	fprintf(stderr, "Generating %s certificate with subject '%s'"
			" and validity %s-%s\n",
			mode == MODE_CA ? "CA" : mode == MODE_SIGN ? "signed" : "selfsigned",
			subject, fstr, tstr);

	mbedtls_x509write_crt_init(&cert);
	//selfsigned always used SHA-256; for ca/sign match the signing key (P-384 → SHA-384, P-521 → SHA-512)
	if (mode != MODE_SELFSIGNED && mbedtls_pk_get_type(issuer_key) == MBEDTLS_PK_ECKEY &&
	    mbedtls_pk_get_bitlen(issuer_key) > 256)
		mbedtls_x509write_crt_set_md_alg(&cert, mbedtls_pk_get_bitlen(issuer_key) > 384 ?
						 MBEDTLS_MD_SHA512 : MBEDTLS_MD_SHA384);
	else
		mbedtls_x509write_crt_set_md_alg(&cert, MBEDTLS_MD_SHA256);
	mbedtls_x509write_crt_set_issuer_key(&cert, issuer_key);
	mbedtls_x509write_crt_set_subject_key(&cert, &key);
	if (mbedtls_x509write_crt_set_subject_name(&cert, subject) ||
	    mbedtls_x509write_crt_set_issuer_name(&cert, mode == MODE_SIGN ? issuer : subject)) {
		fprintf(stderr, "error: invalid subject or issuer name\n");
		return 1;
	}
	if (mbedtls_x509write_crt_set_validity(&cert, fstr, tstr) ||
	    mbedtls_x509write_crt_set_basic_constraints(&cert, mode == MODE_CA, mode == MODE_CA ? pathlen : -1) ||
	    mbedtls_x509write_crt_set_subject_key_identifier(&cert) ||
	    mbedtls_x509write_crt_set_authority_key_identifier(&cert)) {
		fprintf(stderr, "error: failed to set validity, basicConstraints or key identifiers\n");
		return 1;
	}

	if (mode == MODE_CA) {
		if (mbedtls_x509write_crt_set_key_usage(&cert,
				MBEDTLS_X509_KU_KEY_CERT_SIGN | MBEDTLS_X509_KU_CRL_SIGN)) {
			fprintf(stderr, "error: failed to add keyUsage\n");
			return 1;
		}
		if (nc_n && nc_set(&cert, nc, nc_n, nc_critical)) {
			fprintf(stderr, "error: failed to add nameConstraints\n");
			return 1;
		}
	}
	if (mode == MODE_SIGN) {
		if (mbedtls_x509write_crt_set_key_usage(&cert, MBEDTLS_X509_KU_DIGITAL_SIGNATURE |
				(mbedtls_pk_get_type(&key) == MBEDTLS_PK_RSA ? MBEDTLS_X509_KU_KEY_ENCIPHERMENT : 0))) {
			fprintf(stderr, "error: failed to add keyUsage\n");
			return 1;
		}
		//a server certificate unless told otherwise
		if (!eku) {
			eku = calloc(1, sizeof(mbedtls_asn1_sequence));
			eku->buf.tag = MBEDTLS_ASN1_OID;
			SET_OID(eku->buf, MBEDTLS_OID_SERVER_AUTH);
		}
	}
	//an empty subjectAltName is not valid, add it only if names were given
	if (san_list && mbedtls_x509write_crt_set_subject_alternative_name(&cert, san_list)) {
		fprintf(stderr, "error: failed to add subjectAltName\n");
		return 1;
	}
	//mbedtls refuses an empty extendedKeyUsage
	if (eku && mbedtls_x509write_crt_set_ext_key_usage(&cert, eku)) {
		fprintf(stderr, "error: failed to add extendedKeyUsage\n");
		return 1;
	}

	if (_urandom(NULL, (void *) buf, 8)) {
		fprintf(stderr, "error: no random numbers for the serial\n");
		return 1;
	}
	for (len = 0; len < 8; len++)
		sprintf(sstr + len*2, "%02x", (unsigned char) buf[len]);

	mbedtls_mpi_init(&serial);
	if (mbedtls_mpi_read_string(&serial, 16, sstr) ||
	    mbedtls_x509write_crt_set_serial(&cert, &serial)) {
		fprintf(stderr, "error: failed to set the serial\n");
		return 1;
	}

	if (mode != MODE_SELFSIGNED) {
		//make DER, check it with mbedtls itself, then write
		static unsigned char der[8192];
		mbedtls_x509_crt chk;
		uint32_t flags = 0;
		size_t olen;

		len = mbedtls_x509write_crt_der(&cert, der, sizeof(der), _urandom, NULL);
		if (len < 0) {
			fprintf(stderr, "Failed to generate certificate: %d\n", len);
			return 1;
		}
		mbedtls_x509_crt_init(&chk);
		if (mbedtls_x509_crt_parse_der_with_ext_cb(&chk, der + sizeof(der) - len, len, 1,
				mode == MODE_CA ? ca_ext_cb : NULL, NULL) ||
		    mbedtls_x509_crt_verify(&chk, mode == MODE_CA ? &chk : &cacrt, NULL, NULL, &flags, NULL, NULL)) {
			char why[512] = "";
			mbedtls_x509_crt_verify_info(why, sizeof(why), "  ", flags);
			fprintf(stderr, "error: the new certificate does not verify against %s:\n%s",
				mode == MODE_CA ? "itself" : capath, why);
			return 1;
		}
		mbedtls_x509_crt_free(&chk);

		if (keypath)
			write_key(&key, keypath, pem);
		if (pem) {
			if (mbedtls_pem_write_buffer("-----BEGIN CERTIFICATE-----\n", "-----END CERTIFICATE-----\n",
					der + sizeof(der) - len, len, (unsigned char *)buf, sizeof(buf), &olen)) {
				fprintf(stderr, "Failed to generate certificate\n");
				return 1;
			}
			len = strlen(buf);
		} else {
			memcpy(buf + sizeof(buf) - len, der + sizeof(der) - len, len);
		}
		write_file(certpath, len, pem, true);
		commit_pending();
	} else if (pem) {
		if (mbedtls_x509write_crt_pem(&cert, (void *) buf, sizeof(buf), _urandom, NULL) < 0) {
			fprintf(stderr, "Failed to generate certificate\n");
			return 1;
		}

		len = strlen(buf);
	} else {
		len = mbedtls_x509write_crt_der(&cert, (void *) buf, sizeof(buf), _urandom, NULL);
		if (len < 0) {
			fprintf(stderr, "Failed to generate certificate: %d\n", len);
			return 1;
		}
	}
	if (mode == MODE_SELFSIGNED)
		write_file(certpath, len, pem, true);

	mbedtls_x509write_crt_free(&cert);
	mbedtls_mpi_free(&serial);
	mbedtls_pk_free(&key);
	if (mode == MODE_SIGN) {
		mbedtls_pk_free(&cakey);
		mbedtls_x509_crt_free(&cacrt);
	}
	free(nc);
	free(subject_buf);
	while (eku) {
		mbedtls_asn1_sequence *next = eku->next;
		free(eku);
		eku = next;
	}
	while (san_list) {
		mbedtls_x509_san_list *next = san_list->next;
		if (san_list->node.type == MBEDTLS_X509_SAN_IP_ADDRESS)
			free(san_list->node.san.unstructured_name.p);
		free(san_list);
		san_list = next;
	}
	mbedtls_platform_zeroize(buf, sizeof(buf));	//held the new private key

	return 0;
}

int main(int argc, char *argv[])
{
	if (!argv[1]) {
		//Usage
	} else if (!strcmp(argv[1], "eckey")) {
		return dokey(false, argv+2);
	} else if (!strcmp(argv[1], "rsakey")) {
		return dokey(true, argv+2);
	} else if (!strcmp(argv[1], "selfsigned")) {
		return gencert(MODE_SELFSIGNED, argv+2);
	} else if (!strcmp(argv[1], "ca")) {
		return gencert(MODE_CA, argv+2);
	} else if (!strcmp(argv[1], "sign")) {
		return gencert(MODE_SIGN, argv+2);
	}

	fprintf(stderr,
		"PX5G X.509 Certificate Generator Utility v" PX5G_VERSION "\n" PX5G_COPY
		"\nbased on PolarSSL by Christophe Devine and Paul Bakker\n\n");
	fprintf(stderr, "Usage: %s [eckey|rsakey|selfsigned|ca|sign]\n", *argv);
	return 1;
}
