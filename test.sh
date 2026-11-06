#!/bin/sh
# px5g ca/sign checks. Run from an empty directory:  sh /path/to/test.sh /path/to/px5g
# Needs openssl (to check the results independently). testdata/ holds two throw-away test CAs
# (one expired, one valid only from 2090) – never use them for anything else.
P=${1:-px5g}; TD=$(cd "$(dirname "$0")" && pwd)/testdata; ok=0; bad=0
t() { if eval "$2" >/dev/null 2>&1; then echo "ok   $1"; ok=$((ok+1)); else echo "FAIL $1"; bad=$((bad+1)); fi; }
err() { "$P" "$@" 2>&1 >/dev/null; }	# stderr of a px5g run
SAN="-addext subjectAltName=DNS:r.lan"
NC="nameConstraints=critical,permitted;DNS:lan,permitted;DNS:local,permitted;DNS:home.arpa,permitted;IP:192.168.0.0/255.255.0.0,permitted;IP:10.0.0.0/8,permitted;IP:fd00::/8,excluded;DNS:bad.lan"

$P ca -newkey ec -days 3650 -subj "/CN=Home CA/O=Home Access" -keyout ca.key -out ca.crt -addext "$NC" 2>/dev/null
$P sign -CA ca.crt -CAkey ca.key -newkey ec -days 397 -subj /CN=openwrt-main.lan \
  -addext subjectAltName=DNS:openwrt-main.lan -addext subjectAltName=IP:192.168.1.1 -keyout r1.key -out r1.crt 2>/dev/null
$P sign -CA ca.crt -CAkey ca.key -newkey rsa:2048 -subj /CN=nas.lan -addext subjectAltName=DNS:nas.lan -keyout nas.key -out nas.crt 2>/dev/null
$P sign -CA ca.crt -CAkey ca.key -key r1.key -days 397 -subj /CN=openwrt-main.lan -addext subjectAltName=DNS:openwrt-main.lan -out r1-renew.crt 2>/dev/null
$P sign -CA ca.crt -CAkey ca.key -newkey ec -days 9999 -subj /CN=long.lan -addext subjectAltName=DNS:long.lan -out long.crt 2>/dev/null
$P ca -newkey rsa:2048 -days 3650 -subj "/CN=Other CA" -keyout o.key -out o.crt 2>/dev/null
$P selfsigned -newkey ec -subj /CN=self.lan -keyout s.key -out s.crt 2>/dev/null
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 3650 -subj "/CN=OpenSSL CA" -keyout oc.key -out oc.crt \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" -addext "nameConstraints=critical,permitted;DNS:lan" 2>/dev/null
$P sign -CA oc.crt -CAkey oc.key -newkey ec -subj /CN=x.lan -addext subjectAltName=DNS:x.lan -out x.crt 2>/dev/null

echo "-- what it makes"
t "CA is CA:TRUE, keyCertSign"           "openssl x509 -in ca.crt -noout -text | grep -q 'CA:TRUE' && openssl x509 -in ca.crt -noout -text | grep -q 'Certificate Sign'"
t "CA keeps critical nameConstraints when asked" "openssl x509 -in ca.crt -noout -text | grep -q 'Name Constraints: critical'"
t "server cert verifies (strict, sslserver)" "openssl verify -x509_strict -purpose sslserver -CAfile ca.crt r1.crt"
t "server cert has SAN DNS+IP, serverAuth"  "openssl x509 -in r1.crt -noout -ext subjectAltName | grep -q 'IP Address:192.168.1.1' && openssl x509 -in r1.crt -noout -ext extendedKeyUsage | grep -q 'Server Authentication'"
t "server cert is CA:FALSE"              "openssl x509 -in r1.crt -noout -text | grep -q 'CA:FALSE'"
t "issuer = CA subject"                  "[ \"\$(openssl x509 -in r1.crt -noout -issuer_hash)\" = \"\$(openssl x509 -in ca.crt -noout -subject_hash)\" ]"
t "RSA server cert verifies, keyEncipherment" "openssl verify -CAfile ca.crt nas.crt && openssl x509 -in nas.crt -noout -ext keyUsage | grep -q 'Key Encipherment'"
t "renew with existing key keeps the key" "[ \"\$(openssl x509 -in r1.crt -noout -pubkey)\" = \"\$(openssl x509 -in r1-renew.crt -noout -pubkey)\" ] && openssl verify -CAfile ca.crt r1-renew.crt"
t "validity capped at the CA's end"      "[ \"\$(openssl x509 -in long.crt -noout -enddate)\" = \"\$(openssl x509 -in ca.crt -noout -enddate)\" ]"
t "RSA CA without constraints works"     "openssl x509 -in o.crt -noout -text | grep -q 'CA:TRUE' && ! openssl x509 -in o.crt -noout -text | grep -q 'Name Constraints'"
t "signs with a CA made by OpenSSL"      "openssl verify -CAfile oc.crt x.crt"
t "selfsigned unchanged (CA:FALSE)"      "openssl x509 -in s.crt -noout -text | grep -q 'CA:FALSE'"
t "DER output also works"                "$P sign -der -CA ca.crt -CAkey ca.key -newkey ec -subj /CN=d.lan -addext subjectAltName=DNS:d.lan -keyout d.key -out d.der && openssl x509 -inform der -in d.der -out d.pem && openssl verify -CAfile ca.crt d.pem"
t "P-384 CA signs with SHA-384"          "$P ca -newkey ec -pkeyopt ec_paramgen_curve:P-384 -subj /CN=C384 -keyout c384.key -out c384.crt && openssl x509 -in c384.crt -noout -text | grep -q ecdsa-with-SHA384"
t "name limits not critical by default, mbedtls-readable" "$P ca -newkey ec -subj /CN=Soft -keyout soft.key -out soft.crt -addext 'nameConstraints=permitted;DNS:lan,permitted;IP:192.168.0.0/16' && openssl x509 -in soft.crt -noout -text | grep 'Name Constraints' | grep -vq critical"

echo "-- name limits (review 1, 5)"
t "refuses empty nameConstraints"        "! $P ca -newkey ec -subj /CN=E -out e.crt -addext 'nameConstraints=' && ! $P ca -newkey ec -subj /CN=E -out e.crt -addext 'nameConstraints=critical'"
t "warns when only DNS names are limited" "err ca -newkey ec -subj /CN=W -keyout w.key -out w.crt -addext 'nameConstraints=permitted;DNS:lan' | grep -q 'IP addresses stay unlimited'"
t "refuses to sign bank.com"             "! $P sign -CA ca.crt -CAkey ca.key -newkey ec -subj /CN=bank.com -addext subjectAltName=DNS:bank.com -out b.crt && [ ! -e b.crt ]"
t "refuses an excluded name (bad.lan)"   "! $P sign -CA ca.crt -CAkey ca.key -newkey ec -subj /CN=bad.lan -addext subjectAltName=DNS:bad.lan -out b.crt"
t "refuses lookalike evillan for 'lan'"  "! $P sign -CA ca.crt -CAkey ca.key -newkey ec -subj /CN=evillan -addext subjectAltName=DNS:evillan -out b.crt"
t "refuses IP outside the ranges"        "! $P sign -CA ca.crt -CAkey ca.key -newkey ec -subj /CN=ip -addext subjectAltName=IP:8.8.8.8 -out b.crt"
t "accepts IP and IPv6 inside the ranges" "$P sign -CA ca.crt -CAkey ca.key -newkey ec -subj /CN=ip -addext subjectAltName=IP:10.1.2.3 -addext subjectAltName=IP:fd12::1 -out ip.crt && openssl verify -CAfile ca.crt ip.crt"
t "refuses e-mail names under name limits" "! $P sign -CA ca.crt -CAkey ca.key -newkey ec -subj /CN=m.lan -addext subjectAltName=DNS:m.lan -addext subjectAltName=email:a@b.com -out b.crt"
t "refuses a CN outside the limits"      "! $P sign -CA ca.crt -CAkey ca.key -newkey ec -subj /CN=bank.com -addext subjectAltName=DNS:r.lan -out b.crt"
t "OpenSSL CA's limits also enforced"    "! $P sign -CA oc.crt -CAkey oc.key -newkey ec -subj /CN=bank.com -addext subjectAltName=DNS:bank.com -out b.crt"

echo "-- keys and CA (review 2, 3, 6)"
t "refuses the CA's own key for a server" "! $P sign -CA ca.crt -CAkey ca.key -key ca.key -subj /CN=r.lan $SAN -out b.crt"
t "refuses an expired CA"                "err sign -CA $TD/expired-ca.crt -CAkey $TD/expired-ca.key -newkey ec -subj /CN=r.lan $SAN -out b.crt | grep -q expired"
t "refuses a CA not valid yet (clock)"   "err sign -CA $TD/future-ca.crt -CAkey $TD/future-ca.key -newkey ec -subj /CN=r.lan $SAN -out b.crt | grep -q 'not valid yet'"
t "refuses a non-CA certificate as CA"   "! $P sign -CA s.crt -CAkey s.key -newkey ec -subj /CN=y.lan $SAN -out y.crt"
t "refuses a CA key that does not match" "! $P sign -CA ca.crt -CAkey o.key -newkey ec -subj /CN=y.lan $SAN -out y.crt"
t "refuses sign without -CA/-CAkey"      "! $P sign -newkey ec -subj /CN=y.lan $SAN -out y.crt"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -subj "/CN=Home\, CA/O=A+OU=B" -multivalue-rdn -keyout cm.key -out cm.crt \
  -addext basicConstraints=critical,CA:TRUE -addext keyUsage=critical,keyCertSign 2>/dev/null
t "odd CA name: refused, nothing written" "err sign -CA cm.crt -CAkey cm.key -newkey ec -subj /CN=r.lan $SAN -keyout cmr.key -out cmr.crt | grep -q 'does not verify' && [ ! -e cmr.crt ] && [ ! -e cmr.key ]"

echo "-- files (review 4)"
echo old > k.key; chmod 644 k.key
t "existing 0644 key file becomes 600"   "$P sign -CA ca.crt -CAkey ca.key -newkey ec -subj /CN=k.lan -addext subjectAltName=DNS:k.lan -keyout k.key -out k.crt && [ \"\$(stat -c %a k.key)\" = 600 ] && openssl pkey -in k.key -noout"
echo secret > target; ln -s target link.key
t "symlink is replaced, its target untouched" "$P sign -CA ca.crt -CAkey ca.key -newkey ec -subj /CN=l.lan -addext subjectAltName=DNS:l.lan -keyout link.key -out l.crt && [ \"\$(cat target)\" = secret ] && [ ! -L link.key ]"
cp r1.key keep.key; cp r1.crt keep.crt
t "failure leaves old key and cert alone" "! $P sign -CA ca.crt -CAkey ca.key -newkey ec -subj /CN=bank.com -addext subjectAltName=DNS:bank.com -keyout keep.key -out keep.crt && cmp -s keep.key r1.key && cmp -s keep.crt r1.crt"
t "failing cert path: key not replaced"  "! $P sign -CA ca.crt -CAkey ca.key -newkey ec -subj /CN=r.lan $SAN -keyout keep.key -out /nonexistent/x.crt && cmp -s keep.key r1.key"
t "no temporary files left behind"       "! ls ./*.?????? 2>/dev/null | grep -q ."
t "key files are mode 600, certs 644"    "[ \"\$(stat -c %a r1.key)\" = 600 ] && [ \"\$(stat -c %a r1.crt)\" = 644 ]"

echo "-- input checks (review 7, 9 and info)"
t "refuses commas etc. in -subj"         "! $P sign -CA ca.crt -CAkey ca.key -newkey ec -subj '/CN=r.lan,O=Evil' $SAN -out b.crt && ! $P ca -newkey ec -subj '/CN=a+OU=b' -out b.crt"
t "sign needs a subjectAltName"          "! $P sign -CA ca.crt -CAkey ca.key -newkey ec -subj /CN=r.lan -out b.crt"
t "refuses -days 0, -1, 99999, abc"      "! $P ca -newkey ec -days 0 -subj /CN=a -out b.crt && ! $P ca -newkey ec -days -1 -subj /CN=a -out b.crt && ! $P ca -newkey ec -days 99999 -subj /CN=a -out b.crt && ! $P ca -newkey ec -days abc -subj /CN=a -out b.crt"
t "refuses RSA below 2048 bits"          "! $P ca -newkey rsa:1024 -subj /CN=a -out b.crt"
t "refuses -pathlen 9 and junk"          "! $P ca -newkey ec -pathlen 9 -subj /CN=a -out b.crt && ! $P ca -newkey ec -pathlen x -subj /CN=a -out b.crt"
t "refuses bad nameConstraints"          "! $P ca -newkey ec -subj /CN=z -out z.crt -addext 'nameConstraints=permitted;URI:x' && ! $P ca -newkey ec -subj /CN=z -out z.crt -addext 'nameConstraints=permitted;IP:10.0.0.0/33'"
t "refuses unknown options (ca/sign)"    "! $P ca -newkey ec -subj /CN=a -out b.crt -bogus"
echo "-- client certificates (OpenVPN)"
openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -days 3650 -subj "/CN=VPN CA" -keyout vc.key -out vc.crt \
  -addext "basicConstraints=critical,CA:TRUE" -addext "keyUsage=critical,keyCertSign,cRLSign" 2>/dev/null
$P sign -CA vc.crt -CAkey vc.key -newkey ec -days 825 -subj /CN=anna-phone -addext extendedKeyUsage=clientAuth -keyout cl.key -out cl.crt 2>/dev/null
t "client cert without SAN (clientAuth only)" "[ -s cl.crt ] && ! openssl x509 -in cl.crt -noout -ext subjectAltName 2>/dev/null | grep -q DNS"
t "client cert verifies (strict, sslclient)"  "openssl verify -x509_strict -purpose sslclient -CAfile vc.crt cl.crt"
t "client cert has clientAuth, not serverAuth" "openssl x509 -in cl.crt -noout -ext extendedKeyUsage | grep -q 'Client Authentication' && ! openssl x509 -in cl.crt -noout -ext extendedKeyUsage | grep -q 'Server Authentication'"
t "client key belongs to the cert"       "[ \"\$(openssl x509 -in cl.crt -noout -pubkey)\" = \"\$(openssl pkey -in cl.key -pubout)\" ]"
t "a server cert still needs a SAN"      "! $P sign -CA vc.crt -CAkey vc.key -newkey ec -subj /CN=s -out s2.crt && ! $P sign -CA vc.crt -CAkey vc.key -newkey ec -subj /CN=s -addext extendedKeyUsage=clientAuth -addext extendedKeyUsage=serverAuth -out s3.crt"
echo "$ok passed, $bad failed"; [ $bad = 0 ]
