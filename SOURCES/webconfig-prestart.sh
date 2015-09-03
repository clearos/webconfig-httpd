#!/bin/sh

# Environment
KEY="/usr/clearos/sandbox/etc/httpd/conf/server.key"
CRT="/usr/clearos/sandbox/etc/httpd/conf/server.crt"
HOST_CONF="/usr/clearos/sandbox/etc/httpd/conf.d/servername.conf"
HOST_CONF_TEST="/var/tmp/servername.conf.clearos"
SSL_CONF="/usr/clearos/sandbox/etc/httpd/conf/openssl.cnf"

# Determine our hostname
if [ -e /etc/clearos/network.conf ]; then
    source /etc/clearos/network.conf
    HOSTNAME=$INTERNET_HOSTNAME
fi

if [ -z "$HOSTNAME" ]; then
    HOSTNAME=`cat /etc/hostname 2>/dev/null`
fi

if [ -z "$HOSTNAME" ]; then
    HOSTNAME="myserver.lan"
fi

# Copy hostname to ServerName
echo "ServerName $HOSTNAME" > $HOST_CONF_TEST

if diff $HOST_CONF_TEST $HOST_CONF >/dev/null 2>&1; then
	rm $HOST_CONF_TEST
else
	mv $HOST_CONF_TEST $HOST_CONF
fi

# Generate SSL keys
[ -e "$SSL_CONF" ] || exit 1
[ ! -s "$KEY" ] || exit 0

umask 77

sed -e "s/^CN .*/CN = $HOSTNAME/" $SSL_CONF > /var/tmp/openssl.cnf.$$

# Generate keys
/usr/bin/openssl genrsa -out $KEY 2048 2>/dev/null
/usr/bin/openssl req -new -key $KEY -x509 -out $CRT -config /var/tmp/openssl.cnf.$$ -days 3000 -set_serial `date "+%s"` 2>/dev/null

# Fix file permissions and ownership
chown webconfig.webconfig $KEY $CRT /var/tmp/openssl.cnf.$$
chmod 600 $KEY $CRT
rm -f /var/tmp/openssl.cnf.$$
