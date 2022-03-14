#!/bin/bash

hacking_dir=$(readlink -fn $(dirname "$BASH_SOURCE"))
pip3 install --user pytest flake8 cryptography aiosmtpd
sudo yum install -y openldap-servers yadifa libcmocka-devel
sudo systemctl start slapd
sudo ldapadd -H ldapi:/// -Y EXTERNAL -f /etc/openldap/schema/cosine.ldif
sudo ldapadd -H ldapi:/// -Y EXTERNAL -f /etc/openldap/schema/inetorgperson.ldif
sudo ldapadd -H ldapi:/// -Y EXTERNAL -f ${hacking_dir}/../test/ldap/local.ldif
sudo ldapmodify -H ldapi:/// -Y EXTERNAL -f ${hacking_dir}/../test/ldap/config.ldif
ldapadd -w DrowsyPapa -D "cn=Manager,dc=example,dc=com" -f ${hacking_dir}/../test/ldap/data.ldif
echo 'export LDAP_SERVER=ldap://localhost/'
