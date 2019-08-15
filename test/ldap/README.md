# Creating a test LDAP server for integration tests

## Starting the OpenLDAP server

These instructions are based on setting up slapd 2.4.44 on Amazon Linux 2;
results may vary.

```
yum install -y openldap-servers
systemctl start slapd
```

## Loading the data

The commands with `-Y EXTERNAL` must be run as root, since UID 0 is
authorized to update the config database.

```
ldapadd -H ldapi:/// -Y EXTERNAL -f /etc/openldap/schema/cosine.ldif
ldapadd -H ldapi:/// -Y EXTERNAL -f /etc/openldap/schema/inetorgperson.ldif
ldapadd -H ldapi:/// -Y EXTERNAL -f local.ldif
ldapmodify -H ldapi:/// -Y EXTERNAL -f config.ldif
ldapadd -w DrowsyPapa -D "cn=Manager,dc=example,dc=com" -f data.ldif
export LDAP_SERVER=ldap://localhost/
```
