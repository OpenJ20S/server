# FreeBSD Deployment

## Быстрая установка

```bash
# Создать пользователя
pw useradd j20s -d /nonexistent -s /usr/sbin/nologin

# Собрать сервер
GOOS=freebsd GOARCH=amd64 go build -o j20s-server main.go

# Копировать в систему
cp j20s-server /usr/local/bin/
chmod +x /usr/local/bin/j20s-server

# Создать директории
mkdir -p /etc/ssl/j20s

# Сгенерировать сертификат
openssl req -x509 -newkey rsa:4096 -keyout /etc/ssl/j20s/key.pem -out /etc/ssl/j20s/cert.pem -days 365 -nodes -subj "/CN=j20s"
chown j20s:j20s /etc/ssl/j20s/*
chmod 600 /etc/ssl/j20s/key.pem

# Создать rc.d скрипт
cat > /usr/local/etc/rc.d/j20s << 'EOF'
#!/bin/sh
. /etc/rc.subr
name=j20s
rcvar=j20s_enable
load_rc_config $name
: ${j20s_enable:=NO}
: ${j20s_user:=j20s}
pidfile=/var/run/${name}.pid
command=/usr/sbin/daemon
command_args="-p ${pidfile} -u ${j20s_user} /usr/local/bin/j20s-server /etc/ssl/j20s/cert.pem /etc/ssl/j20s/key.pem"
run_rc_command "$1"
EOF

chmod +x /usr/local/etc/rc.d/j20s

# Включить и запустить
echo 'j20s_enable="YES"' >> /etc/rc.conf
service j20s start
```

## Проверка

```bash
service j20s status
sockstat -l | grep 8443
curl -k https://localhost:8443/api/status
``` 