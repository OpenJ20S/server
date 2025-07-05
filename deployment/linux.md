# Linux Deployment

## Ubuntu/Debian

```bash
# Создать пользователя
useradd -r -s /bin/false -d /opt/j20s j20s

# Собрать сервер
GOOS=linux GOARCH=amd64 go build -o j20s-server main.go

# Установить
cp j20s-server /usr/local/bin/
chmod +x /usr/local/bin/j20s-server

# Создать директории
mkdir -p /etc/ssl/j20s

# Сертификат
openssl req -x509 -newkey rsa:4096 -keyout /etc/ssl/j20s/key.pem -out /etc/ssl/j20s/cert.pem -days 365 -nodes -subj "/CN=j20s"
chown j20s:j20s /etc/ssl/j20s/*
chmod 600 /etc/ssl/j20s/key.pem

# Systemd service
cat > /etc/systemd/system/j20s.service << 'EOF'
[Unit]
Description=J20S Server
After=network.target

[Service]
Type=simple
User=j20s
ExecStart=/usr/local/bin/j20s-server /etc/ssl/j20s/cert.pem /etc/ssl/j20s/key.pem
Restart=always

[Install]
WantedBy=multi-user.target
EOF

# Запуск
systemctl enable j20s
systemctl start j20s
```

## CentOS/RHEL

```bash
# Создать пользователя
useradd -r -s /sbin/nologin j20s

# Остальное аналогично Ubuntu
```

## Проверка

```bash
systemctl status j20s
ss -tulpn | grep 8443
curl -k https://localhost:8443/api/status
``` 