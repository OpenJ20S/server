# macOS Deployment

## Быстрая установка

```bash
# Собрать сервер
go build -o j20s-server main.go

# Создать директории
mkdir -p ~/j20s/ssl

# Сертификат
openssl req -x509 -newkey rsa:4096 -keyout ~/j20s/ssl/key.pem -out ~/j20s/ssl/cert.pem -days 365 -nodes -subj "/CN=j20s"
chmod 600 ~/j20s/ssl/key.pem

# Запуск
./j20s-server ~/j20s/ssl/cert.pem ~/j20s/ssl/key.pem
```

## Как сервис (launchd)

```bash
# Установить в систему
sudo cp j20s-server /usr/local/bin/
sudo chmod +x /usr/local/bin/j20s-server

# Создать директории
sudo mkdir -p /usr/local/etc/j20s

# Сертификат
sudo openssl req -x509 -newkey rsa:4096 -keyout /usr/local/etc/j20s/key.pem -out /usr/local/etc/j20s/cert.pem -days 365 -nodes -subj "/CN=j20s"
sudo chmod 600 /usr/local/etc/j20s/key.pem

# Launchd plist
sudo cat > /Library/LaunchDaemons/org.j20s.server.plist << 'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>org.j20s.server</string>
    <key>ProgramArguments</key>
    <array>
        <string>/usr/local/bin/j20s-server</string>
        <string>/usr/local/etc/j20s/cert.pem</string>
        <string>/usr/local/etc/j20s/key.pem</string>
    </array>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
</dict>
</plist>
EOF

# Запуск
sudo launchctl load /Library/LaunchDaemons/org.j20s.server.plist
```

## Проверка

```bash
lsof -i :8443
curl -k https://localhost:8443/api/status
``` 