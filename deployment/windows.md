# Windows Deployment

## Быстрая установка

```powershell
# Собрать сервер
go build -o j20s-server.exe main.go

# Создать директории
mkdir C:\j20s\ssl

# Сертификат (нужен OpenSSL)
openssl req -x509 -newkey rsa:4096 -keyout C:\j20s\ssl\key.pem -out C:\j20s\ssl\cert.pem -days 365 -nodes -subj "/CN=j20s"

# Запуск
.\j20s-server.exe C:\j20s\ssl\cert.pem C:\j20s\ssl\key.pem
```

## Как Windows Service

```powershell
# Создать службу с помощью sc
sc create "J20S Server" binPath= "C:\j20s\j20s-server.exe C:\j20s\ssl\cert.pem C:\j20s\ssl\key.pem" start= auto

# Запустить службу
sc start "J20S Server"
```

## Альтернатива с NSSM

```powershell
# Скачать NSSM (Non-Sucking Service Manager)
# https://nssm.cc/download

# Установить как службу
nssm install J20S C:\j20s\j20s-server.exe
nssm set J20S AppParameters "C:\j20s\ssl\cert.pem C:\j20s\ssl\key.pem"
nssm set J20S AppDirectory C:\j20s
nssm set J20S DisplayName "J20S Secure Messenger Server"
nssm set J20S Description "Secure messenger relay server"

# Запустить
nssm start J20S
```

## Проверка

```powershell
netstat -an | findstr :8443
curl -k https://localhost:8443/api/status

# Проверка службы
sc query "J20S Server"
# или
nssm status J20S
```

## Файрвол

```powershell
# Открыть порт в Windows Firewall
netsh advfirewall firewall add rule name="J20S Server" dir=in action=allow protocol=TCP localport=8443
``` 