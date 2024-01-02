
## New
- Add `capture_commands` to options for capturing more information about the threat source (Look at the table if it's supported or not)


## Install

```
pip3 install -r requirements.txt
```

## Usage Example 

```
python code/http_server.py
```

```
python code/http_server.py --custom --username='ez' --password='123'
```

#### config.json (Output to folder and terminal)
```json
{
  "logs": "file,terminal,json",
  "logs_location": "/var/log/honeypots/",
  "syslog_address": "",
  "syslog_facility": 0,
  "postgres": "",
  "sqlite_file":"",
  "db_options": [],
  "sniffer_filter": "",
  "sniffer_interface": "",
  "honeypots": {
    "ftp": {
      "port": 21,
      "ip": "0.0.0.0",
      "username": "ftp",
      "password": "anonymous",
      "log_file_name": "ftp.log",
      "max_bytes": 10000,
      "backup_count": 10,
      "options":["capture_commands"]
    }
  }
}
```

## Usage Example - Import as object and auto test
```python
from honeypots import QSSHServer
qsshserver = QSSHServer(port=9999)
qsshserver.run_server(process=True)
qsshserver.test_server(port=9999)
INFO:chameleonlogger:['servers', {'status': 'success', 'username': 'test', 'src_ip': '127.0.0.1', 'server': 'ssh_server', 'action': 'login', 'password': 'test', 'src_port': 38696}]
qsshserver.kill_server()
```

## Usage Example - Import as object and test with external ssh command
```python
#you need higher user permissions for binding\closing some ports

from honeypots import QSSHServer
qsshserver = QSSHServer(port=9999)
qsshserver.run_server(process=True)
```
```sh
ssh test@127.0.0.1
```
```python
INFO:chameleonlogger:['servers', {'status': 'success', 'username': 'test', 'src_ip': '127.0.0.1', 'server': 'ssh_server', 'action': 'login', 'password': 'test', 'src_port': 38696}]
qsshserver.kill_server()
```

## All output values
```sh
'error'     :'Information about current error' 
'server'    :'Server name'
'timestamp' :'Time in ISO'
'action'    :'Query, login, etc..'
'data'      :'More info about the action'
'status'    :'The return status of the action (success or fail)'
'dest_ip'   :'Server address'
'dest_port' :'Server port'
'src_ip'    :'Attacker address'
'src_port'  :'Attacker port'
'username'  :'Attacker username'
'password'  :'Attacker password'
```

## Current Servers/Emulators
- QDNSServer
    - Server: DNS 
    - Port: 53/udp
    - Lib: Twisted.dns
    - Logs: ip, port
- QFTPServer
    - Server: FTP 
    - Port: 21/tcp
    - Lib: Twisted.ftp
    - Logs: ip, port, username and password (default)
    - Options: Capture all threat actor commands and data (avalible)
- QHTTPProxyServer
    - Server: HTTP Proxy
    - Port: 8080/tcp
    - Lib: Twisted (low level emulation)
    - Logs: ip, port and data
    - Options: Capture all threat actor commands and data (avalible)
- QHTTPServer
    - Server: HTTP
    - Port: 80/tcp
    - Lib: Twisted.http
    - Logs: ip, port, username and password
    - Options: Capture all threat actor commands and data (avalible)
- QHTTPSServer
    - Server: HTTPS
    - Port: 443/tcp
    - Lib: Twisted.https
    - Logs: ip, port, username and password
- QSOCKS5Server
    - Server: SOCK5
    - Port: 1080/tcp
    - Lib: socketserver
    - Logs: ip, port, username and password
- QSSHServer
    - Server: SSH
    - Port: 22/tcp
    - Lib: paramiko
    - Logs: ip, port, username and password
    - Options: Capture all threat actor commands and data (avalible)
- QTelnetServer
    - Server: Telnet
    - Port: 23/tcp
    - Lib: Twisted
    - Logs: ip, port, username and password
- QRDPServer
    - Emulator: RDP
    - Port: 3389/tcp
    - Lib: Sockets
    - Logs: ip, port, username and password
    - Options: Capture all threat actor commands and data (avalible)
- QDHCPServer
    - Emulator: DHCP
    - Port: 67/udp
    - Lib: Sockets
    - Logs: ip, port


## acknowledgment

- This project is based on the work of [honeypots](https://github.com/qeeqbox/honeypots)
- By using this framework, you are accepting the license terms of all these packages: `pipenv twisted psutil psycopg2-binary dnspython requests impacket paramiko redis mysql-connector pycryptodome vncdotool service_identity requests[socks] pygments http.server`
- Let me know if I missed a reference or resource!

## Notes

- Almost all servers and emulators are stripped-down - You can adjust that as needed


