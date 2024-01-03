
## New
- Add `capture_commands` to options for capturing more information about the threat source (Look at the table if it's supported or not)


## Install

```
> python3 --version
Python 3.8.18

> pip3 install -r requirements.txt
```

## Usage Example 

### Quick Start

```
> python3 code/http_server.py
```

### Custom username, password, ip and port

```
> python3 code/http_server.py --custom --username='zju' --password='zju' --ip='0.0.0.0' --port='80'
```

### config.json (Output to file and terminal)

```json
{
    "logs": "file, terminal",
    "logs_location": "./log/",
    "honeypots": {
        "http": {
            "port": 80,
            "ip": "127.0.0.1",
            "username": "ez",
            "password": "ez",
            "log_file_name": "http.log",
            "max_bytes": 10000,
            "backup_count": 10
        }
    }
}
```

<!-- ```json
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
``` -->

```
> python3 code/http_server.py --config='config.json'
```

### Possible Error

```
Couldn't listen on any:80: [Errno 48] Address already in use.
```

- Solution: Change the port number or kill the process that is using the port

```
> lsof -i:80
COMMAND     PID USER   FD   TYPE  DEVICE SIZE/OFF NODE NAME
python3.8 <PID>    *    *   IPv4       *      0t0  TCP *:http (LISTEN)

> kill -9 <PID>
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

## acknowledgment

- This project is based on the work of [honeypots](https://github.com/qeeqbox/honeypots)



