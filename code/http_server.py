from warnings import filterwarnings
filterwarnings(action='ignore', module='.*OpenSSL.*')

from cgi import FieldStorage
from requests.packages.urllib3 import disable_warnings
from twisted.internet import reactor
from twisted.web.server import Site
from twisted.web.resource import Resource
from twisted.python import log as tlog
from random import choice
from tempfile import gettempdir, _get_candidate_names
from subprocess import Popen
from os import path, getenv
from helper import close_port_wrapper, get_free_port, kill_server_wrapper, server_arguments, setup_logger, disable_logger, set_local_vars, check_if_server_is_running
from uuid import uuid4
from contextlib import suppress

disable_warnings()

class QHTTPServer():
    def __init__(self, **kwargs):
        self.auto_disabled = None
        self.key = path.join(gettempdir(), next(_get_candidate_names()))
        self.cert = path.join(gettempdir(), next(_get_candidate_names()))
        self.mocking_server = choice(['Apache', 'nginx', 'Microsoft-IIS/7.5', 'Microsoft-HTTPAPI/2.0', 'Apache/2.2.15', 'SmartXFilter', 'Microsoft-IIS/8.5', 'Apache/2.4.6', 'Apache-Coyote/1.1', 'Microsoft-IIS/7.0', 'Apache/2.4.18', 'AkamaiGHost', 'Apache/2.2.25', 'Microsoft-IIS/10.0', 'Apache/2.2.3', 'nginx/1.12.1', 'Apache/2.4.29', 'cloudflare', 'Apache/2.2.22'])
        self.process = None

        self.uuid = 'honeypot' + '_' + __class__.__name__ + '_' + str(uuid4())[:8]

        # self.config = kwargs.get('config', '')

        # if self.config:
        #     self.logs = setup_logger(__class__.__name__, self.uuid, self.config)
        #     set_local_vars(self, self.config)
        # else:
        #     self.logs = setup_logger(__class__.__name__, self.uuid, None)
        
        self.logs = setup_logger(__class__.__name__, self.uuid, None)

        self.ip = kwargs.get('ip', None) or (hasattr(self, 'ip') and self.ip) or '127.0.0.1'
        self.port = (kwargs.get('port', None) and int(kwargs.get('port', None))) or (hasattr(self, 'port') and self.port) or 80
        self.username = kwargs.get('username', None) or (hasattr(self, 'username') and self.username) or 'honeypot'
        self.password = kwargs.get('password', None) or (hasattr(self, 'password') and self.password) or 'honeypot'

        self.options = kwargs.get('options', '') or (hasattr(self, 'options') and self.options) or getenv('HONEYPOTS_OPTIONS', '') or ''
        disable_logger(1, tlog)

    def http_server_main(self):
        _q_s = self

        class MainResource(Resource):
            isLeaf = True

            home_file = b'''
            <!DOCTYPE html>
            <html>
            <head>
            <title>Trap!</title>
            <style>
                body {
                font-family: Arial, sans-serif;
                background-color: #f1f1f1;
                text-align: center;
                }
                
                .trap-container {
                margin: 0 auto;
                width: 100%;
                height: 100vh;
                display: flex;
                flex-direction: column;
                justify-content: center;
                align-items: center;
                background-color: white;
                border-radius: 5px;
                box-shadow: 0px 0px 10px rgba(0, 0, 0, 0.1);
                }
                
                .trap-text {
                color: #FF5252;
                font-size: 24px;
                font-weight: bold;
                margin-bottom: 30px;
                }
                
                .trap-image {
                width: 150px;
                height: 150px;
                margin-bottom: 30px;
                }
            </style>
            </head>
            <body>
            <div class="trap-container">
                <h1 class="trap-text">You Fell into the Trap!</h1>
                <img src="https://www.freeimg.cn/i/2024/01/02/6593fb53a812f.png" alt="Tricky Trap" class="trap-image">
                <p>HaHa! You have fallen into a HoneyPot!</p>
            </div>
            </body>
            </html>'''

            login_file = b'''      
            <!DOCTYPE html>
            <html>
            <head>
            <title>Login</title>
            <meta charset="UTF-8">
            <style>
                body {
                font-family: Arial, sans-serif;
                background-color: #f1f1f1;
                text-align: center;
                padding-top: 150px;
                }
                
                .login {
                margin: 0 auto;
                width: 500px;
                height: 300px;
                background-color: white;
                padding: 20px;
                border-radius: 5px;
                box-shadow: 0px 0px 10px rgba(0, 0, 0, 0.1);
                }
                
                .login input[type="text"],
                .login input[type="password"] {
                width: 90%;
                padding: 10px;
                margin-bottom: 15px;
                border: 2px solid #ccc;
                border-radius: 3px;
                }
                
                .login input[type="submit"] {
                width: 100%;
                padding: 10px;
                background-color: #4CAF50;
                color: white;
                border: none;
                border-radius: 3px;
                cursor: pointer;
                }
                
                .login input[type="submit"]:hover {
                background-color: #45a049;
                }
            </style>
            </head>
            <body>
            <div class="login">
                <h1>ZJU Final-Lab</h1>
                <form id='login' action='' method='post'>
                <input type="text" name="username" placeholder="username" required><br>
                <input type="password" name="password" placeholder="password" required><br>
                <input type="submit" value="submit">
                </form>
            </div>
            </body>
            </html>'''

            def check_bytes(self, string):
                if isinstance(string, bytes):
                    return string.decode()
                else:
                    return str(string)

            def render(self, request):

                headers = {}
                client_ip = ""

                with suppress(Exception):
                    def check_bytes(string):
                        if isinstance(string, bytes):
                            return string.decode()
                        else:
                            return str(string)
                    for item, value in dict(request.requestHeaders.getAllRawHeaders()).items():
                        headers.update({check_bytes(item): ','.join(map(check_bytes, value))})
                    headers.update({'method': check_bytes(request.method)})
                    headers.update({'uri': check_bytes(request.uri)})

                if 'fix_get_client_ip' in _q_s.options:
                    with suppress(Exception):
                        raw_headers = dict(request.requestHeaders.getAllRawHeaders())
                        if b'X-Forwarded-For' in raw_headers:
                            client_ip = check_bytes(raw_headers[b'X-Forwarded-For'][0])
                        elif b'X-Real-IP' in raw_headers:
                            client_ip = check_bytes(raw_headers[b'X-Real-IP'][0])

                if client_ip == "":
                    client_ip = request.getClientAddress().host

                with suppress(Exception):
                    if "capture_commands" in _q_s.options:
                        _q_s.logs.info({'server': 'http_server', 'action': 'connection', 'src_ip': client_ip, 'src_port': request.getClientAddress().port, 'dest_ip': _q_s.ip, 'dest_port': _q_s.port, 'data': headers})
                    else:
                        _q_s.logs.info({'server': 'http_server', 'action': 'connection', 'src_ip': client_ip, 'src_port': request.getClientAddress().port, 'dest_ip': _q_s.ip, 'dest_port': _q_s.port})

                if _q_s.mocking_server != '':
                    request.responseHeaders.removeHeader('Server')
                    request.responseHeaders.addRawHeader('Server', _q_s.mocking_server)

                if request.method == b'GET' or request.method == b'POST':
                    _q_s.logs.info({'server': 'http_server', 'action': request.method.decode(), 'src_ip': client_ip, 'src_port': request.getClientAddress().port, 'dest_ip': _q_s.ip, 'dest_port': _q_s.port})

                if request.method == b'GET':
                    if request.uri == b'/login.html':
                        if _q_s.username != '' and _q_s.password != '':
                            request.responseHeaders.addRawHeader('Content-Type', 'text/html; charset=utf-8')
                            return self.login_file

                    request.responseHeaders.addRawHeader('Content-Type', 'text/html; charset=utf-8')
                    return self.login_file

                elif request.method == b'POST':
                    self.headers = request.getAllHeaders()
                    if request.uri == b'/login.html' or b'/':
                        if _q_s.username != '' and _q_s.password != '':
                            form = FieldStorage(fp=request.content, headers=self.headers, environ={'REQUEST_METHOD': 'POST', 'CONTENT_TYPE': self.headers[b'content-type'], })
                            if 'username' in form and 'password' in form:
                                username = self.check_bytes(form['username'].value)
                                password = self.check_bytes(form['password'].value)
                                status = 'failed'
                                if username == _q_s.username and password == _q_s.password:
                                    username = _q_s.username
                                    password = _q_s.password
                                    status = 'success'
                                _q_s.logs.info({'server': 'http_server', 'action': 'login', 'status': status, 'src_ip': client_ip, 'src_port': request.getClientAddress().port, 'username': username, 'password': password, 'dest_ip': _q_s.ip, 'dest_port': _q_s.port})

                    request.responseHeaders.addRawHeader('Content-Type', 'text/html; charset=utf-8')
                    if status == 'failed':
                        return self.login_file
                    return self.home_file
                else:
                    request.responseHeaders.addRawHeader('Content-Type', 'text/html; charset=utf-8')
                    return self.home_file

        print('Listening on port', self.port)
        reactor.listenTCP(self.port, Site(MainResource()))
        print('reactor.run()')
        reactor.run()

    def run_server(self, process=False, auto=False):
        status = 'error'
        run = False
        if process:
            if auto and not self.auto_disabled:
                port = get_free_port()
                print('port', port)
                if port > 0:
                    self.port = port
                    run = True
            elif self.close_port() and self.kill_server():
                run = True

            if run:
                print('run')
                self.process = Popen(['python3', path.realpath(__file__), '--custom', '--ip', str(self.ip), '--port', str(self.port), '--username', str(self.username), '--password', str(self.password), '--options', str(self.options), '--config', str(self.config), '--uuid', str(self.uuid)])
                print('self.process.poll()', self.process.poll())
                print('self.uuid', self.uuid)
                if self.process.poll() is None and check_if_server_is_running(self.uuid):
                    print('check_if_server_is_running')
                    status = 'success'

            self.logs.info({'server': 'http_server', 'action': 'process', 'status': status, 'src_ip': self.ip, 'src_port': self.port, 'username': self.username, 'password': self.password, 'dest_ip': self.ip, 'dest_port': self.port})

            if status == 'success':
                return True
            else:
                self.kill_server()
                return False
        else:
            self.http_server_main()

    def close_port(self):
        ret = close_port_wrapper('http_server', self.ip, self.port, self.logs)
        return ret

    def kill_server(self):
        ret = kill_server_wrapper('http_server', self.uuid, self.process)
        return ret

if __name__ == '__main__':
    parsed = server_arguments()

    if parsed.custom:
        qhttpserver = QHTTPServer(ip=parsed.ip, port=parsed.port, username=parsed.username, password=parsed.password, options=parsed.options, config=parsed.config)
        qhttpserver.run_server()
        # qhttpserver.http_server_main()
    else:
        qhttpserver = QHTTPServer()
        qhttpserver.http_server_main()
