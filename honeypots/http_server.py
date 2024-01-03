# from warnings import filterwarnings
# filterwarnings(action='ignore', module='.*OpenSSL.*')

from cgi import FieldStorage
from requests.packages.urllib3 import disable_warnings
from twisted.internet import reactor
from twisted.web.server import Site
from twisted.web.resource import Resource
from twisted.python import log as tlog
from twisted.web.http import Request
from random import choice
from utils import server_arguments, setup_logger, disable_logger, set_local_vars
from uuid import uuid4

disable_warnings()

class HoneyHTTP():
    def __init__(self, **kwargs):
        self.mocking_server = choice(['Apache', 'nginx', 'Microsoft-IIS/7.5', 'Microsoft-HTTPAPI/2.0', 
                                      'Apache/2.2.15', 'SmartXFilter', 'Microsoft-IIS/8.5', 'Apache/2.4.6', 
                                      'Apache-Coyote/1.1', 'Microsoft-IIS/7.0', 'Apache/2.4.18', 'AkamaiGHost', 
                                      'Apache/2.2.25', 'Microsoft-IIS/10.0', 'Apache/2.2.3', 'nginx/1.12.1', 
                                      'Apache/2.4.29', 'cloudflare', 'Apache/2.2.22'])  # 随机选择一个 mocking server

        self.uuid = __class__.__name__ + '_' + str(uuid4())[:8]  # 生成一个 uuid

        self.config = kwargs.get('config', '')

        if self.config:
            self.logs = setup_logger(__class__.__name__, self.uuid, self.config)
            set_local_vars(self, self.config)
        else:
            self.logs = setup_logger(__class__.__name__, self.uuid, None)
        
        self.ip = kwargs.get('ip', None) or (hasattr(self, 'ip') and self.ip) or '127.0.0.1'    
        self.port = (kwargs.get('port', None) and int(kwargs.get('port', None))) or (hasattr(self, 'port') and self.port) or 80  
        self.username = kwargs.get('username', None) or (hasattr(self, 'username') and self.username) or 'honeypot'  
        self.password = kwargs.get('password', None) or (hasattr(self, 'password') and self.password) or 'honeypot'  

        print(f'ip: {self.ip}; port: {self.port}; username: {self.username}; password: {self.password}')
        
        disable_logger(True, tlog)    

    def http_server(self):
        my_server = self 

        class MainResource(Resource):
            isLeaf = True
            # 陷阱页面
            trap_page = b'''
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
            # 登录页面
            login_page = b'''      
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

            def normalize(self, string):  # 检查是否是 bytes 类型
                if isinstance(string, bytes):
                    return string.decode()
                else:
                    return str(string)

            def render(self, request):
                """
                Renders the HTTP request and returns the appropriate response.

                Args:
                    request (twisted.web.http.Request): The HTTP request object.

                Returns:
                    str: The response content.
                """
                headers = {}
                client_ip = ""

                def normalize(string):
                    if isinstance(string, bytes):
                        return string.decode()
                    else:
                        return str(string)
                
                # 获取请求头
                for item, value in dict(request.requestHeaders.getAllRawHeaders()).items():
                    # 使用 ',' 将 value 连接起来
                    value = ','.join(map(normalize, value))
                    # 将 item 和 value 添加到 headers 中
                    headers.update({normalize(item): value})
                # 获取请求方法和请求 uri
                headers.update({'method': normalize(request.method)})
                headers.update({'uri': normalize(request.uri)})

                """
                获取客户端 ip:
                    检查是否有 X-Forwarded-For 或 X-Real-IP 请求头
                    这两个字段通常用于存储客户端的真实 ip, 特别是在使用反向代理的情况下
                """
                raw_headers = dict(request.requestHeaders.getAllRawHeaders())
                if b'X-Forwarded-For' in raw_headers:
                    client_ip = normalize(raw_headers[b'X-Forwarded-For'][0])
                elif b'X-Real-IP' in raw_headers:
                    client_ip = normalize(raw_headers[b'X-Real-IP'][0])
                else:
                    client_ip = request.getClientAddress().host

                my_server.logs.info({'server': 'http', 'action': 'connection', 'attack_ip': client_ip, 'attack_port': request.getClientAddress().port, 'server_ip': my_server.ip, 'server_port': my_server.port, 'data': headers})

                if my_server.mocking_server != '':
                    request.responseHeaders.removeHeader('Server')
                    request.responseHeaders.addRawHeader('Server', my_server.mocking_server)

                if request.method == b'GET' or request.method == b'POST':
                    my_server.logs.info({'server': 'http', 'action': request.method.decode(), 'attack_ip': client_ip, 'attack_port': request.getClientAddress().port, 'server_ip': my_server.ip, 'server_port': my_server.port})

                if request.method == b'GET':
                    if request.uri == b'/login.html':
                        if my_server.username != '' and my_server.password != '':
                            request.responseHeaders.addRawHeader('Content-Type', 'text/html; charset=utf-8')
                            return self.login_page

                    request.responseHeaders.addRawHeader('Content-Type', 'text/html; charset=utf-8')
                    return self.login_page

                elif request.method == b'POST':
                    self.headers = request.getAllHeaders()
                    if request.uri == b'/login.html' or b'/':
                        if my_server.username != '' and my_server.password != '':
                            form = FieldStorage(fp=request.content, headers=self.headers, environ={'REQUEST_METHOD': 'POST', 'CONTENT_TYPE': self.headers[b'content-type'], })
                            if 'username' in form and 'password' in form:
                                username = self.normalize(form['username'].value)
                                password = self.normalize(form['password'].value)
                                status = 'failed'
                                if username == my_server.username and password == my_server.password:
                                    username = my_server.username
                                    password = my_server.password
                                    status = 'success'
                                my_server.logs.info({'server': 'http', 'action': 'login', 'status': status, 'attacker_ip': client_ip, 'attacker_port': request.getClientAddress().port, 'attack_username': username, 'attack_password': password, 'server_ip': my_server.ip, 'server_port': my_server.port})

                    request.responseHeaders.addRawHeader('Content-Type', 'text/html; charset=utf-8')
                    if status == 'failed':
                        return self.login_page
                    return self.trap_page
                else:
                    request.responseHeaders.addRawHeader('Content-Type', 'text/html; charset=utf-8')
                    return self.trap_page

        try:
            reactor.listenTCP(self.port, Site(MainResource()))
            print(f'[*] HTTP server started on port {self.port}')
            reactor.run()
        except Exception as e:
            print(e)

if __name__ == '__main__':
    parsed = server_arguments()

    http_server = HoneyHTTP(ip=parsed.ip, port=parsed.port, username=parsed.username, password=parsed.password, config=parsed.config)
    http_server.http_server()
