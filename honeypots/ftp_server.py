from warnings import filterwarnings
filterwarnings(action='ignore', module='.*OpenSSL.*')

from twisted.protocols.ftp import FTPAnonymousShell, FTPFactory, FTP, IFTPShell, GUEST_LOGGED_IN_PROCEED, AuthorizationError, USR_LOGGED_IN_PROCEED
from twisted.internet import reactor, defer
from twisted.cred.portal import Portal
from twisted.cred import portal, credentials
from twisted.cred.error import UnauthorizedLogin, UnauthorizedLogin, UnhandledCredentials
from twisted.cred.checkers import ICredentialsChecker
from zope.interface import implementer
from twisted.python import filepath
from twisted.python import log as tlog
from random import choice
from os import getenv
from utils import server_arguments, setup_logger, disable_logger, set_local_vars
from uuid import uuid4
from contextlib import suppress
from tempfile import TemporaryDirectory


class HoneyFTP():
    def __init__(self, **kwargs):
        self.mocking_server = choice(['ProFTPD 1.2.10', 'ProFTPD 1.3.4a', 'FileZilla ftp 0.9.43', 'Gene6 ftpd 3.10.0', 'FileZilla ftp 0.9.33', 'ProFTPD 1.2.8'])
        self.process = None
        # 生成唯一的标识符(uuid)，用于标识当前实例
        self.uuid = 'honeypotslogger' + '_' + __class__.__name__ + '_' + str(uuid4())[:8]
        self.config = kwargs.get('config', '')

        if self.config:
            self.logs = setup_logger(__class__.__name__, self.uuid, self.config)
            set_local_vars(self, self.config)
        else:
            self.logs = setup_logger(__class__.__name__, self.uuid, None)

        # 设置服务器的IP地址，连接端口，用户登录的用户名、密码等初始信息
        # self.ip = '192.168.43.170'
        self.ip = kwargs.get('ip', None) or (hasattr(self, 'ip') and self.ip) or '192.168.43.170'
        self.port = (kwargs.get('port', None) and int(kwargs.get('port', None))) or (hasattr(self, 'port') and self.port) or 21
        self.username = kwargs.get('username', None) or (hasattr(self, 'username') and self.username) or 'ssn'
        self.password = kwargs.get('password', None) or (hasattr(self, 'password') and self.password) or 'nzh'
        # 如果需要过滤特定操作可以设置
        self.options = kwargs.get('options', '') or (hasattr(self, 'options') and self.options) or getenv('HONEYPOTS_OPTIONS', '') or ''
        self.temp_folder = TemporaryDirectory()

        print(f'ip: {self.ip}; port: {self.port}; username: {self.username}; password: {self.password}')

        disable_logger(1, tlog)

    def ftp_server_main(self):
        _q_s = self

        # 根据用户请求的接口类型返回相应的身份验证信息
        @implementer(portal.IRealm)
        class CustomFTPRealm:
            def __init__(self, anonymousRoot):
                self.anonymousRoot = filepath.FilePath(anonymousRoot)

            # 处理用户请求并返回相应的身份验证信息
            def requestAvatar(self, avatarId, mind, *interfaces):
                # 迭代列表检查每个接口是否与IFTPShell接口匹配
                for iface in interfaces:
                    if iface is IFTPShell:
                        avatar = FTPAnonymousShell(self.anonymousRoot)
                        return IFTPShell, avatar, getattr(avatar, 'logout', lambda: None)
                raise NotImplementedError("Only IFTPShell interface is supported by this realm")

        # 核实用户提供的用户名和密码
        @implementer(ICredentialsChecker)
        class CustomAccess:
            credentialInterfaces = (credentials.IAnonymous, credentials.IUsernamePassword)

            def check_bytes(self, string):
                if isinstance(string, bytes):
                    return string.decode()
                else:
                    return str(string)

            # 验证用户密码凭据并返回与凭据相关联的用户标识
            def requestAvatarId(self, credentials):
                with suppress(Exception):
                    username = self.check_bytes(credentials.username)
                    password = self.check_bytes(credentials.password)
                    if username == _q_s.username and password == _q_s.password:
                        username = _q_s.username
                        password = _q_s.password
                        return defer.succeed(credentials.username)
                return defer.fail(UnauthorizedLogin())

        class CustomFTPProtocol(FTP):

            def check_bytes(self, string):
                if isinstance(string, bytes):
                    return string.decode()
                else:
                    return str(string)

            # 记录连接的相关信息
            def connectionMade(self):
                # 记录连接信息
                _q_s.logs.info({'server': 'ftp_server', 'action': 'connection', 'src_ip': self.transport.getPeer().host, 'src_port': self.transport.getPeer().port, 'dest_ip': _q_s.ip, 'dest_port': _q_s.port})
                self.state = self.UNAUTH
                self.setTimeout(self.timeOut)
                self.reply("220.2", self.factory.welcomeMessage)

            # 处理客户端发送的命令请求
            def processCommand(self, cmd, *params):
                with suppress(Exception):
                    # 记录命令信息
                    # if "capture_commands" in _q_s.options:
                    _q_s.logs.info({'server': 'ftp_server', 'action': 'command', 'data': {"cmd": self.check_bytes(cmd.upper()), "args": self.check_bytes(params)}, 'src_ip': self.transport.getPeer().host, 'src_port': self.transport.getPeer().port, 'dest_ip': _q_s.ip, 'dest_port': _q_s.port})
                return super().processCommand(cmd, *params)

            # 处理用户提供密码进行登录的命令
            def ftp_PASS(self, password):
                username = self.check_bytes(self._user)
                password = self.check_bytes(password)
                status = 'failed'
                if username == _q_s.username and password == _q_s.password:
                    username = _q_s.username
                    password = _q_s.password
                    status = 'success'
                # 记录登录操作的信息，包括服务器名称、动作类型、登录状态、源IP地址、源端口、目标IP地址、目标端口、用户名和密码等。
                _q_s.logs.info({'server': 'ftp_server', 'action': 'login', 'status': status, 'src_ip': self.transport.getPeer().host, 'src_port': self.transport.getPeer().port, 'dest_ip': _q_s.ip, 'dest_port': _q_s.port, 'username': username, 'password': password})

                if self.factory.allowAnonymous and self._user == self.factory.userAnonymous:
                    creds = credentials.Anonymous()
                    reply = GUEST_LOGGED_IN_PROCEED
                else:
                    creds = credentials.UsernamePassword(self._user, password)
                    reply = USR_LOGGED_IN_PROCEED

                del self._user

                # 回调函数，处理成功的登录操作
                def _cbLogin(parsed):
                    self.shell = parsed[1]
                    self.logout = parsed[2]
                    self.workingDirectory = []
                    self.state = self.AUTHED
                    return reply

                # 回调函数，用于处理登录操作的失败情况
                def _ebLogin(failure):
                    failure.trap(UnauthorizedLogin, UnhandledCredentials)
                    self.state = self.UNAUTH
                    raise AuthorizationError

                d = self.portal.login(creds, None, IFTPShell)
                d.addCallbacks(_cbLogin, _ebLogin)
                return d

        p = Portal(CustomFTPRealm("data"), [CustomAccess()])
        factory = FTPFactory(p)
        # 指定使用的FTP协议
        factory.protocol = CustomFTPProtocol
        # 指定连接建立后发送给客户端的欢迎消息
        factory.welcomeMessage = "ProFTPD 1.2.10"
        # 监听指定的端口
        reactor.listenTCP(port=self.port, factory=factory)
        # 启动事件循环，开始监听客户端连接
        print(f'[*] FTP server running on {self.ip}:{self.port}')
        reactor.run()
        

if __name__ == '__main__':
    parsed = server_arguments()
    ftpserver = HoneyFTP(ip=parsed.ip, port=parsed.port, username=parsed.username, password=parsed.password, options=parsed.options, config=parsed.config)
    ftpserver.ftp_server_main()
