from logging.handlers import RotatingFileHandler
import sys

from warnings import filterwarnings
filterwarnings(action='ignore', module='.*requests.*')

from psutil import process_iter
from signal import SIGTERM
from argparse import ArgumentParser
from socket import socket, AF_INET, SOCK_STREAM
from json import JSONEncoder, dumps, load
from logging import Handler, DEBUG, getLogger
from sys import stdout
from datetime import datetime
from tempfile import _get_candidate_names, gettempdir
from os import makedirs, path, devnull
from collections.abc import Mapping

old_stderr = sys.stderr
sys.stderr = open(devnull, 'w')

class ComplexEncoder(JSONEncoder):
    def default(self, obj):
        return repr(obj).replace('\x00', ' ')

def set_local_vars(self, config):
    try:
        honeypot = None
        if config and config != '':
            with open(config) as f:
                config_data = load(f)
                honeypots = config_data['honeypots']
                honeypot = self.__class__.__name__[5:].lower()
            if honeypot and honeypot in honeypots:
                for var in honeypots[honeypot]:
                    setattr(self, var, honeypots[honeypot][var])
                    print(f'var: {var} - {honeypots[honeypot][var]}')
                    if var == 'port':
                        setattr(self, 'auto_disabled', True)
    except Exception as e:
        print('Error: {}'.format(repr(e)))

def parse_record(record, custom_filter, type_):
    timestamp = {'timestamp': datetime.utcnow().isoformat()}
    try:
        if custom_filter is not None:
            if 'remove_errors' in custom_filter['honeypots']['options']:
                if 'error' in record.msg:
                    return None
            if isinstance(record.msg, Mapping):
                if 'remove_init' in custom_filter['honeypots']['options']:
                    if record.msg.get('action', None) == 'process':
                        return None
                if 'remove_word_server' in custom_filter['honeypots']['options']:
                    if 'server' in record.msg:
                        record.msg['server'] = record.msg['server'].replace('_server', '')
                if 'honeypots' in custom_filter:
                    for key in record.msg.copy():
                        if key in custom_filter['honeypots']['change']:
                            record.msg[custom_filter['honeypots']['change'][key]] = record.msg.pop(key)
                    for key in record.msg.copy():
                        if key in custom_filter['honeypots']['remove']:
                            del record.msg[key]
                if custom_filter['honeypots']['contains']:
                    if not all(k in record.msg for k in custom_filter['honeypots']['contains']):
                        return None
        if isinstance(record.msg, Mapping):
            record.msg = serialize_object({**timestamp, **record.msg})
        else:
            record.msg = serialize_object(record.msg)
    except Exception as e:
        record.msg = serialize_object({'name': record.name, 'error': repr(e)})
    try:
        if type_ == 'file':
            if custom_filter is not None:
                if 'dump_json_to_file' in custom_filter['honeypots']['options']:
                    record.msg = dumps(record.msg, sort_keys=True, cls=ComplexEncoder)
        else:
            record.msg = dumps(record.msg, sort_keys=True, cls=ComplexEncoder)
    except Exception as e:
        record.msg = serialize_object({'name': record.name, 'error': repr(e)})

    return record

def disable_logger(logger_type, object):
    if logger_type == True:
        temp_name = path.join(gettempdir(), next(_get_candidate_names()))
        object.startLogging(open(temp_name, 'w'), setStdout=False)

def setup_logger(name, temp_name, config):
    logs = 'terminal'
    logs_location = ''
    syslog_address = ''
    syslog_facility = ''
    config_data = None
    custom_filter = None
    if config and config != '':
        try:
            with open(config) as f:
                config_data = load(f)
                logs = config_data.get('logs', logs)
                logs_location = config_data.get('logs_location', logs_location)
                syslog_address = config_data.get('syslog_address', syslog_address)
                syslog_facility = config_data.get('syslog_facility', syslog_facility)
                custom_filter = config_data.get('custom_filter', custom_filter)
                print('logs: {}'.format(logs))
                print('logs_location: {}'.format(logs_location))
                print('syslog_address: {}'.format(syslog_address))
                print('syslog_facility: {}'.format(syslog_facility))
                print('custom_filter: {}'.format(custom_filter))
        except Exception as e:
            print('Error: {}'.format(repr(e)))

    if logs_location == '' or logs_location is None:
        logs_location = path.join(gettempdir(), 'logs')

    if not path.exists(logs_location):
        makedirs(logs_location)

    file_handler = None
    ret_logs_obj = getLogger(temp_name)
    ret_logs_obj.setLevel(DEBUG)

    if 'terminal' in logs:
        ret_logs_obj.addHandler(CustomHandler(temp_name, logs, custom_filter))

    if 'file' in logs:
        max_bytes = 10000
        backup_count = 10
        try:
            if config_data is not None:
                if 'honeypots' in config_data:
                    temp_server_name = name[5:].lower()
                    print('temp_server_name: {}'.format(temp_server_name))
                    if temp_server_name in config_data['honeypots']:
                        if 'log_file_name' in config_data['honeypots'][temp_server_name]:
                            temp_name = config_data['honeypots'][temp_server_name]['log_file_name']

                        if 'max_bytes' in config_data['honeypots'][temp_server_name]:
                            max_bytes = config_data['honeypots'][temp_server_name]['max_bytes']

                        if 'backup_count' in config_data['honeypots'][temp_server_name]:
                            backup_count = config_data['honeypots'][temp_server_name]['backup_count']
        except Exception as e:
            print('Error: {}'.format(repr(e)))

        print('max_bytes: {}'.format(max_bytes))    
        file_handler = CustomHandlerFileRotate(temp_name, logs, custom_filter, path.join(logs_location, temp_name), maxBytes=max_bytes, backupCount=backup_count)
        ret_logs_obj.addHandler(file_handler)

    return ret_logs_obj

def serialize_object(_dict):
    if isinstance(_dict, Mapping):
        return dict((k, serialize_object(v)) for k, v in _dict.items())
    elif isinstance(_dict, list):
        return list(serialize_object(v) for v in _dict)
    elif isinstance(_dict, (int, float)):
        return str(_dict)
    elif isinstance(_dict, str):
        return _dict.replace('\x00', ' ')
    elif isinstance(_dict, bytes):
        return _dict.decode('utf-8', 'ignore').replace('\x00', ' ')
    else:
        return repr(_dict).replace('\x00', ' ')

class CustomHandlerFileRotate(RotatingFileHandler):
    def __init__(self, uuid='', logs='', custom_filter=None, filename='', mode='a', maxBytes=0, backupCount=0, encoding=None, delay=False, errors=None):
        self.logs = logs
        self.custom_filter = custom_filter
        RotatingFileHandler.__init__(self, filename, mode, maxBytes, backupCount, encoding, delay)

    def emit(self, record):
        _record = parse_record(record, self.custom_filter, 'file')
        if _record is not None:
            super().emit(_record)

class CustomHandler(Handler):
    def __init__(self, uuid='', logs='', custom_filter=None, config=None, drop=False):
        self.logs = logs
        self.uuid = uuid
        self.custom_filter = custom_filter
        Handler.__init__(self)

    def emit(self, record):
        try:
            if 'terminal' in self.logs:
                _record = parse_record(record, self.custom_filter, 'terminal')
                if _record:
                    stdout.write(_record.msg + '\n')
        except Exception as e:
            if self.custom_filter is not None:
                if 'honeypots' in self.custom_filter:
                    if 'remove_errors' in self.custom_filter['honeypots']['options']:
                        return None
            stdout.write(dumps({'error': repr(e), 'logger': repr(record)}, sort_keys=True, cls=ComplexEncoder) + '\n')
        stdout.flush()

def server_arguments():
    _server_parser = ArgumentParser(prog='Server')
    _server_parsergroupdeq = _server_parser.add_argument_group('Initialize Server')
    _server_parsergroupdeq.add_argument('--ip', type=str, help='Change server ip, current is 127.0.0.1', required=False, metavar='')
    _server_parsergroupdeq.add_argument('--port', type=int, help='Change port', required=False, metavar='')
    _server_parsergroupdeq.add_argument('--username', type=str, help='Change username', required=False, metavar='')
    _server_parsergroupdeq.add_argument('--password', type=str, help='Change password', required=False, metavar='')
    _server_parsergroupdef = _server_parser.add_argument_group('Initialize Loging')
    _server_parsergroupdef.add_argument('--config', type=str, help='config file for logs and database', required=False, default='')
    return _server_parser.parse_args()
