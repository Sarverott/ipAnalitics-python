#!/usr/bin/env python3

from http.server import BaseHTTPRequestHandler, HTTPServer
import time
from urllib.parse import urlparse, unquote
import pymysql
import sys
import json

config_file_read=open("config.json","r")
config_file_content=config_file_read.read()
config_json=json.loads(config_file_content)


def ipanalitics_machine(self, method):
    log_report(":::: ipAnalitics machine ::::", "reverse")
    parsed_path = urlparse(self.path)
    post_data = query_decoder(parsed_path.query)
    user = ""
    password = ""
    ip = ""
    log_report(":::: query sort ::::", "reverse")
    for a in post_data:
        log_report(a[0] + " : " + a[1], "green")
        if a[0] == 'host':
            user = a[1]
        elif a[0] == 'pass':
            password = a[1]
        elif a[0] == 'ip':
            ip = a[1]
        else:
            fake_responde(self)
            return
    log_report(":::: data verify ::::", "reverse")
    if (self.headers['Content-Length']) is not None:
        if login(user, password, ip, (self.address_string()), (self.command + ":" + self.path), self.rfile.read(int(self.headers['Content-Length'])).decode('utf-8')):
        #    if False:
            self.send_response(200)
            self.send_header("Content-type", "text/html;charset=UTF-8")
            self.end_headers()
            self.wfile.write("OK".encode("utf-8"))
            log_report(":::: response ::::", "reverse")
        else:
            fake_responde(self)
    else:
        if login(user, password, ip, (self.address_string()), (self.command + ":" + self.path), ""):
        #    if False:
            self.send_response(200)
            self.send_header("Content-type", "text/html;charset=UTF-8")
            self.end_headers()
            self.wfile.write("OK".encode("utf-8"))
            log_report(":::: response ::::", "reverse")
        else:
            fake_responde(self)


def fake_responde(self):
    self.server_version = "Apache/1.1.3 (win98)"
    self.sys_version = "Windows 98 (Memphis v4.1) - OSR2"
    log_report("  ## fake respond ##", "red")
    log_report("\n  ip:" + (self.address_string()) + "\n", "red")
    self.send_response(404)
    self.send_header("Content-type", "text/html;charset=ASCII")
    self.send_header("Last-modified", time.strftime("%a, %d %b %Y %H:%M:%S UTC", time.gmtime(0)))
    self.send_header("Date", time.strftime("%a, %d %b %Y %H:%M:%S UTC", time.gmtime(0)))
    self.end_headers()
    self.wfile.write("<h1>404 - not found</h1>".encode("utf-8"))


def connect_db(sql):
    log_report("  ## connecting database ##", "cyan")
    connection = pymysql.connect(user=config_json['database']['user'], password=config_json['database']['password'], host=config_json['database']['ip'], database=config_json['database']['database'])
    cursor = connection.cursor()
    cursor.execute(sql)
    ret = cursor
    # log_report("    <CONNECT_DB> - cursor:" + str(ret.__dict__), "cyan")
    # log_report("    <CONNECT_DB> - cursor['_result']:" + str(ret.__dict__['_result'].__dict__), "cyan")
    cursor.connection.commit()
    cursor.close()
    connection.close()
    return ret


def login(user, password, ip, curip, path, data):
    log_report("  ## login ##", "cyan")
    if user == "" or password == "" or ip == "":
        connect_db(error_raport("NO_DATA", curip, "", "", "", path, data))
        log_report("    <LOGIN> - False", "cyan")
        return False
    login_tulp = connect_db(login_form(user, password))
    log_report("    <LOGIN> - id_h captured", "cyan")
    id_check = []
    for id_h in login_tulp:
        id_check.append(id_h[0])
        log_report("    <LOGIN> - ::" + str(id_h[0]), "cyan")
    if len(id_check) == 1:
        print(str(id_check[0]))
        print(ip)
        connect_db(regist_form(str(id_check[0]), ip))
        connect_db(error_raport("IT_IS_OK", curip, "", "", "", path, data))
        return True
    else:
        connect_db(error_raport("WRONG_DATA", curip, user, password, ip, path, data))
        return False


def log_report(data, color=""):
    if color == "red":
        unicode_color = "\033[1;31m"
    elif color == "blue":
        unicode_color = "\033[1;34m"
    elif color == "cyan":
        unicode_color = "\033[1;36m"
    elif color == "green":
        unicode_color = "\033[1;32m"
    elif color == "bold":
        unicode_color = "\033[;1m"
    elif color == "reverse":
        unicode_color = "\033[;7m"
    else:
        unicode_color = ""
    print(unicode_color + data + "\033[0;0m")
    logs = open(config_json['base']['logsFile'], "a")
    logs.write('\n' + data)
    logs.close()


def error_raport(error, ip, user="", password="", ip_get="", path="", data=""):
    ret = "INSERT INTO error (host, error_text) VALUES ('"
    ret += ip

    if error == "WRONG_DATA":
        ret += "','::WRONG_DATA::(user:"
        ret += user
        ret += ", password:"
        ret += password
        ret += ", ip:"
        ret += ip_get
        ret += ") ::"
    elif error == "NO_DATA":
        ret += "', '::NO_DATA::"
    elif error == "PROTOCOL":
        ret += "', '::PROTOCOL::"
    elif error == "IT_IS_OK":
        ret += "', '::OK::"
    else:
        ret += "','::UNEXPECTED_ERROR::"
        log_report("    <SQL> - " + ret, "green")
    ret += " - command: " + path + " post: " + data + "');"
    return ret


def regist_form(id_host, ip):
    log_report("    <SQL> - INSERT INTO host_logi (hos_ID, ip) VALUES (" + id_host + ",'" + ip + "');", "green")
    return "INSERT INTO host_logi (hos_ID, ip) VALUES (" + id_host + ",'" + ip + "');"


def login_form(user, password):
    log_report("    <SQL> - SELECT id_h FROM hosty WHERE host_nazw='" + user + "' AND haslo='" + password + "';","green")
    return "SELECT id_h FROM hosty WHERE host_nazw='" + user + "' AND haslo='" + password + "';"


def query_decoder(string):
    log_report("    <QUERY> - BEGIN", "cyan")
    array = string.split("&")
    ret = []
    for a in array:
        mid_array = a.split("=")
        if len(mid_array) == 1:
            break
        else:
            mid_array[0] = unquote(mid_array[0])
            mid_array[1] = unquote(mid_array[1])
            ret.append(mid_array)
    log_report("    <QUERY> - END", "cyan")
    return ret


class ip_Analitics(BaseHTTPRequestHandler):
    def do_POST(self):
        log_report("     (" + self.address_string() + ")", "red")
        log_report("        :::: POST ::::", "blue")
        ipanalitics_machine(self, "POST")
        return

    def do_GET(self):
        log_report("        :::: GET ::::", "blue")
        ipanalitics_machine(self, "POST")
        return

    def do_HEAD(self):
        log_report("        :::: HEAD ::::", "blue")
        connect_db(error_raport("PROTOCOL", self.address_string(), "", "", "", self.command + ":" + self.path, self.rfile.read(int(self.headers['Content-Length'])).decode('utf-8')))
        fake_responde(self)
        return


def run_ia():
    handler = ip_Analitics
    httpd = HTTPServer(('', config_json['server']['port']), handler)
    try:
        log_report("    " + time.strftime("[%d-%m-%Y ; %X]", time.gmtime()) + " # Server START", "bold")
        httpd.serve_forever()
    except KeyboardInterrupt:
        log_report("#KEYBOARD INTERRUPT#", "red")
        log_report("    " + time.strftime("[%d-%m-%Y ; %X]", time.gmtime()) + " # Server STOP", "bold")
        httpd.socket.close()
        log_report("Exiting...\n", "red")
        exit()


log_report("begining IP Analitics (" + time.strftime("%d-%m-%Y, %X", time.gmtime()) + ")...", "green")
run_ia()
log_report("    " + time.strftime("[%d-%m-%Y ; %X]", time.gmtime()) + " # Server STOP")
log_report("Exiting...\n", "red")
exit()
