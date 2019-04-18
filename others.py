import re
import socket
import subprocess
import time


def run_process(process):
    p = subprocess.Popen(process, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    line = p.stdout.readline()
    while line != b'\x92\xe0\xa0\xe1\xe1\xa8\xe0\xae\xa2\xaa\xa0 \xa7\xa0\xa2\xa5\xe0\xe8\xa5\xad\xa0.\r\n':
        line = p.stdout.readline()
        yield line


def get_ip(line):
    lines = line.decode('cp866').split(' ')
    r = re.compile(
        r"^([1][0-9][0-9].|^[2][5][0-5].|^[2][0-4][0-9].|^[1][0-9][0-9].|^[0-9][0-9].|^[0-9].)([1][0-9][0-9].|[2][5][0-5].|[2][0-4][0-9].|[1][0-9][0-9].|[0-9][0-9].|[0-9].)([1][0-9][0-9].|[2][5][0-5].|[2][0-4][0-9].|[1][0-9][0-9].|[0-9][0-9].|[0-9].)([1][0-9][0-9]|[2][5][0-5]|[2][0-4][0-9]|[1][0-9][0-9]|[0-9][0-9]|[0-9])$")
    lines = list(filter(r.match, lines))
    if len(list(filter(r.match, lines))) != 0:
        return lines[0]
    else:
        return 'No ip'


def make_request(ip, server):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((server, 43))
    if server == 'whois.arin.net':
        s.send(('n + ' + ip + '\r\n').encode('utf-8'))
    else:
        s.send((ip + '\n\n').encode('utf-8'))
    time.sleep(2)
    resp = s.recv(4096).decode('utf-8')
    s.close()
    return resp


def parse_response(response, server):
    res = []
    lines = list(filter(None, response.split('\n')))
    for line in lines:
        words = list(filter(None, line.split(' ')))
        if words[0].startswith(('OriginAS', 'origin', 'aut-num')) and len(words) > 1:
            res.append(words[1])
        if words[0].startswith(('Country', 'country')) and len(words) > 1:
            res.append(words[1])
        if words[0].startswith(('OrgName', 'netname')) and len(words) > 1:
            res.append(words[1])
    res.append('It was')
    res.append(server)
    return res


def mutate_dictionary(dic):
    delete_me = [k for k in dic if any(len(inner) != 5 for inner in dic[k])]
    for k in delete_me:
        dic[k] = [inner for inner in dic[k] if len(inner) == 5]
    return dic


def filter_dictionary(dic):
    delete_me = []
    for k in dic.keys():
        for i in dic[k]:
            if not i[2].startswith(('as', 'AS', 'As')):
                delete_me.append(i)
    for v in dic.values():
        for d in delete_me:
            if d in v:
                v.remove(d)
    return dic


def gray(dic):
    for k in dic.keys():
        if len(dic[k]) == 0:
            dic[k] = ('N\\a')
    return dic
