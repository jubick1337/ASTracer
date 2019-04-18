import pprint
import sys

from others import run_process, get_ip, make_request, gray, parse_response, mutate_dictionary, filter_dictionary


def main():
    if len(sys.argv) != 2:
        print('usage: asTracer [ip/host]')
        print()
        print('Author Matvey Novikov')
        return
    else:
        res = {}
        servers = ["whois.arin.net", "whois.afrinic.net", "whois.apnic.net", "whois.lacnic.net", "whois.ripe.net"]
        print('Started: ' + '\n')
        for line in run_process('tracert -d ' + sys.argv[1]):
            ip = get_ip(line)
            if ip != 'No ip':
                print('\tworking with: ' + ip, end='\r')
                res[ip] = []
                for server in servers:
                    res[ip].append(parse_response(make_request(ip, server), server))
        print('Done: ')
        pprint.pprint(gray(filter_dictionary(mutate_dictionary(res))))


if __name__ == '__main__':
    main()
