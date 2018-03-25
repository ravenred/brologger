"""
Imported Libirary 
"""
import datetime
import requests
import webbrowser
import os
from collections import Counter
import matplotlib
import matplotlib.pyplot as plt
import pylab
import geoip2.database

parsed_log = []
ip_list = []


def read_file(file):

    f = open(file, 'r')
    start_line = f.readlines()

    for i in start_line[8:]:
        if "#close" in i:
            pass
        else:
            convert = datetime.datetime.fromtimestamp(float(i[:17]))
            new_line = str(convert) + " " + i[17:]
            parsed_log.append(new_line)
            #print(new_line)

            time, uid, id_orig_h, id_orig_p, id_resp_h, id_resp_p, proto, trans_id, \
            query, qclass, qclass_name, qtype, qtype_name,rcode, rcode_name, AA, TC, RD, RA, Z,\
            answers, TTLs, rejected = \
                tuple(map(str, new_line.split("\t")))

            print(answers.split(','))
            print(query)
            ip_list.append(query)


def query_md5():

    url = 'https://www.virustotal.com/vtapi/v2/domain/report'

    for i in ip_list:
        params = {'apikey': 'c85bf7d2a48c392a1b39175ec50ecde00dba85b542c70574388e176c5ca67adb', 'ip': i}
        response = requests.get(url, params=params)
        print(response.json())

read_file('0b08c5785b3c01c2113b6e8a4bf6738d_20120817/dns.log')
#query_md5()
