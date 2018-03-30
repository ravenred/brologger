"""
Imported Libirary 
"""
import datetime
import credentials
import requests
import webbrowser
import os
from collections import Counter
import matplotlib
import matplotlib.pyplot as plt
import pylab
import geoip2.database

parsed_log = []
md5_list = []


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

            time, fuid, tx_hosts, rx_hosts,	conn_uids, source, depth, analyzers, mime_type, \
            filename, duration, local_orig, is_orig, seen_bytes, total_bytes, missing_bytes, \
            overflow_bytes,	timedout, parent_fuid, md5,	sha1, sha256, extracted = \
                tuple(map(str, new_line.split("\t")))

            print(filename + " : " + md5)
            md5_list.append(md5)


def query_md5():

    url = 'https://www.virustotal.com/vtapi/v2/file/behaviour'

    params = {'apikey': 'c85bf7d2a48c392a1b39175ec50ecde00dba85b542c70574388e176c5ca67adb', 'hash': '6b22bb92ad161ae6efa5ce2794258f8f'}

    response = requests.get(url, params=params)

    print(response)

read_file('0b08c5785b3c01c2113b6e8a4bf6738d_20120817/files.log')
#query_md5()
