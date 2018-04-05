"""
Author : Ian O'Connell
Student No. : B00080570
"""
import datetime
import requests
import webbrowser
import os
from collections import Counter
import matplotlib
import matplotlib.pyplot as plt
import credentials

parsed_log = []
ip_list = []
query_list = []


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
            query, qclass, qclass_name, qtype, qtype_name, rcode, rcode_name, AA, TC, RD, RA, Z,\
            answers, TTLs, rejected = \
                tuple(map(str, new_line.split("\t")))

            ip_list.append(id_resp_h)
            query_list.append(query)

"""
Query the ip list for 
"""


def query_md5():

    url = 'https://www.virustotal.com/vtapi/v2/domain/report'

    for i in ip_list:
        params = {'apikey': credentials.apikey, 'ip': i}
        try:
            response = requests.get(url, params=params)
            print(unicode(response.json()))
        except requests.DependencyWarning:
            pass


def show_queries():

    small_size = 8
    matplotlib.rc('font', size=small_size)

    s = Counter(query_list)         # Counts the top IP's in the log file
    sDict = dict(s)                 # Converts them to a dictionary
    xVals = []                      # X Value list is declared
    yVals = []                      # Y Value list is declared
    count = 0                       # Loop count is set to zero
    for key, value in sorted(sDict.iteritems(), key=lambda (k, v): (v, k)):     # Sorts values into X & Y
        count += 1                      # Count is incremented by one
        if count > len(sDict)-5:        # If the count is greater than 10 append the first 10 x & y values
            xVals.append(key)           # The x value gets added
            yVals.append(value)         # The y value gets added

    plt.barh(xVals, yVals, color='purple')                                         # The figure is plotted
    plt.suptitle('Top Requested Queries', fontsize=14, fontweight='bold')       # Title is set
    plt.xlabel('Queries', fontsize=10, fontweight='bold')                       # X axis titles
    plt.ylabel('Total', fontsize=10, fontweight='bold')                         # Y axis titles
    dportfig = plt.gcf()                                                        # Figure is formatted
    dportfig.set_size_inches(12, 8)                                             # Figure is sized
    dportfig.savefig(os.path.join('dns/')+"dns_queries.png")                    # Figure is saved
    plt.close()                                                                 # Graph is closed


"""
This method opens up the template report
"""


def generate_html_report():

    webbrowser.open_new_tab("dns_bro_log.html")      # Uses web browser library to open report


"""
Main method this calls other methods needed for gathering data from the log file
"""


def main():
    #query_md5()
    show_queries()
    generate_html_report()


if __name__ == '__main__':
    main()
