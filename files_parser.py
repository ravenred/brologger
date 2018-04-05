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


parsed_log = []
md5_list = []
file_type_list = []
source_ips_list = []


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

            md5_list.append(md5)
            file_type_list.append(mime_type)
            source_ips_list.append(tx_hosts)


def query_md5():

    url = 'https://www.virustotal.com/vtapi/v2/file/behaviour'

    params = {'apikey': 'c85bf7d2a48c392a1b39175ec50ecde00dba85b542c70574388e176c5ca67adb', 'hash': '6b22bb92ad161ae6efa5ce2794258f8f'}

    response = requests.get(url, params=params)

    print(response)


"""
This method displays the file types in a graph
"""


def show_file_types():

    small_size = 6
    matplotlib.rc('font', size=small_size)

    s = Counter(file_type_list)         # Counts the top file types in the log file
    sDict = dict(s)                     # Converts them to a dictionary
    xVals = []                          # X Value list is declared
    yVals = []                          # Y Value list is declared
    count = 0                           # Loop count is set to zero

    for key, value in sorted(sDict.iteritems(), key=lambda (k, v): (v, k)):   # Sorts values into X & Y
        count += 1                          # Count is incremented by one
        if count > len(sDict)-10:           # If the count is greater than 10 append the first 10 x & y values
            xVals.append(key)               # The x value gets added
            yVals.append(value)             # The y value gets added

    plt.barh(xVals, yVals, color='red')   # The figure is plotted
    plt.suptitle('Top File Types', fontsize=14, fontweight='bold')              # Title is set
    plt.xlabel('Type of File', fontsize=10, fontweight='bold')                  # X axis titles
    plt.ylabel('Total', fontsize=10, fontweight='bold')                         # Y axis titles
    dportfig = plt.gcf()                                                        # Figure is formatted
    dportfig.set_size_inches(12, 8)                                             # Figure is sized
    dportfig.savefig(os.path.join('files/')+"files_types.png")                  # Figure is saved
    plt.close()                                                                 # Graph is closed

"""
This method opens up the template report
"""


def generate_files_report():

    webbrowser.open_new_tab("files_bro_log.html")      # Uses web browser library to open report


"""
This method displays the source ip in a graph
"""


def show_source_ip():

    small_size = 6
    matplotlib.rc('font', size=small_size)

    s = Counter(source_ips_list)    # Counts the top IP's in the log file
    sDict = dict(s)                     # Converts them to a dictionary
    xVals = []                          # X Value list is declared
    yVals = []                          # Y Value list is declared
    count = 0                           # Loop count is set to zero

    for key, value in sorted(sDict.iteritems(), key=lambda (k, v): (v, k)):   # Sorts values into X & Y
        count += 1                          # Count is incremented by one
        if count > len(sDict)-10:           # If the count is greater than 10 append the first 10 x & y values
            xVals.append(key)               # The x value gets added
            yVals.append(value)             # The y value gets added

    plt.bar(xVals, yVals)                   # The figure is plotted
    plt.suptitle('Top Source IPs', fontsize=14, fontweight='bold')      # Title is set
    plt.xlabel('IPs', fontsize=10, fontweight='bold')                           # X axis titles
    plt.ylabel('Total', fontsize=10, fontweight='bold')                         # Y axis titles
    dportfig = plt.gcf()                                                        # Figure is formatted
    dportfig.set_size_inches(12, 5)                                             # Figure is sized
    dportfig.savefig(os.path.join('files/')+"files_sourceip.png")                   # Figure is saved
    plt.close()                                                                 # Graph is closed


"""
Main method this calls other methods needed for gathering data from the log file
"""


def main():
    #read_file('0ad9515239c4033d84936c2e6ba00ed1_20120624/files.log')
    show_file_types()
    show_source_ip()
    generate_files_report()


if __name__ == '__main__':

    main()
