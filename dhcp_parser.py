import datetime                                 # Import datetime module for epoch time
import matplotlib                               # Imports Libraries for graphs
import matplotlib.pyplot as plt                 # Shortens the matplotlib library call
import os                                       # Imports the real file path for saving and reading files
import webbrowser                               # Imports firefox open tab
import urllib2
import json
import codecs
from collections import Counter                 # Imports Counter for lists

"""These are the lists used to gather the data from the log"""
parsed_log = []                     # Parsed Bro Log with converted time
destination_ip_list = []            # Destination IP List
destination_port_list = []          # Destination Port List
mac_address_list = []               # MAC address List
vendor_list = []                    # Vendor List

"""
This method reads in the http.log
"""


def read_file(file_name):           # Start of read file

    f = open(file_name, 'r')        # Opens weird.log
    start_line = f.readlines()      # Reads in first line

    for i in start_line[8:]:        # Loops through the file but starts at line 9 to gather data
        if "#close" in i:           # If the line contains "#close" the parser stops
            pass                    # Parser stops
        else:
            convert = datetime.datetime.fromtimestamp(float(i[:17]))    # The first 18 characters of time are converted
            new_line = str(convert) + " " + i[17:]                      # The float is converted to a string
            parsed_log.append(new_line)                                 # The new line is appended to the parsed log

            # All the fields from the http.log are mapped to a variable in this tuple
            time, uid, orig_h, orig_p, resp_h, resp_p, \
                mac, assigned_ip, lease_time, trans_id = \
                tuple(map(str, new_line.split("\t")))       # Bro logs are spaced using tabs to separate each field

            destination_ip_list.append(resp_h)      # The Destination IP from the log file is added to the list
            destination_port_list.append(resp_p)    # The Destination Port from the log file is added to the list
            mac_address_list.append(mac)            # The MAC Address from the log file is added to the list


"""
This method displays the destination port in a graph
"""


def show_destination_port():

    s = Counter(destination_ip_list)        # Counts the top destination ports in the log file
    sDict = dict(s)                         # Converts them to a dictionary
    xVals = []                              # X Value list is declared
    yVals = []                              # Y Value list is declared
    count = 0                               # Loop count is set to zero

    for key, value in sorted(sDict.iteritems(), key=lambda (k, v): (v, k)):     # Sorts values into X & Y
        count += 1                          # Count is incremented by one
        if count > len(sDict)-10:           # If the count is greater than 10 append the first 10 x & y values
            xVals.append(key)               # The x value gets added
            yVals.append(value)             # The y value gets added

    plt.bar(xVals, yVals, color='green')    # The figure is plotted
    plt.suptitle('Top Destination Ports', fontsize=14, fontweight='bold')    # Title is set
    plt.xlabel('Destination Ports', fontsize=10, fontweight='bold')             # X axis titles
    plt.ylabel('Total', fontsize=10, fontweight='bold')                         # Y axis titles
    dportfig = plt.gcf()                                                        # Figure is formatted
    dportfig.set_size_inches(10, 5)                                             # Figure is sized
    dportfig.savefig(os.path.join('weird/')+"weird_dport.png")                  # Figure is saved
    plt.close()                                                                 # Graph is closed


"""
This method displays the destination ip in a graph
"""


def show_destination_ip():

    small_size = 6
    matplotlib.rc('font', size=small_size)

    s = Counter(destination_port_list)  # Counts the top IP's in the log file
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
    plt.suptitle('Top Destination IPs', fontsize=14, fontweight='bold')      # Title is set
    plt.xlabel('IPs', fontsize=10, fontweight='bold')                           # X axis titles
    plt.ylabel('Total', fontsize=10, fontweight='bold')                         # Y axis titles
    dportfig = plt.gcf()                                                        # Figure is formatted
    dportfig.set_size_inches(10, 5)                                             # Figure is sized
    dportfig.savefig(os.path.join('weird/')+"weird_destip.png")                 # Figure is saved
    plt.close()                                                                 # Graph is closed


"""
Mac address lookup function
"""


def find_mac_address():

    # API base url,you can also use https if you need
    url = "http://macvendors.co/api/"
    # Mac address to lookup vendor from
    # mac_address = "BC:92:6B:A0:00:01"

    for mac_address in mac_address_list:

        request = urllib2.Request(url+mac_address, headers={'User-Agent' : "API Browser"})
        response = urllib2.urlopen(request)
        # Fix: json object must be str, not 'bytes'
        reader = codecs.getreader("utf-8")
        obj = json.load(reader(response))

        # Print company name
        print (obj['result']['company'])

        # Results are formatted to be stored
        results = (obj['result']['company'])
        vendor_list.append(results)


"""
This method displays the destination ip in a graph
"""


def show_vendor():

    small_size = 6
    matplotlib.rc('font', size=small_size)

    s = Counter(vendor_list)            # Counts the top vendor address in the log file
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
    plt.suptitle('Top Mac Vendors', fontsize=14, fontweight='bold')      # Title is set
    plt.xlabel('Vendors', fontsize=10, fontweight='bold')                           # X axis titles
    plt.ylabel('Total', fontsize=10, fontweight='bold')                         # Y axis titles
    dportfig = plt.gcf()                                                        # Figure is formatted
    dportfig.set_size_inches(10, 5)                                             # Figure is sized
    dportfig.savefig(os.path.join('dhcp/')+"dhcp_vendors.png")                 # Figure is saved
    plt.close()                                                                 # Graph is closed


"""
This method displays the mac addresses in a graph
"""


def show_mac_addresses():

    small_size = 6
    matplotlib.rc('font', size=small_size)

    s = Counter(mac_address_list)       # Counts the top vendor address in the log file
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
    plt.suptitle('Top Mac Address', fontsize=14, fontweight='bold')      # Title is set
    plt.xlabel('Address', fontsize=10, fontweight='bold')                           # X axis titles
    plt.ylabel('Total', fontsize=10, fontweight='bold')                         # Y axis titles
    dportfig = plt.gcf()                                                        # Figure is formatted
    dportfig.set_size_inches(10, 5)                                             # Figure is sized
    dportfig.savefig(os.path.join('dhcp/')+"dhcp_address.png")                 # Figure is saved
    plt.close()                                                                 # Graph is closed


"""
This method opens up the template report
"""


def generate_weird_report():

    webbrowser.open_new_tab("dhcp_bro_log.html")      # Uses web browser library to open report


"""
Main method this calls other methods needed for gathering data from the log file
"""


def main():

    #read_file('0ad9515239c4033d84936c2e6ba00ed1_20120624\dhcp.log')
    show_destination_ip()
    show_destination_port()
    find_mac_address()
    show_vendor()
    show_mac_addresses()
    generate_weird_report()


if __name__ == '__main__':
    main()


