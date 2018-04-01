"""
Author : Ian O'Connell
Student No. : B00080570
"""
import datetime                                 # Import datetime module for epoch time
import webbrowser                               # Imports firefox open tab
import os                                       # Imports the real file path for saving and reading files
from collections import Counter                 # Imports Counter for lists
import matplotlib                               # Imports Libraries for graphs
import matplotlib.pyplot as plt                 # Shortens the matplotlib library call

"""These are the lists used to gather the data from the log"""
parsed_log = []                # Parsed Bro Log with converted time
source_ip_list = []            # Source IP List
source_port_list = []          # Source Port List
destination_ip_list = []       # Destination IP List
destination_port_list = []     # Destination Port List
service_list = []              # Services List
protocol_list = []             # Protocols List
history_list = []              # History of Connections List


"""
This method reads in the http.log
"""


def read_file(file_name):

    f = open(file_name, 'r')        # Opens http.log
    start_line = f.readlines()      # Reads in first line

    for i in start_line[8:]:        # Loops through the file but starts at line 9 to gather data
        if "#close" in i:           # If the line contains "#close" the parser stops
            pass                    # Parser stops
        else:
            convert = datetime.datetime.fromtimestamp(float(i[:17]))    # The first 18 characters of time are converted
            new_line = str(convert) + " " + i[17:]                      # The float is converted to a string
            parsed_log.append(new_line)                                 # The new line is appened to the parsed log

            # All the fields from the http.log are mapped to a variable in this tuple
            time, uid, orig_h, orig_p, resp_h, resp_p, proto, service,	duration, orig_bytes, resp_bytes, conn_state, \
            local_orig,	missed_bytes, history, orig_pkts, orig_ip_bytes, resp_pkts, resp_ip_bytes,tunnel_parents = \
                tuple(map(str, new_line.split("\t")))       # Bro logs are spaced using tabs to separate each field

            source_ip_list.append(orig_h)
            source_port_list.append(orig_p)
            destination_ip_list.append(resp_h)
            destination_port_list.append(resp_p)
            service_list.append(service)
            protocol_list.append(proto)
            history_list.append(history)


"""
This method displays the destination ip in a graph
"""


def show_destination_ip():

    small_size = 8
    matplotlib.rc('font', size=small_size)

    s = Counter(destination_ip_list)    # Counts the top IP's in the log file
    sDict = dict(s)                     # Converts them to a dictionary
    xVals = []                          # X Value list is declared
    yVals = []                          # Y Value list is declared
    count = 0                           # Loop count is set to zero

    for key, value in sorted(sDict.iteritems(), key=lambda (k, v): (v, k)):   # Sorts values into X & Y
        count += 1                          # Count is incremented by one
        if count > len(sDict)-10:           # If the count is greater than 10 append the first 10 x & y values
            xVals.append(key)               # The x value gets added
            yVals.append(value)             # The y value gets added

    plt.bar(xVals, yVals, color="orange")                   # The figure is plotted
    plt.suptitle('Top Destination IPs', fontsize=14, fontweight='bold')      # Title is set
    plt.xlabel('IPs', fontsize=10, fontweight='bold')                           # X axis titles
    plt.ylabel('Total', fontsize=10, fontweight='bold')                         # Y axis titles
    dportfig = plt.gcf()                                                        # Figure is formatted
    dportfig.set_size_inches(12, 5)                                             # Figure is sized
    dportfig.savefig(os.path.join('conn/')+"conn_destip.png")                   # Figure is saved
    plt.close()                                                                 # Graph is closed


"""
This method displays the services in a graph
"""


def show_services():

    small_size = 10
    matplotlib.rc('font', size=small_size)

    s = Counter(service_list)    # Counts the top IP's in the log file
    sDict = dict(s)                     # Converts them to a dictionary
    xVals = []                          # X Value list is declared
    yVals = []                          # Y Value list is declared
    count = 0                           # Loop count is set to zero

    for key, value in sorted(sDict.iteritems(), key=lambda (k, v): (v, k)):   # Sorts values into X & Y
        count += 1                          # Count is incremented by one
        if count > len(sDict)-10:           # If the count is greater than 10 append the first 10 x & y values
            xVals.append(key)               # The x value gets added
            yVals.append(value)             # The y value gets added

    plt.bar(xVals, yVals, color="purple")                                       # The figure is plotted
    plt.suptitle('Top Services', fontsize=14, fontweight='bold')                # Title is set
    plt.xlabel('Services', fontsize=10, fontweight='bold')                      # X axis titles
    plt.ylabel('Total', fontsize=10, fontweight='bold')                         # Y axis titles
    dportfig = plt.gcf()                                                        # Figure is formatted
    dportfig.set_size_inches(12, 5)                                             # Figure is sized
    dportfig.savefig(os.path.join('conn/')+"conn_services.png")                 # Figure is saved
    plt.close()                                                                 # Graph is closed


"""
This method displays the protocols in a graph
"""


def show_protocols():

    small_size = 10
    matplotlib.rc('font', size=small_size)

    s = Counter(protocol_list)    # Counts the top IP's in the log file
    sDict = dict(s)                     # Converts them to a dictionary
    xVals = []                          # X Value list is declared
    yVals = []                          # Y Value list is declared
    count = 0                           # Loop count is set to zero

    for key, value in sorted(sDict.iteritems(), key=lambda (k, v): (v, k)):   # Sorts values into X & Y
        count += 1                          # Count is incremented by one
        if count > len(sDict)-10:           # If the count is greater than 10 append the first 10 x & y values
            xVals.append(key)               # The x value gets added
            yVals.append(value)             # The y value gets added

    plt.bar(xVals, yVals, color="green")                                       # The figure is plotted
    plt.suptitle('Top Protocols', fontsize=14, fontweight='bold')                # Title is set
    plt.xlabel('protocols', fontsize=10, fontweight='bold')                      # X axis titles
    plt.ylabel('Total', fontsize=10, fontweight='bold')                         # Y axis titles
    dportfig = plt.gcf()                                                        # Figure is formatted
    dportfig.set_size_inches(12, 5)                                             # Figure is sized
    dportfig.savefig(os.path.join('conn/')+"conn_protocols.png")                 # Figure is saved
    plt.close()                                                                 # Graph is closed


    """
This method displays the destination ip in a graph
"""


def show_history():

    small_size = 8
    matplotlib.rc('font', size=small_size)

    s = Counter(history_list)           # Counts the top IP's in the log file
    sDict = dict(s)                     # Converts them to a dictionary
    xVals = []                          # X Value list is declared
    yVals = []                          # Y Value list is declared
    count = 0                           # Loop count is set to zero

    for key, value in sorted(sDict.iteritems(), key=lambda (k, v): (v, k)):   # Sorts values into X & Y
        count += 1                          # Count is incremented by one
        if count > len(sDict)-10:           # If the count is greater than 10 append the first 10 x & y values
            xVals.append(key)               # The x value gets added
            yVals.append(value)             # The y value gets added

    plt.bar(xVals, yVals, color="red")                                          # The figure is plotted
    plt.suptitle('History of Connections', fontsize=14, fontweight='bold')      # Title is set
    plt.xlabel('Connections', fontsize=10, fontweight='bold')                   # X axis titles
    plt.ylabel('Total', fontsize=10, fontweight='bold')                         # Y axis titles
    dportfig = plt.gcf()                                                        # Figure is formatted
    dportfig.set_size_inches(12, 5)                                             # Figure is sized
    dportfig.savefig(os.path.join('conn/')+"conn_history.png")                  # Figure is saved
    plt.close()                                                                 # Graph is closed


"""
This method opens up the template report
"""


def generate_html_report():

    webbrowser.open_new_tab("conn_bro_log.html")      # Uses web browser library to open report


"""
Main method this calls other methods needed for gathering data from the log file
"""


def main():

    show_destination_ip()
    show_services()
    show_protocols()
    show_history()
    generate_html_report()


if __name__ == '__main__':
    main()                  # Main method is called
