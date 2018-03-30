import datetime                                 # Import datetime module for epoch time
import matplotlib                               # Imports Libraries for graphs
import matplotlib.pyplot as plt                 # Shortens the matplotlib library call
import os                                       # Imports the real file path for saving and reading files
import webbrowser                               # Imports firefox open tab
from collections import Counter                 # Imports Counter for lists

"""These are the lists used to gather the data from the log"""
parsed_log = []                     # Parsed Bro Log with converted time
weird_message_list = []             # Weird messages are stored in a list
destination_ip_list = []            # Destination IP List
destination_port_list = []          # Destination Port List

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
            time, uid, id_orig_h, id_orig_p, resp_h, \
            resp_p, name, addl, notice, peer = \
                tuple(map(str, new_line.split("\t")))       # Bro logs are spaced using tabs to separate each field

            weird_message_list.append(name)     # The name of messages from the log file is added to the list
            destination_ip_list.append(resp_h)      # The Destination IP from the log file is added to the list
            destination_port_list.append(resp_p)    # The Destination Port from the log file is added to the list


"""
This method displays all of the weird messages
"""


def show_weird_messages():

    s = Counter(weird_message_list)         # Counts the top notices ports in the log file
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
    dportfig.savefig(os.path.join('weird/')+"weird_messages.png")                  # Figure is saved
    plt.close()


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
    plt.suptitle('Top Notices', fontsize=14, fontweight='bold')      # Title is set
    plt.xlabel('IPs', fontsize=10, fontweight='bold')                           # X axis titles
    plt.ylabel('Total', fontsize=10, fontweight='bold')                         # Y axis titles
    dportfig = plt.gcf()                                                        # Figure is formatted
    dportfig.set_size_inches(10, 5)                                             # Figure is sized
    dportfig.savefig(os.path.join('weird/')+"weird_destip.png")                 # Figure is saved
    plt.close()                                                                 # Graph is closed


"""
This method opens up the template report
"""


def generate_weird_report():

    webbrowser.open_new_tab("weird_bro_log.html")      # Uses web browser library to open report


"""
Main method this calls other methods needed for gathering data from the log file
"""


def main():

    show_destination_ip()
    show_destination_port()
    show_weird_messages()
    generate_weird_report()


if __name__ == '__main__':
    main()


