"""
Imported Libraries
"""
import datetime                                 #Import datetime module for epoch time
import webbrowser                               #Imports firefox open tab
import os                                       #Imports the real file path for saving and reading files
from collections import Counter                 #Imports Counter for lists
import matplotlib                               #Imports Libraries for graphs
import matplotlib.pyplot as plt                 #Shortens the matplotlib library call
import geoip2.database                          #Imports the database reader
import geoip2.errors                            #Imports the Error message
import pandas as pd                             #Imports the Pandas module for tables
from pandas.plotting._tools import table        #Imports
from mpl_toolkits.basemap import Basemap

"""These are the lists used to gather the data from the log"""
parsed_log = []                # Parsed Bro Log with converted time
source_ip_list = []            # Source IP List
source_port_list = []          # Source Port List
destination_ip_list = []       # Destination IP List
destination_port_list = []     # Destination Port List
url_list = []                  # List of all URLs in http.log
user_agent_list = []           # List of all User-Agents in http.log
countries_list = []            # List of all Countries from IPs


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
            time, uid, orig_h, orig_p, resp_h, resp_p, trans_depth, method, host, uri, referrer, user_agent, \
                request_body_len, response_body_len, status_code, status_msg, info_code, info_msg, filename, \
                tags, username, password, proxied, orig_fuids, orig_mime_types, resp_fuids, resp_mime_types = \
                tuple(map(str, new_line.split("\t")))       # Bro logs are spaced using tabs to separate each field

            source_ip_list.append(orig_h)                # The Source IP from the log file is added to the list
            source_port_list.append(orig_p)               # The Source Port from the log file is added to the list
            destination_ip_list.append(resp_h)                  # The Destination IP from the log file is added to the list
            destination_port_list.append(resp_p)                    # The Destination Port from the log file is added to the list
            url_list.append(host+uri)               # The host & Uri from the log file is added to the list
            user_agent_list.append(user_agent)      # The User-Agents from the log file is added to the list

"""
This method prints out the newly parsed & converted log
"""


def print_log():

    for i in parsed_log:
        print(i)

"""
This method displays the destination port in a graph
"""


def show_destination_port():

    s = Counter(source_port_list)       # Counts the top destination ports in the log file
    sDict = dict(s)                     # Converts them to a dictionary
    xVals = []                          # X Value list is declared
    yVals = []                          # Y Value list is declared
    count = 0                           # Loop count is set to zero
    for key, value in sorted(sDict.iteritems(), key=lambda (k, v): (v, k)):     # Sorts values into X & Y
        count += 1                          # Count is incremented by one
        if count > len(sDict)-10:           # If
            xVals.append(key)
            yVals.append(value)

    plt.bar(xVals, yVals, color='green')
    plt.suptitle('Top 10 Destination Ports', fontsize=14, fontweight='bold')
    plt.xlabel('Destination Ports', fontsize=10, fontweight='bold')
    plt.ylabel('Total', fontsize=10, fontweight='bold')
    dportfig = plt.gcf()
    dportfig.set_size_inches(10, 5)
    dportfig.savefig(os.path.join('http/')+"http_dport.png")
    plt.close()


def dport_table():

    data = Counter(destination_port_list)
    df = pd.DataFrame.from_dict(data, orient='index')

    ax = plt.subplot(111, frame_on=False)  # no visible frame
    ax.xaxis.set_visible(False)  # hide the x axis
    ax.yaxis.set_visible(False)  # hide the y axis
    table(ax, df, colWidths=[0.17]*len(df.columns), cellLoc='center', rowLoc='center', loc='center')  # where df is your data frame
    dt = plt.gcf()
    dt.set_size_inches(10, 4)
    plt.show()


def show_destip():

    small_size = 6
    matplotlib.rc('font', size=small_size)

    s = Counter(destination_ip_list)    # Counts the top IP's in the log file
    sDict = dict(s)
    xVals = []
    yVals = []
    count = 0

    for key, value in sorted(sDict.iteritems(),key=lambda (k,v): (v,k)):
        count += 1
        if count > len(sDict)-10:
            xVals.append(key)
            yVals.append(value)

    plt.bar(xVals, yVals)
    plt.suptitle('Top 10 Destination IPs', fontsize=14, fontweight='bold')
    plt.xlabel('IPs', fontsize=10, fontweight='bold')
    plt.ylabel('Total', fontsize=10, fontweight='bold')
    dportfig = plt.gcf()
    dportfig.set_size_inches(10, 5)
    dportfig.savefig(os.path.join('http/')+"http_destip.png")
    plt.close()


def destip_table():

    data = Counter(destination_ip_list)
    df = pd.DataFrame.from_dict(data, orient='index')
    df.rename(columns={-1: 'IP', 0: 'Total'}, inplace=True)

    ax = plt.subplot(111, frame_on=False)  # no visible
    ax.set_title('All Destination IPs', color='white', fontsize=14, fontweight='bold')
    ax.xaxis.set_visible(False)  # hide the x axis
    ax.yaxis.set_visible(False)  # hide the y axis
    table(ax, df, colWidths=[0.17]*len(df.columns), cellLoc='center', rowLoc='center', loc='center')  # where df is your data frame
    dt = plt.gcf()
    dt.set_facecolor('#8c8c8c')
    dt.set_size_inches(5, 5)
    dt.savefig(os.path.join('http/')+"http_table_destip.png", facecolor=dt.get_facecolor())
    plt.close()


def show_urls():

    small_size = 8
    matplotlib.rc('font', size=small_size)

    s = Counter(url_list)
    sDict = dict(s)
    xVals = []
    yVals = []
    count = 0
    for key, value in sorted(sDict.iteritems(), key=lambda (k, v): (v, k)):
        count+=1
        if count > len(sDict)-5:
            xVals.append(key)
            yVals.append(value)

    plt.barh(xVals, yVals, color='red')
    plt.suptitle('Top 5 Requested URLs', fontsize=14, fontweight='bold')
    plt.xlabel('URLs', fontsize=10, fontweight='bold')
    plt.ylabel('Total', fontsize=10, fontweight='bold')
    dportfig = plt.gcf()
    dportfig.set_size_inches(12, 8)
    dportfig.savefig(os.path.join('http/')+"http_urls.png")
    plt.close()


def show_user_agent():

    SMALL_SIZE = 6
    matplotlib.rc('font', size=SMALL_SIZE)

    s = Counter(user_agent_list)
    sDict = dict(s)
    xVals = []
    yVals = []
    count = 0
    for key, value in sorted(sDict.iteritems(),key=lambda (k, v): (v, k)):
        count+=1
        if count > len(sDict)-5:
            xVals.append(key)
            yVals.append(value)

    plt.barh(xVals, yVals)
    plt.suptitle('Top 5 User-Agents', fontsize=14, fontweight='bold')
    plt.xlabel('User-Agents', fontsize=10, fontweight='bold')
    plt.ylabel('Total', fontsize=10, fontweight='bold')
    dportfig = plt.gcf()
    dportfig.set_size_inches(12, 8)
    dportfig.savefig(os.path.join('http/')+"http_user_agents.png")
    plt.close()


def user_agent_table():

    data = Counter(user_agent_list)
    df = pd.DataFrame.from_dict(data, orient='index')
    df.rename(columns={-1: 'IP', 0: 'Total'}, inplace=True)

    ax = plt.subplot(111, frame_on=False)  # no visible
    ax.set_title('All User Agents', color='white', fontsize=14, fontweight='bold', loc='left')
    ax.xaxis.set_visible(False)  # hide the x axis
    ax.yaxis.set_visible(False)  # hide the y axis
    table(ax, df, colWidths=[0.17]*len(df.columns), cellLoc='center', rowLoc='right', loc='center')  # where df is your data frame
    dt = plt.gcf()
    dt.set_facecolor('#8c8c8c')
    dt.set_size_inches(10, 7)
    dt.savefig(os.path.join('http/')+"http_table_user_agent.png", facecolor=dt.get_facecolor())
    plt.close()


def show_country():

    GeoIPDatabase = 'db/GeoLite2-Country.mmdb'     #IP database file
    ipData = geoip2.database.Reader(GeoIPDatabase)

    for i in destination_ip_list:
        try:
            location = ipData.country(i)
            countries_list.append(location.country.name)

        except geoip2.errors.AddressNotFoundError:
            print("IP not in Database")
            pass

    SMALL_SIZE = 10
    matplotlib.rc('font', size=SMALL_SIZE)

    s = Counter(countries_list)
    sDict = dict(s)
    xVals = []
    yVals = []
    count = 0
    for key, value in sorted(sDict.iteritems(),key=lambda (k,v): (v,k)):
        count += 1
        if count > len(sDict)-10:
            xVals.append(key)
            yVals.append(value)

    plt.bar(xVals, yVals, color='purple')
    plt.suptitle('Top 5 Countries', fontsize=14, fontweight='bold')
    plt.xlabel('Countries', fontsize=12, fontweight='bold')
    plt.ylabel('Total', fontsize=12, fontweight='bold')
    dportfig = plt.gcf()
    dportfig.set_size_inches(10, 5)
    dportfig.savefig(os.path.join('http/')+"http_country.png")
    plt.close()


def map_country():

    m = Basemap()
    m.bluemarble()
    md = plt.gcf()
    md.set_size_inches(10, 8)
    md.savefig(os.path.join('http/')+"http_map_country.png")
    plt.close()


def table_country():

    data = Counter(countries_list)
    df = pd.DataFrame.from_dict(data, orient='index')
    df.rename(columns={0: 'Total'}, inplace=True)

    ax = plt.subplot(111, frame_on=False)  # no visible
    ax.set_title('All Countries', color='white', fontsize=14, fontweight='bold', loc='center')
    ax.xaxis.set_visible(False)  # hide the x axis
    ax.yaxis.set_visible(False)  # hide the y axis
    table(ax, df, colWidths=[0.17]*len(df.columns), cellLoc='center', rowLoc='right', loc='center')  # Where df is your data frame
    dt = plt.gcf()
    dt.set_facecolor('#8c8c8c')
    dt.set_size_inches(8, 6)
    dt.savefig(os.path.join('http/')+"http_table_countries.png", facecolor=dt.get_facecolor())
    plt.close()


def show_city():

    GeoIPDatabase = 'db/GeoLite2-City.mmdb'     #IP database file
    ipData = geoip2.database.Reader(GeoIPDatabase)
    cities = []

    for i in destination_ip_list:
        try:
            location = ipData.city(i)
            cities.append(unicode(location.city.name))
        except geoip2.errors.AddressNotFoundError:
            print("IP not in Database:" + i)

    small_size = 8
    matplotlib.rc('font', size=small_size)

    s = Counter(cities)
    sDict = dict(s)
    xVals = []
    yVals = []
    count = 0
    for key, value in sorted(sDict.iteritems(), key=lambda (k, v): (v, k)):
        count += 1
        if count > len(sDict)-10:
            xVals.append(key)
            yVals.append(value)

    plt.bar(xVals, yVals)
    plt.bar(xVals, yVals, color='orange')
    plt.suptitle('Top 10 Cities', fontsize=14, fontweight='bold')
    plt.xlabel('Cities', fontsize=10, fontweight='bold')
    plt.ylabel('Total', fontsize=10, fontweight='bold')
    dportfig = plt.gcf()
    dportfig.set_size_inches(12, 6)
    dportfig.savefig(os.path.join('http/')+"http_city.png")
    plt.close()


def map_cities():

    m = Basemap()
    m.bluemarble()

    GeoIPDatabase = 'db/GeoLite2-City.mmdb'     #IP database file
    ipData = geoip2.database.Reader(GeoIPDatabase)
    cities = []
    lat = []
    long = []

    for i in destination_ip_list:
        try:
            location = ipData.city(i)
            cities.append(unicode(location.city.name))
            lat.append(location.location.latitude)
            long.append(location.location.longitude)

        except geoip2.errors.AddressNotFoundError:
            print("IP not in Database:" + i)

    x, y = m(long, lat)
    m.plot(x, y, 'ro', markersize=12)

    for city, xpt, ypt in zip(cities, long, lat):
        plt.text(xpt, ypt, city)

    md = plt.gcf()
    md.set_size_inches(10, 8)
    md.savefig(os.path.join('http/')+"http_map_cities.png")
    plt.title('Top Attacking Cities Map')
    plt.close()


def generate_html_report():

    webbrowser.open_new_tab("Bro-Log-Report.html")


def main():
    read_file('http.log')
    destip_table()
    show_destination_port()
    show_destip()
    show_urls()
    show_user_agent()
    user_agent_table()
    show_country()
    table_country()
    show_city()
    generate_html_report()
    map_country()
    map_cities()

if __name__ == '__main__':
    main()
