"""
Author : Ian O'Connell
Student No. : B00080570
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

            source_ip_list.append(orig_h)           # The Source IP from the log file is added to the list
            source_port_list.append(orig_p)         # The Source Port from the log file is added to the list
            destination_ip_list.append(resp_h)      # The Destination IP from the log file is added to the list
            destination_port_list.append(resp_p)    # The Destination Port from the log file is added to the list
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
        if count > len(sDict)-10:           # If the count is greater than 10 append the first 10 x & y values
            xVals.append(key)               # The x value gets added
            yVals.append(value)             # The y value gets added

    plt.bar(xVals, yVals, color='green')    # The figure is plotted
    plt.suptitle('Top 10 Destination Ports', fontsize=14, fontweight='bold')    # Title is set
    plt.xlabel('Destination Ports', fontsize=10, fontweight='bold')             # X axis titles
    plt.ylabel('Total', fontsize=10, fontweight='bold')                         # Y axis titles
    dportfig = plt.gcf()                                                        # Figure is formatted
    dportfig.set_size_inches(10, 5)                                             # Figure is sized
    dportfig.savefig(os.path.join('http/')+"http_dport.png")                    # Figure is saved
    plt.close()                                                                 # Graph is closed


def destination_port_table():

    data = Counter(destination_port_list)
    df = pd.DataFrame.from_dict(data, orient='index')

    ax = plt.subplot(111, frame_on=False)  # no visible frame
    ax.xaxis.set_visible(False)  # hide the x axis
    ax.yaxis.set_visible(False)  # hide the y axis

    # Where df is your data frame
    table(ax, df, colWidths=[0.17]*len(df.columns), cellLoc='center', rowLoc='center', loc='center')
    dt = plt.gcf()
    dt.set_size_inches(10, 4)
    plt.show()


"""
This method displays the destination ip in a graph
"""


def show_destination_ip():

    small_size = 6
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

    plt.bar(xVals, yVals)                   # The figure is plotted
    plt.suptitle('Top 10 Destination IPs', fontsize=14, fontweight='bold')      # Title is set
    plt.xlabel('IPs', fontsize=10, fontweight='bold')                           # X axis titles
    plt.ylabel('Total', fontsize=10, fontweight='bold')                         # Y axis titles
    dportfig = plt.gcf()                                                        # Figure is formatted
    dportfig.set_size_inches(10, 5)                                             # Figure is sized
    dportfig.savefig(os.path.join('http/')+"http_destip.png")                   # Figure is saved
    plt.close()                                                                 # Graph is closed


def destination_ip_table():

    data = Counter(destination_ip_list)
    df = pd.DataFrame.from_dict(data, orient='index')
    df.rename(columns={-1: 'IP', 0: 'Total'}, inplace=True)

    ax = plt.subplot(111, frame_on=False)           # no visible
    ax.set_title('All Destination IPs', color='white', fontsize=14, fontweight='bold')
    ax.xaxis.set_visible(False)                     # hide the x axis
    ax.yaxis.set_visible(False)                     # hide the y axis

    # Where df is your data frame
    table(ax, df, colWidths=[0.17]*len(df.columns), cellLoc='center', rowLoc='center', loc='center')
    dt = plt.gcf()
    dt.set_facecolor('#8c8c8c')
    dt.set_size_inches(5, 5)
    dt.savefig(os.path.join('http/')+"http_table_destip.png", facecolor=dt.get_facecolor())
    plt.close()


"""
This method displays the URLs in a graph
"""


def show_urls():

    small_size = 8
    matplotlib.rc('font', size=small_size)

    s = Counter(url_list)           # Counts the top IP's in the log file
    sDict = dict(s)                 # Converts them to a dictionary
    xVals = []                      # X Value list is declared
    yVals = []                      # Y Value list is declared
    count = 0                       # Loop count is set to zero
    for key, value in sorted(sDict.iteritems(), key=lambda (k, v): (v, k)):     # Sorts values into X & Y
        count += 1                      # Count is incremented by one
        if count > len(sDict)-5:        # If the count is greater than 10 append the first 10 x & y values
            xVals.append(key)           # The x value gets added
            yVals.append(value)         # The y value gets added

    plt.barh(xVals, yVals, color='red') # The figure is plotted
    plt.suptitle('Top 5 Requested URLs', fontsize=14, fontweight='bold')        # Title is set
    plt.xlabel('URLs', fontsize=10, fontweight='bold')                          # X axis titles
    plt.ylabel('Total', fontsize=10, fontweight='bold')                         # Y axis titles
    dportfig = plt.gcf()                                                        # Figure is formatted
    dportfig.set_size_inches(12, 8)                                             # Figure is sized
    dportfig.savefig(os.path.join('http/')+"http_urls.png")                     # Figure is saved
    plt.close()                                                                 # Graph is closed


"""
This method displays the User-Agents in a graph
"""


def show_user_agent():

    small_size = 6
    matplotlib.rc('font', size=small_size)

    s = Counter(user_agent_list)
    sDict = dict(s)
    xVals = []
    yVals = []
    count = 0
    for key, value in sorted(sDict.iteritems(),key=lambda (k, v): (v, k)):
        count += 1
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

    ax = plt.subplot(111, frame_on=False)   # no visible
    ax.set_title('All User Agents', color='white', fontsize=14, fontweight='bold', loc='left')
    ax.xaxis.set_visible(False)             # hide the x axis
    ax.yaxis.set_visible(False)             # hide the y axis

    # Where df is your data frame
    table(ax, df, colWidths=[0.17]*len(df.columns), cellLoc='center', rowLoc='right', loc='center')
    dt = plt.gcf()
    dt.set_facecolor('#8c8c8c')
    dt.set_size_inches(10, 7)
    dt.savefig(os.path.join('http/')+"http_table_user_agent.png", facecolor=dt.get_facecolor())
    plt.close()


"""
This method displays the Countries in a graph
"""


def show_country():

    geo_ip_database = 'db/GeoLite2-Country.mmdb'                  # IP database file
    ip_data = geoip2.database.Reader(geo_ip_database)              # Reader for the database

    for i in destination_ip_list:
        try:
            location = ip_data.country(i)
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
    for key, value in sorted(sDict.iteritems(),key=lambda (k, v): (v, k)):
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

    ax = plt.subplot(111, frame_on=False)       # no visible
    ax.set_title('All Countries', color='white', fontsize=14, fontweight='bold', loc='center')
    ax.xaxis.set_visible(False)                 # hide the x axis
    ax.yaxis.set_visible(False)                 # hide the y axis

    # Where df is your data frame
    table(ax, df, colWidths=[0.17]*len(df.columns), cellLoc='center', rowLoc='right', loc='center')
    dt = plt.gcf()
    dt.set_facecolor('#8c8c8c')
    dt.set_size_inches(8, 6)
    dt.savefig(os.path.join('http/')+"http_table_countries.png", facecolor=dt.get_facecolor())
    plt.close()


"""
This method displays the Top Cities in a graph
"""


def show_city():

    geo_ip_database = 'db/GeoLite2-City.mmdb'                   # IP database file
    ip_data = geoip2.database.Reader(geo_ip_database)           # Reader for the database
    cities = []                                                 # Cities list

    for i in destination_ip_list:                               # Loops through all IPs in destination list
        try:                                                    # Try
            location = ip_data.city(i)                          # Locate the ip address
            cities.append(unicode(location.city.name))          # Save the city name to the city list

        except geoip2.errors.AddressNotFoundError:              # Except the AddressNotFound Error
            print("IP not in Database:" + i)                    # Print the ip address out to console

    small_size = 8                                              # Font size on graph
    matplotlib.rc('font', size=small_size)                      # Size set

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


"""
This method generates the global map of the cities
"""


def map_cities():

    m = Basemap()                                       # m equals the Basemap graph
    m.bluemarble()                                      # Uses the earth background

    geo_ip_database = 'db/GeoLite2-City.mmdb'           # IP database file
    ip_data = geoip2.database.Reader(geo_ip_database)   # Reader for the database
    cities = []                                         # Cities list
    lat = []                                            # Latitude list
    long = []                                           # Longitude list

    for i in destination_ip_list:                       # Loops through all IPs in destination list
        try:                                            # Try
            location = ip_data.city(i)                  # Locate the ip address
            cities.append(unicode(location.city.name))  # Save the city name to the city list
            lat.append(location.location.latitude)      # Save the cities longitude
            long.append(location.location.longitude)    # Save the cities latitude

        except geoip2.errors.AddressNotFoundError:      # Except the AddressNotFound Error
            print("IP not in Database:" + i)            # Print the ip address out to console

    x, y = m(long, lat)                                 # x & y equal the long & lat on the map
    m.plot(x, y, 'ro', markersize=12)                   # Red Markers are plotted using the long & lat

    for city, xpt, ypt in zip(cities, long, lat):       # For all cities at the locations put the name
        plt.text(xpt, ypt, city, color='w')             # Coloured in white text

    md = plt.gcf()                                                  # Format the figure
    md.set_size_inches(10, 6)                                       # Set the size of the figure
    md.savefig(os.path.join('http/')+"http_map_cities.png")         # Save the figure
    plt.title('Top Attacking Cities Map')                           # Set the title
    plt.close()                                                     # Close the graph


"""
This method opens up the template report
"""


def generate_html_report():

    webbrowser.open_new_tab("Bro-Log-Report.html")      # Uses web browser library to open report


"""
Main method this calls other methods needed for gathering data from the log file
"""


def main():
    read_file('http.log')
    destination_ip_table()
    show_destination_port()
    show_destination_ip()
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
