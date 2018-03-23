"""
Imported Libirary 
"""
import datetime
import webbrowser
import os
from collections import Counter
import matplotlib
import matplotlib.pyplot as plt
import pylab
import geoip2.database
import pandas as pd
from pandas.plotting._tools import table
from mpl_toolkits.basemap import Basemap

"""
Parser File
"""
parsed_log = []
source_ip = []
sport_list = []
dest_ip = []
dport = []
url_list = []
user_agent_list = []
traffic_list = []
countries = []


def read_file(file_name):

    f = open(file_name, 'r')
    start_line = f.readlines()

    for i in start_line[8:]:
        if "#close" in i:
            pass
        else:
            convert = datetime.datetime.fromtimestamp(float(i[:17]))
            new_line = str(convert) + " " + i[17:]
            parsed_log.append(new_line)

            time, uid, orig_h, orig_p, resp_h, resp_p, trans_depth, method, host, uri, referrer, user_agent, \
                request_body_len, response_body_len, status_code, status_msg, info_code, info_msg, filename, \
                tags, username, password, proxied, orig_fuids, orig_mime_types, resp_fuids, resp_mime_types = \
                tuple(map(str, new_line.split("\t")))

            source_ip.append(orig_h)
            sport_list.append(orig_p)
            dest_ip.append(resp_h)
            dport.append(resp_p)
            url_list.append(host+uri)
            user_agent_list.append(user_agent)
            traffic_list.append(time) #[:19]
            #print(time)


def print_log():

    for i in parsed_log:
        print(i)


def show_traffic():

    s = Counter(traffic_list)
    sDict = dict(s)
    xVals = []
    yVals = []
    count = 0

    for key, value in sorted(sDict.iteritems(), key=lambda (k, v): (v, k)):
        count += 1
        if count > len(sDict)-10:
            xVals.append(key)
            yVals.append(value)

    plt.scatter(xVals, yVals, color='red')
    traffic_fig = plt.gcf()
    traffic_fig.set_size_inches(15, 8)
    plt.grid()
    #plt.show()
    plt.close()


def show_dport():

    s = Counter(sport_list)
    sDict = dict(s)
    xVals = []
    yVals = []
    count = 0
    for key, value in sorted(sDict.iteritems(), key=lambda (k, v): (v, k)):
        count += 1
        if count > len(sDict)-10:
            xVals.append(key)
            yVals.append(value)

    plt.bar(xVals, yVals, color='green')
    plt.suptitle('Top 10 Destination Ports', fontsize=14, fontweight='bold')
    plt.xlabel('Destination Ports', fontsize=10, fontweight='bold')
    plt.ylabel('Total', fontsize=10, fontweight='bold')
    dportfig = plt.gcf()
    dportfig.set_size_inches(10, 5)
    dportfig.savefig(os.path.join('bro_app/static/images/tmp/http/')+"http_dport.png")
    #plt.show()
    plt.close()


def dport_table():

    data = Counter(dport)
    df = pd.DataFrame.from_dict(data, orient='index')

    ax = plt.subplot(111, frame_on=False)  # no visible frame
    ax.xaxis.set_visible(False)  # hide the x axis
    ax.yaxis.set_visible(False)  # hide the y axis
    table(ax, df, colWidths=[0.17]*len(df.columns), cellLoc='center', rowLoc='center', loc='center')  # where df is your data frame
    #df.plot(table=df, ax=ax)
    dt = plt.gcf()
    dt.set_size_inches(10, 4)
    plt.show()


def show_destip():

    small_size = 6
    matplotlib.rc('font', size=small_size)

    s = Counter(dest_ip)
    sDict = dict(s)
    xVals = []
    yVals = []
    count = 0

    for key, value in sorted(sDict.iteritems(),key=lambda (k,v): (v,k)):
        count+=1
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
    #plt.show()
    plt.close()


def destip_table():

    data = Counter(dest_ip)
    df = pd.DataFrame.from_dict(data, orient='index')
    #df.columns = ['IP' 'Total']
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
    #plt.show()
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
    #plt.show()
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
    #plt.show()
    plt.close()


def user_agent_table():

    data = Counter(user_agent_list)
    df = pd.DataFrame.from_dict(data, orient='index')
    #df.columns = ['IP' 'Total']
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
    #plt.show()
    plt.close()


def show_country():

    GeoIPDatabase = 'GeoLite2-Country.mmdb'     #IP database file
    ipData = geoip2.database.Reader(GeoIPDatabase)

    for i in dest_ip:
        #try:
        location = ipData.country(i)
        countries.append(location.country.name)

        #expect geoip2.errors.AddressNotFoundError:

    SMALL_SIZE = 10
    matplotlib.rc('font', size=SMALL_SIZE)

    s = Counter(countries)
    sDict = dict(s)
    xVals = []
    yVals = []
    count = 0
    for key, value in sorted(sDict.iteritems(),key=lambda (k,v): (v,k)):
        count+=1
        if count > len(sDict)-10:
            xVals.append(key)
            yVals.append(value)

    plt.bar(xVals, yVals)
    plt.bar(xVals, yVals, color='purple')
    plt.suptitle('Top 5 Countries', fontsize=14, fontweight='bold')
    plt.xlabel('Countries', fontsize=12, fontweight='bold')
    plt.ylabel('Total', fontsize=12, fontweight='bold')
    dportfig = plt.gcf()
    dportfig.set_size_inches(10, 5)
    dportfig.savefig(os.path.join('http/')+"http_country.png")
    #plt.show()
    plt.close()


def map_country():

    m = Basemap()
    #m.drawcoastlines()
    #m.drawcountries()
    #m.drawmapboundary(fill_color='aqua')
    #m.fillcontinents(color='coral', lake_color='aqua')
    m.bluemarble()
    md = plt.gcf()
    md.set_size_inches(10, 8)
    md.savefig(os.path.join('http/')+"http_map_country.png")
    #plt.show()
    plt.close()


def table_country():

    data = Counter(countries)
    df = pd.DataFrame.from_dict(data, orient='index')
    df.rename(columns={0: 'Total'}, inplace=True)

    ax = plt.subplot(111, frame_on=False)  # no visible
    ax.set_title('All Countries', color='white', fontsize=14, fontweight='bold', loc='center')
    ax.xaxis.set_visible(False)  # hide the x axis
    ax.yaxis.set_visible(False)  # hide the y axis
    table(ax, df, colWidths=[0.17]*len(df.columns), cellLoc='center', rowLoc='right', loc='center')  # where df is your data frame
    dt = plt.gcf()
    dt.set_facecolor('#8c8c8c')
    dt.set_size_inches(8, 6)
    dt.savefig(os.path.join('http/')+"http_table_countries.png", facecolor=dt.get_facecolor())
    #plt.show()
    plt.close()


def show_city():

    GeoIPDatabase = 'GeoLite2-City.mmdb'     #IP database file
    ipData = geoip2.database.Reader(GeoIPDatabase)
    cities = []

    for i in dest_ip:
        location = ipData.city(i)
        cities.append(unicode(location.city.name))

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
    #plt.show()
    plt.close()


def map_cities():

    #plt.figure(figsize=(14, 8))
    m = Basemap()
    m.bluemarble()

    GeoIPDatabase = 'GeoLite2-City.mmdb'     #IP database file
    ipData = geoip2.database.Reader(GeoIPDatabase)
    cities = []
    lat = []
    long = []

    for i in dest_ip:
        location = ipData.city(i)
        cities.append(unicode(location.city.name))
        lat.append(location.location.latitude)
        long.append(location.location.longitude)

    x, y = m(long, lat)
    m.plot(x, y, 'ro', markersize=12)

    for city, xpt, ypt in zip(cities, long, lat):
        plt.text(xpt, ypt, city)

    md = plt.gcf()
    md.set_size_inches(10, 8)
    md.savefig(os.path.join('http/')+"http_map_cities.png")
    plt.title('Top Attacking Cities Map')
    #plt.show()
    plt.close()


def generate_html_report():

    webbrowser.open_new_tab("Bro-Log-Report.html")


def main():
    read_file('http.log')
    destip_table()
    show_traffic()
    show_dport()
    show_destip()
    show_urls()
    show_user_agent()
    user_agent_table()
    show_country()
    table_country()
    show_city()
    #generate_html_report()
    map_country()
    map_cities()

if __name__ == '__main__':
    main()
