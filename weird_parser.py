import datetime

parsed_log = []


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

            time, uid, id_orig_h, id_orig_p, id_resp_h, id_resp_p, name, addl, notice, peer = \
                tuple(map(str, new_line.split("\t")))



read_file('0ad9515239c4033d84936c2e6ba00ed1_20120624/weird.log')