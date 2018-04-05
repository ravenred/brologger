from Tkinter import *
import Tkinter, Tkconstants, tkFileDialog
import http_parser
import weird_parser
import dhcp_parser
import files_parser
import connection_parser
import dns_parser


def main():
    root = Tk()
    root.wm_title("Bro Logger")
    root.iconbitmap('brologger.ico')

    # HTTP Dialog
    root.http_file = tkFileDialog.askopenfilename(initialdir="/", title="Select a http.log file",
                                                  filetypes=(("log files", "*.log"),
                                                             ("all files", "*.*")))
    print (root.http_file)

    # Weird Dialog
    root.weird_file = tkFileDialog.askopenfilename(initialdir="/", title="Select a weird.log file",
                                                   filetypes=(("log files", "*.log"),
                                                              ("all files", "*.*")))
    print (root.weird_file)

    # DHCP Dialog
    root.dhcp_file = tkFileDialog.askopenfilename(initialdir="/", title="Select a dhcp.log file",
                                                  filetypes=(("log files", "*.log"),
                                                             ("all files", "*.*")))
    print (root.dhcp_file)

    # Files Dialog
    root.files_file = tkFileDialog.askopenfilename(initialdir="/", title="Select a files.log file",
                                                   filetypes=(("log files", "*.log"),
                                                              ("all files", "*.*")))
    print (root.files_file)

    # Connections Dialog
    root.conn_file = tkFileDialog.askopenfilename(initialdir="/", title="Select a conn.log file",
                                                  filetypes=(("log files", "*.log"),
                                                             ("all files", "*.*")))
    print (root.conn_file)

    # DNS Dialog
    root.dns_file = tkFileDialog.askopenfilename(initialdir="/", title="Select a dns.log file",
                                                 filetypes=(("log files", "*.log"),
                                                            ("all files", "*.*")))
    print (root.dns_file)

    #Parser Code
    http_parser.read_file(root.http_file)
    http_parser.main()
    weird_parser.read_file(root.weird_file)
    weird_parser.main()
    dhcp_parser.read_file(root.dhcp_file)
    dhcp_parser.main()
    files_parser.read_file(root.files_file)
    files_parser.main()
    connection_parser.read_file(root.conn_file)
    connection_parser.main()
    dns_parser.read_file(root.dns_file)
    dns_parser.main()


if __name__ == '__main__':
    main()
