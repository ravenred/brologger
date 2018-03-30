from Tkinter import *
import Tkinter, Tkconstants, tkFileDialog
import html_parser
import weird_parser
import dhcp_parser


def main():
    root = Tk()
    root.http_file = tkFileDialog.askopenfilename(initialdir="/", title="Select a http.log file",
                                                  filetypes=(("log files", "*.log"),
                                                             ("all files", "*.*")))
    print (root.http_file)

    root.weird_file = tkFileDialog.askopenfilename(initialdir="/", title="Select a weird.log file",
                                                   filetypes=(("log files", "*.log"),
                                                              ("all files", "*.*")))
    print (root.weird_file)

    root.dhcp_file = tkFileDialog.askopenfilename(initialdir="/", title="Select a dhcp.log file",
                                                  filetypes=(("log files", "*.log"),
                                                             ("all files", "*.*")))
    print (root.dhcp_file)

    #Parser Code
    html_parser.read_file(root.http_file)
    html_parser.main()
    weird_parser.read_file(root.weird_file)
    weird_parser.main()
    dhcp_parser.read_file(root.dhcp_file)
    dhcp_parser.main()


if __name__ == '__main__':
    main()
