from Tkinter import *
import Tkinter, Tkconstants, tkFileDialog
import html_parser
import weird_parser
import dhcp_parser
import files_parser


def main():
    root = Tk()
    root.wm_title("Bro Logger")

    Frame(root, height=500, width=750)

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

    root.files_file = tkFileDialog.askopenfilename(initialdir="/", title="Select a files.log file",
                                                   filetypes=(("log files", "*.log"),
                                                              ("all files", "*.*")))
    print (root.files_file)

    #Parser Code
    html_parser.read_file(root.http_file)
    html_parser.main()
    weird_parser.read_file(root.weird_file)
    weird_parser.main()
    dhcp_parser.read_file(root.dhcp_file)
    dhcp_parser.main()
    files_parser.read_file(root.files_file)
    files_parser.main()


if __name__ == '__main__':
    main()
