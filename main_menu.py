from Tkinter import *
import Tkinter, Tkconstants, tkFileDialog
import html_parser
import weird_parser


def main():
    root = Tk()
    root.http_file = tkFileDialog.askopenfilename(initialdir="/", title="Select file",
                                                  filetypes=(("log files", "*.log"),
                                                             ("all files", "*.*")))
    print (root.http_file)

    root.weird_file = tkFileDialog.askopenfilename(initialdir="/", title="Select file",
                                                   filetypes=(("log files", "*.log"),
                                                              ("all files", "*.*")))
    print (root.weird_file)

    #Parser Code
    html_parser.read_file(root.http_file)
    html_parser.main()
    weird_parser.read_file(root.weird_file)
    weird_parser.main()


if __name__ == '__main__':
    main()
