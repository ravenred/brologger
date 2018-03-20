from Tkinter import *
import Tkinter, Tkconstants, tkFileDialog
import html_parser


def main():
    root = Tk()
    root.filename = tkFileDialog.askopenfilename(initialdir="/", title="Select file", filetypes=(("jpeg files","*.jpg"), ("all files","*.*")))
    print (root.filename)

    #Parser Code
    html_parser.read_file(root.filename)
    html_parser.main()

if __name__ == '__main__':
    main()
