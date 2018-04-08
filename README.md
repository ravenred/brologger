# brologger

##  Bro Network Security Monitor Log Analyser 
This program uses a GUI to read in the six following Bro Logs:
*   http.log
*  weird.log
*   dhcp.log
*   files.log
*   conn.log
*   dns.log

Then outputs the sorted contents to graphs using a html web report.

## Installation
To setup the log analyser firstly Git clone using the following command.
```
git clone https://github.com/ravenred/brologger.git
```
Next to install the requirements.txt file 
```
pip install -r /brologger/requirements.txt
```

## Run
To run the program
```
python brologger
```
