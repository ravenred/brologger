from flask import Flask, render_template
import html_parser

app = Flask(__name__)


@app.route('/')
def index():
    return render_template("index.html")


@app.route('/http_dashboard')
def http_dashboard():

    return render_template("http_dashboard.html")


@app.route('/dns_dashboard')
def dns_dashboard():
    return render_template("dns_dashboard.html")


@app.route('/files_dashboard')
def files_dashboard():
    return 'files'

@app.route('/dhcp_dashboard')
def dhcp_dashboard():
    return 'DHCP'

if __name__ == "__main__":
    app.run(debug=True)
