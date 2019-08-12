import http.server
import socketserver
from io import BytesIO
import time
import os
import datetime
import json

class SimpleHTTPRequestHandler(http.server.BaseHTTPRequestHandler):

    def __init__(self, *args):
        self.f = open("index.html", "r").read()
        super().__init__(*args)

    def do_GET(self):
        mtime = self.headers['If-Modified-Since']
        if mtime is not None:
            mtime = datetime.datetime.strptime(mtime[0:-4], "%a, %d %b %Y %H:%M:%S")
            mtime2 = datetime.datetime.utcfromtimestamp(os.path.getmtime('index.html'))
            if mtime > mtime2:
                self.send_response(302)
                self.end_headers()
                return

        self.send_response(200)
        self.end_headers()
        self.wfile.write(self.f.encode('ascii'))

    def do_POST(self):
        content_length = int(self.headers['Content-Length'])
        body = self.rfile.read(content_length)
        self.send_response(200)
        self.end_headers()

        body = json.loads(body.decode('ascii'))
        if body["fname"] == "Teja" and body["lname"] == "Dhondu":
            response = "Welcome Teja"
        else:
            response = "Who are you"

        self.wfile.write(response.encode('ascii'))

PORT = 20101
Handler = SimpleHTTPRequestHandler
httpd = socketserver.TCPServer(("", PORT), Handler)
print("serving at port", PORT)
httpd.serve_forever()
