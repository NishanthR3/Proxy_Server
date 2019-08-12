import socket
import json
import base64

def Main():
    # Port numbers and addresses
    proxy_address = "127.0.0.1"
    proxy_port = 20100
    print("host_address ?")
    host_address = input()
    host_address = str(host_address)
    print("host_port ?")
    host_port = int(input())
    print("http 1 https 2")
    http_type = int(input())

    # Set up socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((proxy_address, proxy_port))

    # Construct host header
    host_headers = []
    print("get 1 post 2")
    req_type = int(input())
    if req_type != 1 and req_type != 2:
        return
    # POST request
    if req_type == 2:
        host_headers.append("POST / HTTP/1.0\r\n")
        host_headers.append("Content-Length: {}\r\n")
        host_headers.append("Content-Type: application/json\r\n\r\n")
        host_body = json.dumps({
            "fname": "Teja",
            "lname": "Dhondu"
        }, sort_keys = True)
        host_headers[1] = host_headers[1].format(len(host_body))
        host_request = ''.join(host_headers) + host_body
    # GET request
    else:
        print("cache control yes 1 no 2")
        req_type = int(input())
        if req_type != 1 and req_type != 2:
            return
        if req_type == 2:
            host_request = "GET / HTTP/1.0\r\nCache-Control: no-store\r\n\r\n" # For GET requests
        else:
            host_request = "GET / HTTP/1.0\r\n\r\n" # For GET requests

    # Construct proxy header and send
    proxy_headers = []
    proxy_headers.append("POST / HTTP/1.0\r\n")
    proxy_headers.append("Content-Length: {}\r\n")
    print("username ?")
    username = input()
    print("password ?")
    password = input()
    # username = "username"
    # password = "password"
    code = username + ":" + password
    chk = base64.b64encode(code.encode('utf-8')).decode('utf-8')
    proxy_headers.append("Authorization : Basic {}\r\n".format(chk))
    proxy_headers.append("Content-Type: application/json\r\n\r\n")
    proxy_body = json.dumps({
        "host_address": host_address,
        "host_port": host_port,
        "host_request": host_request,
        "http_type": http_type
    }, sort_keys = True)
    proxy_request = ''.join(proxy_headers) + proxy_body
    s.sendall(proxy_request.encode('ascii'))

    # Recieve data from proxy server
    chunks = []
    while True:
        chunk = s.recv(1024)
        if len(chunk) < 1:
            break
        chunks.append(chunk)
    data = b''.join(chunks)
    try:
        print('Received from the server :', str(data.decode('ascii')))
    except:
        print("Can't decode response. Here is the original response")
        print(data)
    s.close()

if __name__ == '__main__':
    Main()
