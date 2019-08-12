import socket
import ssl
import base64
import json
import time
import random
import datetime
from _thread import *

cache = [[0, 0], [0, 0], [0, 0]]
cache_pointer = [0]
cache_times = {}

# Parse host request to check for cache control header
def parse_host_request(host_request, proxy_request):
    # Split headers
    host_headers = host_request.split('\r\n')
    host_headers.pop()
    host_headers.pop()

    # Check type of request
    if host_headers[0][0:4] == "POST":
        return host_request, True, True
    elif host_headers[0][0:4] == "GET ":
        for i in range(len(cache)):
            if cache[i][0] == proxy_request:
                date = datetime.datetime.utcfromtimestamp(cache[i][2])
                date = str(date.strftime("%a, %d %b %Y %H:%M:%S %Z")) + "GMT"
                host_headers.append("If-Modified-Since: " + date)
                host_headers.append('\r\n')
                host_request = '\r\n'.join(host_headers)
    else:
        return host_request, False, False

    # Check for cache control header
    NO_CACHE = False
    for header in host_headers:
        header = header.strip()
        if header.startswith("Cache-Control"):
            if header.endswith("no-cache") or header.endswith("no-store"):
                NO_CACHE = True
                break

    return host_request, NO_CACHE, True

# Parse proxy request, check for authentication, return proxy request body
def parse_proxy_request(proxy_request):
    # Split headers and get the proxy request body
    proxy_headers = proxy_request.split('\r\n')
    proxy_body = json.loads(proxy_headers.pop())
    proxy_headers.pop()

    # Check for authentication
    auth_true = False
    for header in proxy_headers:
        header = header.strip()
        if header.startswith("Authorization"):
            auth = header.split(" ")
            auth_str = str.encode(auth[-1])
            auth_res = base64.b64decode(auth_str).decode('utf-8')
            with open('data.txt') as f:
                for line in f:
                    line = line.strip('\n')
                    if line == auth_res:
                        auth_true = True
                        break
            admin_true = False
            with open('admin.txt') as f:
                for line in f:
                    line = line.strip('\n')
                    if line == auth_res:
                        auth_true = True
                        admin_true = True
                        break

    return proxy_body, auth_true, admin_true

# Serve client connections
def serve(c):
    # Recieve proxy request from client and parse it
    proxy_request = c.recv(1024)
    if not proxy_request:
        return
    proxy_request = proxy_request.decode('ascii')
    proxy_body, auth_true, admin_true = parse_proxy_request(proxy_request)
    host_address = proxy_body["host_address"]
    host_port = int(proxy_body["host_port"])
    host_request = proxy_body["host_request"]
    host_request, NO_CACHE, isValid = parse_host_request(host_request, proxy_request)

    # Check for valid type of request
    if not isValid:
        print("Invalid request type")
        print('Server thread closed')
        c.sendall("Invalid request type".encode('ascii'))
        c.close()
        return

    # Check for authentication
    if not auth_true:
        print("authentication failed")
        print('Server thread closed')
        c.sendall("authentication failed".encode('ascii'))
        c.close()
        return

    # Check for blacklisted ip address
    try:
        # print("asjdfahskgggggggggggggggggggggggggggggggggg")
        # print(blacklist(host_address))
        print(admin_true)
        if (blacklist(host_address) or not (host_address != "127.0.0.1" or inside_iit(host_address))) and not admin_true:
            print('port black listed')
            print('Server thread closed')
            c.sendall("port black listed".encode('ascii'))
            c.close()
            return
    except:
        print("Invalid host address")
        print('Server thread closed')
        c.sendall("Invalid host address".encode('ascii'))
        c.close()
        return

    # Set up socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    if proxy_body['http_type'] == 2:
        s = ssl.wrap_socket(s, ssl_version=ssl.PROTOCOL_TLSv1) # HTTPS request if host is outside localhost
    try:
        s.connect((host_address, host_port))
        s.sendall(host_request.encode('ascii'))
    except Exception as e:
        print(e)
        print("Unable to connect to host")
        print('Server thread closed')
        c.sendall("Unable to connect to host".encode('ascii'))
        c.close()
        return

    # Recieve data from host server
    chunks = []
    while True:
        chunk = s.recv(1024)
        if len(chunk) < 1:
            break
        chunks.append(chunk)
    data = b''.join(chunks)

    # Check for cache access
    if not NO_CACHE:
        for i in range(len(cache)):
            if cache[i][0] == proxy_request:
                response = data.decode('ascii')
                print(response[9:12])
                if response[9:12] == "200":
                    break
                print("cache access")
                print('Server thread closed')
                c.sendall(cache[i][1])
                c.close()
                s.close()
                return

    # Cache response from host
    if not NO_CACHE:
        # Check if cache for request already exists. If so then overwrite it
        cached = False
        for i in range(len(cache)):
            if cache[i][0] == proxy_request:
                cache[i][1] = data
                cache[i][2] = time.time()
                cached = True
        # If cache for request doesn't exist, check number of times request has been
        # sent in last 5 minutes. If over 3, then store in cache
        if not cached and proxy_request in cache_times:
            if cache_times[proxy_request][1] < 3:
                cache_times[proxy_request][1] += 1
            else:
                if cache_times[proxy_request][0] - time.time() < 300:
                    cache[cache_pointer[0]] = [proxy_request, data, time.time()]
                    cache_pointer[0] = (cache_pointer[0] + 1) % 3
                else:
                    cache_times[proxy_request] = [time.time(), 1]
        elif not cached:
            cache_times[proxy_request] = [time.time(), 1]


    # send reponse to client
    c.sendall(data)
    print('Server thread closed')
    c.close()
    s.close()

def blacklist(addr):
    # addr =
    with open('blacklist.txt') as f:
        for cidr in f:
            # print(line)
            ipv4, bit_mask = cidr.split('/')
            # print(ipv4)
            # print(bitmask)
            ipv4_1, ipv4_2, ipv4_3, ipv4_4 = ipv4.split('.')
            # print(ipv4_1, ipv4_2, ipv4_3, ipv4_4)
            decimal_ipaddr = int(ipv4_1) * (16 ** 3) + int(ipv4_2) * (16 ** 2) + int(ipv4_3) * 16 + int(ipv4_4)
            # print(decimal_ipaddr)
            ipv4_1, ipv4_2, ipv4_3, ipv4_4 = addr.split('.')
            # print(ipv4_1, ipv4_2, ipv4_3, ipv4_4)
            decimal_ipaddr1 = int(ipv4_1) * (16 ** 3) + int(ipv4_2) * (16 ** 2) + int(ipv4_3) * 16 + int(ipv4_4)
            # print(decimal_ipaddr1)
            zero_mask = 32 - int(bit_mask)
            subnet_ipaddr  = (2 ** int(bit_mask) - 1) * 2 ** zero_mask
            net_addr  = decimal_ipaddr & subnet_ipaddr
            net_addr1 = decimal_ipaddr1 & subnet_ipaddr
            if net_addr == net_addr1:
                # print("blocked")
                return True
            return False
            # else:
                # print("not blocked")
            # print("apna")

def inside_iit(addr):
    with open('blacklist.txt') as f:
        # for cidr in f:
            # print(line)
        ipv4, bit_mask = "10.1.131.0", 22
        # print(ipv4)
        # print(bitmask)
        ipv4_1, ipv4_2, ipv4_3, ipv4_4 = ipv4.split('.')
        # print(ipv4_1, ipv4_2, ipv4_3, ipv4_4)
        decimal_ipaddr = int(ipv4_1) * (16 ** 3) + int(ipv4_2) * (16 ** 2) + int(ipv4_3) * 16 + int(ipv4_4)
        # print(decimal_ipaddr)
        ipv4_1, ipv4_2, ipv4_3, ipv4_4 = addr.split('.')
        # print(ipv4_1, ipv4_2, ipv4_3, ipv4_4)
        decimal_ipaddr1 = int(ipv4_1) * (16 ** 3) + int(ipv4_2) * (16 ** 2) + int(ipv4_3) * 16 + int(ipv4_4)
        # print(decimal_ipaddr1)
        zero_mask = 32 - int(bit_mask)
        subnet_ipaddr  = (2 ** int(bit_mask) - 1) * 2 ** zero_mask
        net_addr  = decimal_ipaddr & subnet_ipaddr
        net_addr1 = decimal_ipaddr1 & subnet_ipaddr
        if net_addr == net_addr1:
            # print("blocked")
            return True
        return False
        # else:
            # print("not blocked")
        # print("apna")


def Main():
    # Set up socket
    address = "127.0.0.1"
    port = 20100
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR | socket.SO_REUSEPORT, 1)
    s.bind((address, port))
    print("socket binded to post", port)
    s.listen(5)
    print("socket is listening")

    # Accept connections from clients
    while True:
        c, addr = s.accept()
        print('Connected to :', addr[0], ':', addr[1])
        start_new_thread(serve, (c,))
    s.close()

if __name__ == '__main__':
    Main()
    # print(blacklist("126.0.0.1"))
