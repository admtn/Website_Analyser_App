from flask import Flask, request, jsonify
from bs4 import BeautifulSoup
from ipwhois import IPWhois
from urllib.parse import urlparse
from dotenv import load_dotenv
from getFunctions import getDomainName,getSubdomain,getInfo
from flask_sockets import Sockets
from validateURL import validateURL
import validators
import requests
import socket
import uuid
import json

load_dotenv()  # Load environment variables from .env file
app = Flask(__name__)
sockets = Sockets(app)
ws_clients = dict()


@app.route('/')
def analyze_website(url=None):
    socketEntry = True if url else False
    if url is None: # web entry point
        request_data = request.args
        if 'url' not in request_data:
            return jsonify({"error": "Missing URL parameter"}), 400
        url = request_data['url']
        if not validateURL(url):
            return jsonify({"error": "Invalid URL parameter"}), 400

    try:
        # fetching website content
        if socketEntry:
            if not validateURL(url): # if no https input, add it
                url = "https://" + url
            if not validateURL(url): # if after adding https to url and invalid, user inputted invalid input
                return jsonify({"error": "Invalid URL parameter"}), 400

        response = requests.get(url)

        soup = BeautifulSoup(response.content, 'html.parser')

        # get necessary info such as domain name from the fqdn and the ip
        fqdn = socket.getfqdn(url) # get fully qualified domain name
        domain = getDomainName(fqdn)
        ip = socket.gethostbyname(domain)
        whois = IPWhois(ip)
        whois_info = whois.lookup_rdap(depth=3)

        # exctracting assets
        scripts = {script['src'] for script in soup.find_all('script') if script.get('src')}
        styles = {link['href'] for link in soup.find_all('link', rel='stylesheet') if link.get('href')}
        images = {img['src'] for img in soup.find_all('img') if img.get('src')}
        iframes = {iframe['src'] for iframe in soup.find_all('iframe') if iframe.get('src')}
        anchors = {a['href'] for a in soup.find_all('a', href=True) if a['href'].startswith('http')}
        subdomains = getSubdomain(domain)
        isp,location,organisation = getInfo(ip)

        output = {
            "info": {
                "ip": ip,
                "isp": isp,
                "organization": organisation,
                "asn": whois_info.get('asn'),
                "location": location
                # "location": whois_info.get('network', {}).get('country')
            },
            "subdomains": subdomains,
            "asset_domains": {
                "javascripts": list(scripts),
                "stylesheets": list(styles),
                "images": list(images),
                "iframes": list(iframes),
                "anchors": list(anchors)
            }
        }

        return output

    except Exception as e:
        # return jsonify({"error": str(e)}), 500
        return {"error": str(e)}
    
@sockets.route('/ws')
def analyse_websocket(ws):
    client_id = str(uuid.uuid4())
    ws_clients[client_id] = dict()
    while not ws.closed:
        message = ws.receive()
        if message:
            try:
                data = json.loads(message)
            except:
                ws.send(json.dumps({"error": "Invalid JSON format in the message"}))
            else:
                if 'url' in data:
                        if not validateURL(data['url']) and not validateURL("https://"+data['url']):
                            ws.send(json.dumps({"error": "Invalid URL"}))
                        else:
                            ws.send(json.dumps({"data": f"creating session for {data['url']}..."}))
                            ws_clients[client_id]['url'] = data['url']
                            ws.send(json.dumps({"data": f"session created for {data['url']}"}))
                elif 'operation' in data:
                    if 'url' not in ws_clients[client_id]:
                        ws.send(json.dumps({"error": "Session not found. Please provide a valid URL first"}))
                    
                    # no exceptions has occured
                    url = ws_clients[client_id]['url']
                    result = analyze_website(url)
                    if data['operation'] == "get_info":
                        ws.send(json.dumps(result.get('info')))
                        # ws.send(json.dumps({"data": result["info"]}))
                    elif data['operation'] == 'get_subdomains':
                        ws.send(json.dumps(result.get('subdomains')))
                    elif data['operation'] == 'get_asset_domains':
                        ws.send(json.dumps(result.get('asset_domains')))
                else:
                    ws.send(json.dumps({"error": "Invalid message format"}))
        else:
            ws.send(json.dumps({"error": "Invalid message format"}))

if __name__ == '__main__':
    from gevent import pywsgi
    from geventwebsocket.handler import WebSocketHandler
    server = pywsgi.WSGIServer(('0.0.0.0', 5000), app, handler_class=WebSocketHandler)
    server.serve_forever()