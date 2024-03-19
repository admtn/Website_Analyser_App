
from urllib.parse import urlparse
from dotenv import load_dotenv
import requests
import os

load_dotenv()  # Load environment variables from .env file
def getDomainName(url):
    domainName = urlparse(url).netloc
    return domainName # https://www.youtube.com -> youtube.com

def getSubdomain(domainName):
    if domainName[:4] == "www.":
        domainName = domainName[4:]
    apiKey = os.getenv("subdomainsLookup_apiKey")
    if not apiKey:
        raise Exception("subdomainsLookup_apiKey not found in environment variables")

    request_url = f"https://subdomains.whoisxmlapi.com/api/v1?apiKey={apiKey}&domainName={domainName}"
    response = requests.get(request_url)

    # check for successful get request else we raise exception below
    if response.status_code == 200:
        data = response.json()
        records = data.get("result", {}).get("records", [])
        # Use a list comprehension to extract all subdomains
        subdomains = [record.get("domain") for record in records]
        return subdomains
    else:
        response.raise_for_status()

# gets isp,country code and org
def getInfo(ip):
    apiKey = os.getenv("IPgeolocation_key")
    if not apiKey:
        raise Exception("IPgeolocation_key not found in environment variables")

    request_url = f"https://api.ipgeolocation.io/ipgeo?apiKey={apiKey}&ip={ip}"
    response = requests.get(request_url)
    # check for successful get request else we raise exception below
    if response.status_code == 200:
        data = response.json() 
        return data['isp'],data['country_code2'],data['organization']
    else:
        response.raise_for_status()