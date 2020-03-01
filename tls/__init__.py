
import logging
import azure.functions as func
import subprocess
import sys
import json
import re
from urllib.parse import urlparse


def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Python HTTP trigger function processed a request.')
    name = req.params.get('servername') # This can be either an IP address or a hostname
    if not name:
        try:
            req_body = req.get_json()
        except ValueError:
            pass
        else:
            name = req_body.get('servername')

    if name:
        return func.HttpResponse(getTlsData(name))
    else:
        return func.HttpResponse(
             "Please pass a servername on the query string or in the request body",
             status_code=400
        )

def getTlsData(name):
    ip_regex_pattern = '(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}'
    https_regex_pattern = '^https://'
    http_regex_pattern = '^http://'
    


    if(re.match(https_regex_pattern,name)==None):
        if(re.match(http_regex_pattern,name)==None):
            if(re.match(ip_regex_pattern,name) == None):
                server = str(name) + ":443"
            else:
                server = str(name) + ":443"
        else:
            server = urlparse(name)['netloc'] + ":443"
    else:
        server = urlparse(name)['netloc'] + ":443"

    return_object = {}
    return_object["url"] = server[0:-4]

    try:
        result = subprocess.getstatusoutput("echo | openssl s_client -connect " + server + "| openssl x509 -noout -email -subject -issuer -fingerprint -serial -dates")
    except:
        return_object["Error"] = True
        return_object["Error Message"] = result
        return_object["Issuing CA"] = "N/A"
        return_object["Subject Common Name"] = "N/A"
        return_object["Fingerprint"] = "N/A"
        return_object["Serial Number"] = "N/A"
        return_object["Department"] = "N/A"
        return return_object

    response_text = result[1].split("\n")
    for line in response_text:

        #Issuer
        if(line.startswith("issuer=")):
            return_object['Issuing CA'] = line.split("=")[-1].strip()

        #Subject and Department
        if(line.startswith("subject=")):
            return_object['Subject Common Name'] = line.split("=")[-1].strip()
            return_object['Department'] = line.split("=")[-2].split(",")[0].strip()

        #Email
        if(line.startswith("email=")):
            return_object['Email'] = line.split("=")[-1].strip()

        #Fingerprint
        if(line.find("Fingerprint=") >= 0):
            return_object['Fingerprint'] = line.split("=")[-1].strip()

        #serial
        if(line.startswith("serial=")):
            return_object['Serial Number'] = line.split("=")[-1].strip()

        #NotBefore
        if(line.startswith("notBefore=")):
            return_object['Valid From'] = line.split("=")[-1].strip()

        #NotAfter
        if(line.startswith("notAfter=")):
            return_object['Valid Till'] = line.split("=")[-1].strip()

    return_object["Error"] = False
    return_object["Error Message"] = None
    return return_object