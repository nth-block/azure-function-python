import logging
import azure.functions as func
import subprocess
import sys
import json
import re
from urllib.parse import urlparse

# Invocation
# https://<azureFunctionName>.azurewebsites.net/api/tlsv2?domain=http://<domainName>
# https://<azureFunctionName>.azurewebsites.net/api/tlsv2?domain=https://<domainName>
# https://<azureFunctionName>.azurewebsites.net/api/tlsv2?domain=<domainname>
# https://<azureFunctionName>.azurewebsites.net/api/tlsv2?domain=<ipAddress>


def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Python HTTP trigger function processed a request.')
    # This can be either an IP address or a hostname
    name = req.params.get('domain')
    if not name:
        try:
            req_body = req.get_json()
        except ValueError:
            pass
        else:
            name = req_body.get('domain')

    if name:
        return func.HttpResponse(
            body=json.dumps(getTlsData(name)),
            headers={'Content-Type': 'application/json'}
        )
    else:
        return func.HttpResponse(
             body=json.dumps(
                 {"error": "Please pass a domain on the query string or in the request body"}),
             headers={'Content-Type': 'application/json'},
             status_code=400
        )


def getTlsData(name: str) -> dict:
    ip_regex_pattern = '(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)(\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)){3}'
    https_regex_pattern = '^http(s|)://'
    # http_regex_pattern = '^http://'

    if(re.match(https_regex_pattern, name) == None):
        if(re.match(ip_regex_pattern, name) == None):
            server = str(name) + ":443"
        else:
            # If the name does not have https as well as an IP address as well, we assume that the invocation only contains the domain name
            server = str(name) + ":443"
            # return func.HttpResponse(json.dumps({dict(error = "Entry must be either a domain name or IP address")}), status_code = 400)
    else:
        server = urlparse(name).netloc + ":443"

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
        return return_object

    response_text = result[1].split("\n")
    for line in response_text:

        # Issuer
        if(line.startswith("issuer=")):
            return_object['Issuing CA'] = line.split("=")[-1].strip()

        # Subject
        if(line.startswith("subject=")):
            return_object['Subject Common Name'] = line.split("=")[-1].strip()

        # Email
        if(line.startswith("email=")):
            return_object['Email'] = line.split("=")[-1].strip()

        # Fingerprint
        if(line.find("Fingerprint=") >= 0):
            return_object['Fingerprint'] = line.split("=")[-1].strip()

        # serial
        if(line.startswith("serial=")):
            return_object['Serial Number'] = line.split("=")[-1].strip()

        # NotBefore
        if(line.startswith("notBefore=")):
            return_object['Valid From'] = line.split("=")[-1].strip()

        # NotAfter
        if(line.startswith("notAfter=")):
            return_object['Valid Till'] = line.split("=")[-1].strip()

    return_object["Error"] = False
    return_object["Error Message"] = None
    return return_object
