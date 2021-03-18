import logging
import json
import azure.functions as func


def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Python HTTP trigger function processed a request.')

    headers = req.headers['x-forwarded-for']

    if headers:
        return func.HttpResponse(body=json.dumps({"public_ip": headers.split(':')[0]}),headers={"Content-Type":"application/json"})
    else:
        return func.HttpResponse(
             "Please pass a name on the query string or in the request body",
             status_code=400
        )