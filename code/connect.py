#!/usr/bin/python3

import argparse
import json
import logging
import os
import requests
import sys
import uuid

from requests_oauthlib import OAuth1Session


class MAASAPICred:
    """
    Represents a MAAS API Credenital
    Provides both MAAS API and OAuth terminology
    """

    def __init__(self, api_json):
        self.consumer_key = api_json["consumer_key"]
        self.token_key = api_json["token_key"]
        self.token_secret = api_json["token_secret"]
        self.client_key = self.consumer_key
        self.resource_owner_key = self.token_key
        self.resource_owner_secret = self.token_secret


def grab_maas_apikey(site, username, password):
    consumer = os.environ.get("USER") + "@" + os.environ.get("HOSTNAME")
    uri = "/accounts/authenticate/"

    payload = {
        "username": args.username,
        "password": args.password,
        "consumer": consumer,
    }

    return requests.post(site + uri, data=payload)


if __name__ == "__main__":
    log = logging.getLogger("requests_oauthlib")
    log.addHandler(logging.StreamHandler(sys.stdout))
    log.setLevel(logging.INFO)

    parser = argparse.ArgumentParser(
        prog="connect.py",
        description="Test connectivity to MAAS, grab token and use it",
        epilog="Used to help build an ansible module",
    )

    parser.add_argument("username")
    parser.add_argument("password")

    args = parser.parse_args()

    site = "http://maas1.internal.lotaris.org:5240/MAAS"

    r = grab_maas_apikey(site, args.username, args.password)

    c = MAASAPICred(r.json())

    maas_session = OAuth1Session(
        c.client_key,
        resource_owner_key=c.resource_owner_key,
        resource_owner_secret=c.resource_owner_secret,
        signature_method="PLAINTEXT",
    )

    users = maas_session.get(f"{site}/api/2.0/users/")
    users.raise_for_status()
    print(json.dumps(users.json(), indent=2))
