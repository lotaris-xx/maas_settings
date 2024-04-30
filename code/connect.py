#!/usr/bin/python3

import argparse
import json
import logging
import os
import requests
import sys
import uuid

from requests_oauthlib import OAuth1Session

if __name__ == "__main__":
    log = logging.getLogger("requests_oauthlib")
    log.addHandler(logging.StreamHandler(sys.stdout))
    log.setLevel(logging.INFO)

    parser = argparse.ArgumentParser(
        prog="connect.py",
        description="Test connectivity to maas, grab token and use it",
        epilog="Used to help build an ansible module",
    )

    parser.add_argument("username")
    parser.add_argument("password")

    args = parser.parse_args()

    consumer = os.environ.get("USER") + "@" + os.environ.get("HOSTNAME")
    site = "http://maas1.internal.lotaris.org:5240/MAAS"
    uri = "/accounts/authenticate/"

    payload = {
        "username": args.username,
        "password": args.password,
        "consumer": consumer,
    }

    r = requests.post(site + uri, data=payload)

    credential = r.json()

    CONSUMER_KEY = credential["consumer_key"]
    CONSUMER_TOKEN = credential["token_key"]
    SECRET = credential["token_secret"]

    maas = OAuth1Session(
        CONSUMER_KEY,
        resource_owner_key=CONSUMER_TOKEN,
        resource_owner_secret=SECRET,
        signature_method="PLAINTEXT",
    )
    users = maas.get(f"{site}/api/2.0/users/")
    users.raise_for_status()
    print(json.dumps(users.json(), indent=2))
