#!/usr/bin/python

# Copyright: Allen Smith <asmith687@t-mobile.com>
# License: MIT-0 (See https://opensource.org/license/mit-0)
from __future__ import absolute_import, division, print_function

from requests import post, exceptions
from requests_oauthlib import OAuth1Session
from yaml import safe_dump

__metaclass__ = type

DOCUMENTATION = r"""
---
module: maas_subnet

short_description: Configure MAAS subnets

version_added: "1.0.0"

description: Configure MAAS subnets

options:
    password:
        description: Password for username used to get API token
        required: true
        type: str
    site:
        description: URL of the MAAS site (generally ending in /MAAS)
        required: true
        type: str
    state:
        description: A list containing subnet specifier dictionaries
        required: false
        type: str
        default: present
        choices:
            - absent
            - present
    username:
        description: Username to get API token for
        required: true
        type: str
    subnets:
        description: A list containing subnet specifier dictionaries
        required: true
        type: list
        suboptions:
          name:
              description: The name of the subnet
              required: true
              type: dict


# Specify this value according to your collection
# in format of namespace.collection.doc_fragment_name
# extends_documentation_fragment:
#     - my_namespace.my_collection.my_doc_fragment_name

author:
    - Allen Smith (@allsmith-tmo)
"""

EXAMPLES = r"""
# Add 3 subnets if they don't exist
-  username: user
   password: password
   subnets:
     - name: 100
     - name: 200
     - name: 300

# Remove two subnets if they exist
-  username: user
   password: password
   state: absent
   subnets:
     - name: 200
     - name: 300
"""

RETURN = r"""
# These are examples of possible return values, and in general should use other names for return values.
message:
    description: A status message from the module
    type: str
    returned: always
"""

from ansible.module_utils.basic import AnsibleModule


class maas_api_cred:
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


def get_maas_subnets(session, module):
    try:
        current_subnets = session.get(
            f"{module.params['site']}/api/2.0/fabrics/0/subnets/"
        )
        current_subnets.raise_for_status()
        return current_subnets.json()
    except exceptions.RequestException as e:
        module.fail_json(msg="get_maas_subnets failed: {}".format(str(e)))


def grab_maas_apikey(module):
    consumer = "ansible@host"
    uri = "/accounts/authenticate/"
    site = module.params["site"]
    username = module.params["username"]
    password = module.params["password"]

    payload = {
        "username": username,
        "password": password,
        "consumer": consumer,
    }
    try:
        r = post(site + uri, data=payload)
        r.raise_for_status()
        return r
    except exceptions.RequestException as e:
        module.fail_json(msg="Auth failed: {}".format(str(e)))


def maas_add_subnets(session, current_subnets, module, res):
    vlist = []

    for subnet in module.params["subnets"]:
        if str(subnet["name"]) not in current_subnets.keys():
            vlist.append(subnet["name"])
            res["changed"] = True

            if not module.check_mode:
                payload = {
                    "name": subnet["name"],
                    "vid": subnet["name"],
                    "fabric_id": "0",
                }
                try:
                    r = session.post(
                        f"{module.params['site']}/api/2.0/fabrics/0/subnets/",
                        data=payload,
                    )
                    r.raise_for_status()
                except exceptions.RequestException as e:
                    module.fail_json(msg="subnet Add Failed: {}".format(str(e)))

                new_subnets_dict = {
                    item["name"]: item for item in get_maas_subnets(session, module)
                }

                res["diff"] = dict(
                    before=safe_dump(current_subnets),
                    after=safe_dump(new_subnets_dict),
                )

        res["message"] = "Added subnets " + str(vlist)


def maas_delete_subnets(session, current_subnets, module, res):
    vlist = []

    for subnet in module.params["subnets"]:
        if str(subnet["name"]) in current_subnets.keys():
            vlist.append(subnet["name"])
            res["changed"] = True

            if not module.check_mode:
                try:
                    r = session.delete(
                        f"{module.params['site']}/api/2.0/fabrics/0/subnets/{subnet['name']}/",
                    )
                    r.raise_for_status()
                except exceptions.RequestException as e:
                    module.fail_json(msg="subnet Remove Failed: {}".format(str(e)))

                new_subnets_dict = {
                    item["name"]: item for item in get_maas_subnets(session, module)
                }

                res["diff"] = dict(
                    before=safe_dump(current_subnets),
                    after=safe_dump(new_subnets_dict),
                )

    res["message"] = "Removed subnets " + str(vlist)


def run_module():
    module_args = dict(
        subnets=dict(type="list", required=True),
        password=dict(type="str", required=True, no_log=True),
        username=dict(type="str", required=True),
        site=dict(type="str", required=True),
        state=dict(type="str", required=False, default="present"),
    )

    result = dict(changed=False, message={}, diff={})

    module = AnsibleModule(argument_spec=module_args, supports_check_mode=True)

    r = grab_maas_apikey(module)
    c = maas_api_cred(r.json())

    maas_session = OAuth1Session(
        c.client_key,
        resource_owner_key=c.resource_owner_key,
        resource_owner_secret=c.resource_owner_secret,
        signature_method="PLAINTEXT",
    )

    current_subnets_dict = {
        item["name"]: item for item in get_maas_subnets(maas_session, module)
    }

    if module.params["state"] == "present":
        maas_add_subnets(maas_session, current_subnets_dict, module, result)

    elif module.params["state"] == "absent":
        maas_delete_subnets(maas_session, current_subnets_dict, module, result)

    module.exit_json(**result)


def main():
    run_module()


if __name__ == "__main__":
    main()
