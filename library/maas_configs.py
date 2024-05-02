#!/usr/bin/python

# Copyright: Allen Smith <asmith687@t-mobile.com>
# License: MIT-0 (See https://opensource.org/license/mit-0)
from __future__ import absolute_import, division, print_function

from argparse import ArgumentParser
from requests import post
from requests_oauthlib import OAuth1Session

__metaclass__ = type

DOCUMENTATION = r"""
---
module: maas_configs

short_description: Configure various maas settings

version_added: "1.0.0"

description: Configure various MAAS settings. Different kinds of
settings are supported.

options:
    configs:
        description: A dictionary containing configurations to apply
        required: true
        type: dict
    password:
        description: Password for username used to get API token
        required: true
        type: str
    site:
        description: URL of the MAAS site (generally ending in /MAAS)
        required: true
        type: str
    username:
        description: Username to get API token for
        required: true
        type: str

# Specify this value according to your collection
# in format of namespace.collection.doc_fragment_name
# extends_documentation_fragment:
#     - my_namespace.my_collection.my_doc_fragment_name

author:
    - Allen Smith (@allsmith-tmo)
"""

EXAMPLES = r"""
# Pass in a message
-  username: user
   password: password
   configs:
     vlans:
        - name: 100
        - name: 200
        - name: 300
"""

RETURN = r"""
# These are examples of possible return values, and in general should use other names for return values.
message:
    description: The output message that the test module generates.
    type: str
    returned: always
    sample: 'goodbye'
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


def get_maas_vlans(session, params):
    current_vlans = session.get(f"{params['site']}/api/2.0/fabrics/0/vlans/")
    current_vlans.raise_for_status()
    return current_vlans.json()


def grab_maas_apikey(site, username, password):
    consumer = "ansible@host"
    uri = "/accounts/authenticate/"

    payload = {
        "username": username,
        "password": password,
        "consumer": consumer,
    }

    return post(site + uri, data=payload)


def run_module():
    # define available arguments/parameters a user can pass to the module
    module_args = dict(
        configs=dict(type="dict", required=True),
        password=dict(type="str", required=True, no_log=True),
        username=dict(type="str", required=True),
        site=dict(type="str", required=True),
    )

    # seed the result dict in the object
    # we primarily care about changed and state
    # changed is if this module effectively modified the target
    # state will include any data that you want your module to pass back
    # for consumption, for example, in a subsequent task
    result = dict(changed=False, message={})

    # the AnsibleModule object will be our abstraction working with Ansible
    # this includes instantiation, a couple of common attr would be the
    # args/params passed to the execution, as well as if the module
    # supports check mode
    module = AnsibleModule(argument_spec=module_args, supports_check_mode=True)

    # if the user is working with this module in only check mode we do not
    # want to make any changes to the environment, just return the current
    # state with no modifications
    if module.check_mode:
        module.exit_json(**result)

    # manipulate or modify the state as needed (this is going to be the
    # part where your module will do what it needs to do)

    r = grab_maas_apikey(
        module.params["site"], module.params["username"], module.params["password"]
    )
    r.raise_for_status()

    c = maas_api_cred(r.json())

    maas_session = OAuth1Session(
        c.client_key,
        resource_owner_key=c.resource_owner_key,
        resource_owner_secret=c.resource_owner_secret,
        signature_method="PLAINTEXT",
    )

    if "vlans" in module.params["configs"].keys():

        current_vlans_dict = {
            item["name"]: item for item in get_maas_vlans(maas_session, module.params)
        }

        vlist = []

        result["message"] = module.params["configs"]["vlans"]

        for vlan in module.params["configs"]["vlans"]:
            if str(vlan["name"]) not in current_vlans_dict.keys():
                vlist.append(vlan["name"])

                # Create a new vlan
                payload = {"name": vlan["name"], "vid": vlan["name"], "fabric_id": "0"}
                r = maas_session.post(
                    module.params["site"] + "/api/2.0/fabrics/0/vlans/", data=payload
                )
                # r.raise_for_status()

                result["changed"] = True

        result["message"] = "Added vlans " + str(vlist)
    else:
        result["message"] = "Did not find vlans in keys"

    # use whatever logic you need to determine whether or not this module
    # made any modifications to your target
    # if module.params["new"]:
    #    result["changed"] = True

    # during the execution of the module, if there is an exception or a
    # conditional state that effectively causes a failure, run
    # AnsibleModule.fail_json() to pass in the message and the result
    # if module.params["name"] == "fail me":
    #    module.fail_json(msg="You requested this to fail", **result)

    # in the event of a successful module execution, you will want to
    # simple AnsibleModule.exit_json(), passing the key/value results
    module.exit_json(**result)


def main():
    run_module()


if __name__ == "__main__":
    main()
