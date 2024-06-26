#!/usr/bin/python

# Copyright: Allen Smith <asmith687@t-mobile.com>
# License: MIT-0 (See https://opensource.org/license/mit-0)
from __future__ import absolute_import, division, print_function
from ansible.module_utils.basic import missing_required_lib

from collections import Counter
from yaml import safe_dump

try:
    from requests import post, exceptions

    HAS_REQUESTS = True
except:
    HAS_REQUESTS = False

try:
    from requests_oauthlib import OAuth1Session

    HAS_REQUESTS_OAUTHLIB = True
except:
    HAS_REQUESTS_OAUTHLIB = False

NODE_SCRIPT_SUPPORTED_KEYS = ["mtu", "name", "vid"]
NODE_SCRIPT_MODIFY_KEYS = ["mtu", "name"]

__metaclass__ = type

DOCUMENTATION = r"""
---
module: maas_node_scripts

short_description: Configure MAAS node scripts

version_added: "1.0.0"

description: Configure MAAS node scripts

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
        description:
          - if C(absent) then the node script(s) will be removed if currently present.
          - if C(present) then the node script(s) will be created/updated.
          - if C(exact) then the resulting node script list will match what is passed in.
        required: false
        type: str
        default: present
        choices: [ absent, present, exact ]
    username:
        description: Username to get API token for
        required: true
        type: str
    scripts_dir:
        description: Directory where node scripts are located
        required: true
        type: str
    user_scripts:
        description: A list containing node script specifier dictionaries
        required: true
        type: list
        suboptions:
          name:
              description: The name of the node script
              required: true
              type: str
          file:
              description: The location of the node script
              required: true
              type: str

notes:
   - The API accepts more options for O(node_scripts) list members
     however only those mentioned are supported by this
     module.

requirements:
   - requests
   - requests-oauthlib

author:
    - Allen Smith (@asmith-tmo)
"""

EXAMPLES = r"""
# Add 2 node_scripts if they don't exist
-  username: user
   password: password
   script_dir: /root/user_scripts
   node_scripts:
     - name: "script1"
       file: "script1.sh"
     - name: "check health"
       file: "0-check_health.sh"

# Remove two node_scripts if they exist
-  username: user
   password: password
   state: absent
   node_scripts:
     - name: script1
     - name: check health

# Add/Remove as needed to exactly match given list
-  username: user
   password: password
   state: exact
   node_scripts:
     - name: validate app perms
       file: validate_app_perms.sh
     - name: script2.sh
       file: script2.sh

"""

RETURN = r"""
message:
    description: Status messages
    type: list
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


def node_script_needs_updating(current, wanted):
    """
    Compare two node_script definitions and see if there are differences
    in the fields we allow to be changed
    """
    ret = False
    current_filtered = {
        k: v for k, v in current.items() if k in NODE_SCRIPT_MODIFY_KEYS
    }
    wanted_filtered = {k: v for k, v in wanted.items() if k in NODE_SCRIPT_MODIFY_KEYS}

    for key in wanted_filtered.keys():
        if (key not in current_filtered.keys()) or (
            str(wanted_filtered[key]) != str(current_filtered[key])
        ):
            ret = True

    return ret


def get_maas_node_scripts(session, module):
    """
    Grab the current list of node_scripts
    NOTE: We only support fabric 0 at this time so it is hard coded.
    """
    try:
        filtered_node_scripts = []
        current_node_scripts = session.get(f"{module.params['site']}/api/2.0/scripts/")
        current_node_scripts.raise_for_status()

        module.fail_json(msg=f"{current_node_scripts.json()}")

        # filter the list down to keys we support
        for node_script in current_node_scripts.json():
            filtered_node_scripts.append(
                {
                    k: v
                    for k, v in node_script.items()
                    if k in NODE_SCRIPT_SUPPORTED_KEYS
                }
            )
        return filtered_node_scripts
    except exceptions.RequestException as e:
        module.fail_json(
            msg="Failed to get current node_script list: {}".format(str(e))
        )


def grab_maas_apikey(module):
    """
    Connect to MAAS API and grab the 3 part API key
    """
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


def maas_add_node_scripts(
    session, current_node_scripts, module_node_scripts, module, res
):
    """
    Given a list of node_scripts to add, we add those that don't exist
    If they exist, we check if something has changed and if it
    is a parameter that we can update, we call a function to do
    that.
    """
    vlist_added = []
    vlist_updated = []

    for node_script in module_node_scripts:
        wanted = {}
        wanted["name"] = node_script["name"]
        wanted["fabric_id"] = 0
        wanted["mtu"] = int(node_script["mtu"]) if "mtu" in node_script.keys() else 1500
        wanted["vid"] = (
            int(node_script["vid"])
            if "vid" in node_script.keys()
            else int(node_script["name"])
        )

        if wanted["vid"] not in current_node_scripts.keys():
            if wanted["name"] in current_node_scripts.keys():
                module.fail_json(
                    msg=f"Can't change vid for node_script {wanted['name']} from {current_node_scripts[wanted['name']]['vid']} to {wanted['vid']}"
                )

            vlist_added.append(wanted["vid"])
            res["changed"] = True

            if not module.check_mode:
                payload = {
                    "mtu": wanted["mtu"],
                    "name": wanted["name"],
                    "vid": wanted["vid"],
                    "fabric_id": wanted["fabric_id"],
                }
                try:
                    r = session.post(
                        f"{module.params['site']}/api/2.0/fabrics/{wanted['fabric_id']}/node_scripts/",
                        data=payload,
                    )
                    r.raise_for_status()
                except exceptions.RequestException as e:
                    module.fail_json(
                        msg=f"node_script Add Failed: {format(str(e))} with payload {format(payload)} and {format(wanted)}"
                    )
        else:
            if node_script_needs_updating(current_node_scripts[wanted["vid"]], wanted):
                vlist_updated.append(wanted["vid"])
                res["changed"] = True

                if not module.check_mode:
                    payload = {
                        "mtu": wanted["mtu"],
                        "name": wanted["name"],
                    }
                    try:
                        r = session.put(
                            f"{module.params['site']}/api/2.0/fabrics/{wanted['fabric_id']}/node_scripts/{wanted['vid']}/",
                            data=payload,
                        )
                        r.raise_for_status()
                    except exceptions.RequestException as e:
                        module.fail_json(
                            msg=f"node_script Update Failed: {format(str(e))} with payload {format(payload)} and {format(wanted)}"
                        )

    new_node_scripts_dict = {
        item["vid"]: item for item in get_maas_node_scripts(session, module)
    }

    res["diff"] = dict(
        before=safe_dump(current_node_scripts),
        after=safe_dump(new_node_scripts_dict),
    )

    if vlist_added:
        res["message"].append("Added node_scripts: " + str(vlist_added))

    if vlist_updated:
        res["message"].append("Updated node_scripts: " + str(vlist_updated))


def maas_delete_node_scripts(
    session, current_node_scripts, module_node_scripts, module, res
):
    """
    Given a list of node_scripts to remove, we delete those that exist"
    """
    vlist = []

    for node_script in module_node_scripts:
        fabric_id = 0
        vid = (
            int(node_script["vid"])
            if "vid" in node_script.keys()
            else int(node_script["name"])
        )

        if vid in current_node_scripts.keys():
            vlist.append(vid)
            res["changed"] = True

            if not module.check_mode:
                try:
                    r = session.delete(
                        f"{module.params['site']}/api/2.0/fabrics/{fabric_id}/node_scripts/{vid}/",
                    )
                    r.raise_for_status()
                except exceptions.RequestException as e:
                    module.fail_json(
                        msg=f"node_script Remove Failed: {format(str(e))} with {format(current_node_scripts)}"
                    )

                new_node_scripts_dict = {
                    item["vid"]: item for item in get_maas_node_scripts(session, module)
                }

                res["diff"] = dict(
                    before=safe_dump(current_node_scripts),
                    after=safe_dump(new_node_scripts_dict),
                )

    if vlist:
        res["message"].append("Removed node_scripts: " + str(vlist))


def maas_exact_node_scripts(
    session, current_node_scripts, module_node_scripts, module, res
):
    """
    Given a list of node_scripts, remove and add/update as needed
    to make reality match the list
    """
    wanted = []
    wanted_delete = []
    wanted_add_update = []

    for node_script in module_node_scripts:
        node_script["vid"] = (
            int(node_script["vid"])
            if "vid" in node_script.keys()
            else int(node_script["name"])
        )
        wanted.append(node_script["vid"])

    module_node_scripts_dict = {k["vid"]: k for k in module_node_scripts}
    delete_list = [vid for vid in current_node_scripts.keys() if vid not in wanted]
    add_list = [vid for vid in wanted if vid not in current_node_scripts.keys()]
    update_list = [vid for vid in wanted if vid in current_node_scripts.keys()]

    delete_list.remove(0)

    if delete_list:
        wanted_delete = [{"name": k} for k in delete_list]
        maas_delete_node_scripts(
            session, current_node_scripts, wanted_delete, module, res
        )

    if add_list:
        wanted_add = [module_node_scripts_dict[k] for k in add_list]
        maas_add_node_scripts(session, current_node_scripts, wanted_add, module, res)

    if update_list:
        wanted_update = [module_node_scripts_dict[k] for k in update_list]
        maas_add_node_scripts(session, current_node_scripts, wanted_update, module, res)


def run_module():
    module_args = dict(
        script_dir=dict(type="str", required=True),
        user_scripts=dict(type="list", required=True),
        password=dict(type="str", required=True, no_log=True),
        username=dict(type="str", required=True),
        site=dict(type="str", required=True),
        state=dict(type="str", required=False, default="present"),
    )

    result = dict(changed=False, message=[], diff={})

    module = AnsibleModule(argument_spec=module_args, supports_check_mode=True)

    if not HAS_REQUESTS:
        module.fail_json(msg=missing_required_lib("requests"))

    if not HAS_REQUESTS_OAUTHLIB:
        module.fail_json(msg=missing_required_lib("requests_oauthlib"))

    # validate_module_parameters(module)

    response = grab_maas_apikey(module)
    api_cred = maas_api_cred(response.json())

    maas_session = OAuth1Session(
        api_cred.client_key,
        resource_owner_key=api_cred.resource_owner_key,
        resource_owner_secret=api_cred.resource_owner_secret,
        signature_method="PLAINTEXT",
    )

    current_node_scripts_dict = {
        item["vid"]: item for item in get_maas_node_scripts(maas_session, module)
    }

    if module.params["state"] == "present":
        maas_add_node_scripts(
            maas_session,
            current_node_scripts_dict,
            module.params["node_scripts"],
            module,
            result,
        )

    elif module.params["state"] == "absent":
        maas_delete_node_scripts(
            maas_session,
            current_node_scripts_dict,
            module.params["node_scripts"],
            module,
            result,
        )

    elif module.params["state"] == "exact":
        maas_exact_node_scripts(
            maas_session,
            current_node_scripts_dict,
            module.params["node_scripts"],
            module,
            result,
        )

    module.exit_json(**result)


def validate_module_parameters(module):
    """
    Perform simple validations on module parameters
    """
    node_scripts = module.params["node_scripts"]

    # Detect duplice vids
    vid_list = [
        node_script["vid"] if "vid" in node_script.keys() else node_script["name"]
        for node_script in node_scripts
    ]
    if len(vid_list) != len(set(vid_list)):
        node_script_dupes = [
            item for item, count in Counter(vid_list).items() if count > 1
        ]
        module.fail_json(
            msg=f"Duplicate vids handed to us in list of node_scripts. Dupes are {node_script_dupes} from: {node_scripts}"
        )

    # Detect invalid vids
    invalid_vid_list = [
        vid for vid in vid_list if not type(vid) is int or (vid < 1 or vid > 4094)
    ]
    if len(invalid_vid_list):
        module.fail_json(
            msg=f"Invalid VIDs detected {invalid_vid_list} from: {node_scripts}"
        )

    # Detect keys we don't yet handle
    for node_script in node_scripts:
        for key in node_script.keys():
            if key not in NODE_SCRIPT_SUPPORTED_KEYS:
                module.fail_json(
                    msg=f"{key} is not a supported key. Possible values {NODE_SCRIPT_SUPPORTED_KEYS}"
                )


def main():
    run_module()


if __name__ == "__main__":
    main()
