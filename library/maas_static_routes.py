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

STATIC_ROUTE_SUPPORTED_KEYS = ["mtu", "name", "vid"]
STATIC_ROUTE_MODIFY_KEYS = ["mtu", "name"]

__metaclass__ = type

DOCUMENTATION = r"""
---
module: maas_static_routes

short_description: Configure MAAS static_routes

version_added: "1.0.0"

description: Configure MAAS static_routes

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
          - if C(absent) then the static_route(s) will be removed if currently present.
          - if C(present) then the static_route(s) will be created/updated.
          - if C(exact) then the resulting static_route list will match what is passed in.
        required: false
        type: str
        default: present
        choices: [ absent, present, exact ]
    username:
        description: Username to get API token for
        required: true
        type: str
    static_routes:
        description: A list containing static_route specifier dictionaries
        required: true
        type: list
        suboptions:
          mtu:
              description: The MTU of the static_route
              required: false
              default: 1500
              type: str
          name:
              description: The name of the static_route
              required: true
              type: str
          vid:
              description: static_route ID (defaults to O(name))
              required: false
              default: O(name)
              type: str

notes:
   - The API accepts more options for O(static_routes) list members
     however only those mentioned are supported by this
     module.

requirements:
   - requests
   - requests-oauthlib

author:
    - Allen Smith (@asmith-tmo)
"""

EXAMPLES = r"""
# Add 3 static_routes if they don't exist
-  username: user
   password: password
   static_routes:
     - name: 100
     - name: 200
     - name: 300

# Remove two static_routes if they exist
-  username: user
   password: password
   state: absent
   static_routes:
     - name: 200
     - name: 300

# Add/Remove as needed to exactly match given list
-  username: user
   password: password
   state: exact
   static_routes:
     - name: 400
     - name: static_route 500
       vid: 500

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


def static_route_needs_updating(current, wanted):
    """
    Compare two static_route definitions and see if there are differences
    in the fields we allow to be changed
    """
    ret = False
    current_filtered = {
        k: v for k, v in current.items() if k in STATIC_ROUTE_MODIFY_KEYS
    }
    wanted_filtered = {k: v for k, v in wanted.items() if k in STATIC_ROUTE_MODIFY_KEYS}

    for key in wanted_filtered.keys():
        if (key not in current_filtered.keys()) or (
            str(wanted_filtered[key]) != str(current_filtered[key])
        ):
            ret = True

    return ret


def get_maas_static_routes(session, module):
    """
    Grab the current list of static_routes
    NOTE: We only support fabric 0 at this time so it is hard coded.
    """
    try:
        filtered_static_routes = []
        current_static_routes = session.get(
            f"{module.params['site']}/api/2.0/fabrics/0/static_routes/"
        )
        current_static_routes.raise_for_status()

        # filter the list down to keys we support
        for static_route in current_static_routes.json():
            filtered_static_routes.append(
                {
                    k: v
                    for k, v in static_route.items()
                    if k in STATIC_ROUTE_SUPPORTED_KEYS
                }
            )
        return filtered_static_routes
    except exceptions.RequestException as e:
        module.fail_json(
            msg="Failed to get current static_route list: {}".format(str(e))
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


def maas_add_static_routes(
    session, current_static_routes, module_static_routes, module, res
):
    """
    Given a list of static_routes to add, we add those that don't exist
    If they exist, we check if something has changed and if it
    is a parameter that we can update, we call a function to do
    that.
    """
    vlist_added = []
    vlist_updated = []

    for static_route in module_static_routes:
        wanted = {}
        wanted["name"] = static_route["name"]
        wanted["fabric_id"] = 0
        wanted["mtu"] = (
            int(static_route["mtu"]) if "mtu" in static_route.keys() else 1500
        )
        wanted["vid"] = (
            int(static_route["vid"])
            if "vid" in static_route.keys()
            else int(static_route["name"])
        )

        if wanted["vid"] not in current_static_routes.keys():
            if wanted["name"] in current_static_routes.keys():
                module.fail_json(
                    msg=f"Can't change vid for static_route {wanted['name']} from {current_static_routes[wanted['name']]['vid']} to {wanted['vid']}"
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
                        f"{module.params['site']}/api/2.0/fabrics/{wanted['fabric_id']}/static_routes/",
                        data=payload,
                    )
                    r.raise_for_status()
                except exceptions.RequestException as e:
                    module.fail_json(
                        msg=f"static_route Add Failed: {format(str(e))} with payload {format(payload)} and {format(wanted)}"
                    )
        else:
            if static_route_needs_updating(
                current_static_routes[wanted["vid"]], wanted
            ):
                vlist_updated.append(wanted["vid"])
                res["changed"] = True

                if not module.check_mode:
                    payload = {
                        "mtu": wanted["mtu"],
                        "name": wanted["name"],
                    }
                    try:
                        r = session.put(
                            f"{module.params['site']}/api/2.0/fabrics/{wanted['fabric_id']}/static_routes/{wanted['vid']}/",
                            data=payload,
                        )
                        r.raise_for_status()
                    except exceptions.RequestException as e:
                        module.fail_json(
                            msg=f"static_route Update Failed: {format(str(e))} with payload {format(payload)} and {format(wanted)}"
                        )

    new_static_routes_dict = {
        item["vid"]: item for item in get_maas_static_routes(session, module)
    }

    res["diff"] = dict(
        before=safe_dump(current_static_routes),
        after=safe_dump(new_static_routes_dict),
    )

    if vlist_added:
        res["message"].append("Added static_routes: " + str(vlist_added))

    if vlist_updated:
        res["message"].append("Updated static_routes: " + str(vlist_updated))


def maas_delete_static_routes(
    session, current_static_routes, module_static_routes, module, res
):
    """
    Given a list of static_routes to remove, we delete those that exist"
    """
    vlist = []

    for static_route in module_static_routes:
        fabric_id = 0
        vid = (
            int(static_route["vid"])
            if "vid" in static_route.keys()
            else int(static_route["name"])
        )

        if vid in current_static_routes.keys():
            vlist.append(vid)
            res["changed"] = True

            if not module.check_mode:
                try:
                    r = session.delete(
                        f"{module.params['site']}/api/2.0/fabrics/{fabric_id}/static_routes/{vid}/",
                    )
                    r.raise_for_status()
                except exceptions.RequestException as e:
                    module.fail_json(
                        msg=f"static_route Remove Failed: {format(str(e))} with {format(current_static_routes)}"
                    )

                new_static_routes_dict = {
                    item["vid"]: item
                    for item in get_maas_static_routes(session, module)
                }

                res["diff"] = dict(
                    before=safe_dump(current_static_routes),
                    after=safe_dump(new_static_routes_dict),
                )

    if vlist:
        res["message"].append("Removed static_routes: " + str(vlist))


def maas_exact_static_routes(
    session, current_static_routes, module_static_routes, module, res
):
    """
    Given a list of static_routes, remove and add/update as needed
    to make reality match the list
    """
    wanted = []
    wanted_delete = []
    wanted_add_update = []

    for static_route in module_static_routes:
        static_route["vid"] = (
            int(static_route["vid"])
            if "vid" in static_route.keys()
            else int(static_route["name"])
        )
        wanted.append(static_route["vid"])

    module_static_routes_dict = {k["vid"]: k for k in module_static_routes}
    delete_list = [vid for vid in current_static_routes.keys() if vid not in wanted]
    add_list = [vid for vid in wanted if vid not in current_static_routes.keys()]
    update_list = [vid for vid in wanted if vid in current_static_routes.keys()]

    delete_list.remove(0)

    if delete_list:
        wanted_delete = [{"name": k} for k in delete_list]
        maas_delete_static_routes(
            session, current_static_routes, wanted_delete, module, res
        )

    if add_list:
        wanted_add = [module_static_routes_dict[k] for k in add_list]
        maas_add_static_routes(session, current_static_routes, wanted_add, module, res)

    if update_list:
        wanted_update = [module_static_routes_dict[k] for k in update_list]
        maas_add_static_routes(
            session, current_static_routes, wanted_update, module, res
        )


def run_module():
    module_args = dict(
        static_routes=dict(type="list", required=True),
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

    validate_module_parameters(module)

    response = grab_maas_apikey(module)
    api_cred = maas_api_cred(response.json())

    maas_session = OAuth1Session(
        api_cred.client_key,
        resource_owner_key=api_cred.resource_owner_key,
        resource_owner_secret=api_cred.resource_owner_secret,
        signature_method="PLAINTEXT",
    )

    current_static_routes_dict = {
        item["vid"]: item for item in get_maas_static_routes(maas_session, module)
    }

    if module.params["state"] == "present":
        maas_add_static_routes(
            maas_session,
            current_static_routes_dict,
            module.params["static_routes"],
            module,
            result,
        )

    elif module.params["state"] == "absent":
        maas_delete_static_routes(
            maas_session,
            current_static_routes_dict,
            module.params["static_routes"],
            module,
            result,
        )

    elif module.params["state"] == "exact":
        maas_exact_static_routes(
            maas_session,
            current_static_routes_dict,
            module.params["static_routes"],
            module,
            result,
        )

    module.exit_json(**result)


def validate_module_parameters(module):
    """
    Perform simple validations on module parameters
    """
    static_routes = module.params["static_routes"]

    # Detect duplice vids
    vid_list = [
        static_route["vid"] if "vid" in static_route.keys() else static_route["name"]
        for static_route in static_routes
    ]
    if len(vid_list) != len(set(vid_list)):
        static_route_dupes = [
            item for item, count in Counter(vid_list).items() if count > 1
        ]
        module.fail_json(
            msg=f"Duplicate vids handed to us in list of static_routes. Dupes are {static_route_dupes} from: {static_routes}"
        )

    # Detect invalid vids
    invalid_vid_list = [
        vid for vid in vid_list if not type(vid) is int or (vid < 1 or vid > 4094)
    ]
    if len(invalid_vid_list):
        module.fail_json(
            msg=f"Invalid VIDs detected {invalid_vid_list} from: {static_routes}"
        )

    # Detect keys we don't yet handle
    for static_route in static_routes:
        for key in static_route.keys():
            if key not in STATIC_ROUTE_SUPPORTED_KEYS:
                module.fail_json(
                    msg=f"{key} is not a supported key. Possible values {STATIC_ROUTE_SUPPORTED_KEYS}"
                )


def main():
    run_module()


if __name__ == "__main__":
    main()
