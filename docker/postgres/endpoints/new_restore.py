# Copyright 2024-2025 NetCracker Technology Corporation
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import logging
import os
import requests
from requests.exceptions import RequestException

import utils
from flask_restful import Resource
from flask import request
from flask_httpauth import HTTPBasicAuth

auth = HTTPBasicAuth()

@auth.verify_password
def verify(username, password):
    return utils.validate_user(username, password)

def _granular_base():
    protocol = "https" if os.getenv("TLS", "false").lower() == "true" else "http"
    return f"{protocol}://localhost:9000", (protocol == "https")


class NewRestore(Resource):
    __endpoints = ['/api/v1/restore/<backup_id>']

    def __init__(self):
        self.__log = logging.getLogger("NewRestore")

    @staticmethod
    def get_endpoints():
        return NewRestore.__endpoints

    @auth.login_required
    def post(self, backup_id):
        self.__log.debug("Endpoint /api/v1/restore/%s called", backup_id)

        body = request.get_json(silent=True) or {}
        storage_name = body.get("storageName")
        blob_path = body.get("blobPath")
        pairs = body.get("databases") or []

        if not storage_name or not blob_path:
            return {"message": "storageName and blobPath are required"}, 400
        if not isinstance(pairs, (list, tuple)):
            return {"message": "databases must be an array of objects"}, 400

        dbs = []
        dbmap = {}
        for item in pairs:
            prev_name = (item or {}).get("previousDatabaseName")
            curr_name = (item or {}).get("databaseName")
            if not prev_name or not curr_name:
                return {"message": "each databases item must have previousDatabaseName and databaseName"}, 400
            dbs.append(prev_name)          
            dbmap[prev_name] = curr_name      

        granular_req = {
            "backupId": backup_id,
            "databases": dbs,
            "databasesMapping": dbmap
        }

        cred = request.authorization
        base, is_tls = _granular_base()
        try:
            r = requests.post(
                f"{base}/restore/request",
                json=granular_req,
                auth=(cred.username, cred.password) if cred else None,
                verify=False if is_tls else True,
                timeout=30
            )
        except RequestException as e:
            self.__log.exception("Upstream granular /restore/request failed: %s", e)
            return {"message": "Upstream error"}, 502

        try:
            data = r.json()
        except ValueError:
            return {"message": "Upstream returned non-JSON"}, 502

        tracking_id = data.get("trackingId")
        if not tracking_id or r.status_code not in (200, 202):
            return (data if isinstance(data, dict) else {"message": "Upstream error"}), r.status_code

        return {"restoreId": tracking_id}, 202


class NewRestoreStatus(Resource):
    __endpoints = ['/api/v1/restore/<restore_id>']

    def __init__(self):
        self.__log = logging.getLogger("NewRestoreStatus")

    @staticmethod
    def get_endpoints():
        return NewRestoreStatus.__endpoints

    @auth.login_required
    def get(self, restore_id):
        self.__log.debug("Endpoint /api/v1/restore/%s called", restore_id)

        cred = request.authorization
        base, is_tls = _granular_base()
        try:
            r = requests.get(
                f"{base}/restore/status/{restore_id}",
                params=request.args,
                auth=(cred.username, cred.password) if cred else None,
                verify=False if is_tls else True,
                timeout=30
            )
        except RequestException as e:
            self.__log.exception("Upstream granular /restore/status failed: %s", e)
            return {"message": "Upstream error"}, 502

        ctype = r.headers.get("Content-Type", "")
        if ctype.startswith("application/json"):
            return r.json(), r.status_code
        return r.text, r.status_code
    
class NewRestoreDelete(Resource):
    __endpoints = [
        '/api/v1/restore/<restore_id>',
    ]

    def __init__(self):
        self.__log = logging.getLogger("NewRestoreDelete")

    @staticmethod
    def get_endpoints():
        return NewRestoreDelete.__endpoints

    @auth.login_required
    def delete(self, restore_id):
        self.__log.info("DELETE /api/v1/restore/%s", restore_id)
        cred = request.authorization
        base, is_tls = _granular_base()
        try:
            r = requests.post(
                f"{base}/restore/terminate/{restore_id}",
                auth=(cred.username, cred.password) if cred else None,
                verify=False if is_tls else True,
                timeout=30
            )
            ctype = r.headers.get('Content-Type', '')
            if ctype.startswith('application/json'):
                return r.json(), r.status_code
            return r.text, r.status_code
        except requests.RequestException as e:
            self.__log.exception("Proxy to granular restore terminate failed: %s", e)
            return {"message": "Upstream error"}, 502