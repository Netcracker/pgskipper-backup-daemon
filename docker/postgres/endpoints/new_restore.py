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
from requests.exceptions import HTTPError

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
    __endpoints = [
        '/api/v1/restore/<backup_id>',
    ]

    def __init__(self):
        self.__log = logging.getLogger("NewRestore")

    @staticmethod
    def get_endpoints():
        return NewRestore.__endpoints

    @auth.login_required
    def post(self, backup_id):
        self.__log.debug("Endpoint /api/v1/restore/%s called", backup_id)
        cred = request.authorization
        body = request.get_json() or {}
        body['backupId'] = backup_id 
        base, is_tls = _granular_base()
        try:
            r = requests.post(
                f"{base}/restore/request",
                json=body,
                auth=(cred.username, cred.password) if cred else None,
                verify=False if is_tls else True
            )
            if r.headers.get('Content-Type', '').startswith('application/json'):
                data = r.json()
                if isinstance(data, dict) and 'trackingId' in data:
                    data = {'restoreId': data['trackingId']}
                return data, r.status_code
            return r.text, r.status_code
        except HTTPError as e:
            self.__log.exception("Proxying to granular /restore/request failed", e)
            return {"message": "Upstream error"}, 502


class NewRestoreStatus(Resource):
    __endpoints = [
        '/api/v1/restore/<restore_id>',
    ]

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
                verify=False if is_tls else True
            )
            if r.headers.get('Content-Type', '').startswith('application/json'):
                return r.json(), r.status_code
            return r.text, r.status_code
        except HTTPError as e:
            self.__log.exception("Proxying to granular /restore/status failed", e)
            return {"message": "Upstream error"}, 502