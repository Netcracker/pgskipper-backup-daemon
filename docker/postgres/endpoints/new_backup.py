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

class NewBackup(Resource):

    __endpoints = [
        '/api/v1/backup',  
    ]

    def __init__(self):
        self.__log = logging.getLogger("NewBackup")

    @staticmethod
    def get_endpoints():
        return NewBackup.__endpoints

    @auth.login_required
    def post(self):
        self.__log.debug("Endpoint /api/v1/backup called")
        body = request.get_json() or {}
        cred = request.authorization
        base, is_tls = _granular_base()
        try:
            r = requests.post(
                f"{base}/backup/request",
                json=body,
                auth=(cred.username, cred.password) if cred else None,
                verify=False if is_tls else True
            )
            if r.headers.get('Content-Type', '').startswith('application/json'):
                return r.json(), r.status_code
            return r.text, r.status_code
        except HTTPError as e:
            self.__log.exception("Proxying to granular /backup/request failed", e)
            return {"message": "Upstream error"}, 502
        

class NewBackupStatus(Resource):
    __endpoints = [
        '/api/v1/backup/<backup_id>',
    ]

    def __init__(self):
        self.__log = logging.getLogger("NewBackupStatus")

    @staticmethod
    def get_endpoints():
        return NewBackupStatus.__endpoints

    @auth.login_required
    def get(self, backup_id):
        self.__log.debug("Endpoint /api/v1/backup/%s called", backup_id)
        cred = request.authorization
        base, is_tls = _granular_base()
        try:
            r = requests.get(
                f"{base}/backup/status/{backup_id}",
                params=request.args, 
                auth=(cred.username, cred.password) if cred else None,
                verify=False if is_tls else True
            )
            if r.headers.get('Content-Type', '').startswith('application/json'):
                return r.json(), r.status_code
            return r.text, r.status_code
        except HTTPError as e:
            self.__log.exception("Proxying to granular /backup/status failed", e)
            return {"message": "Upstream error"}, 502