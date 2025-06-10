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

import http.client
import json
import logging
import os
import io

import flask
import flask_restful
from flask import Flask
from apscheduler.schedulers.background import BackgroundScheduler

import requests
import backups
import configs
import pg_backup
import pg_restore
import utils
import storage_s3
import psycopg2
import threading
from functools import wraps

import shutil
from backups import build_backup_path, build_namespace_path, is_valid_namespace, build_backup_status_file_path
from flask_httpauth import HTTPBasicAuth

from flask import request, abort, Response, stream_with_context

from opentelemetry.instrumentation.flask import FlaskInstrumentor
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.sdk.resources import SERVICE_NAME, Resource


auth = HTTPBasicAuth()


def superuser_authorization(func_to_decorate):
    @wraps(func_to_decorate)
    def wrap(self, *args, **kwargs):
        if utils.is_auth_needed():
            if request.authorization.username == configs.postgresql_user():
                return func_to_decorate(self, *args, **kwargs)
            else:
                abort(403, 'You are not authorized to perform such action')
        else:
            return func_to_decorate(self, *args, **kwargs)

    return wrap


@auth.verify_password
def authenticate_user(username, password):
    if utils.is_auth_needed():

        connection_properties = configs.connection_properties(username=username, password=password)
        connect = None
        try:
            connect = psycopg2.connect(**connection_properties)
            connect.cursor()
            return True
        except psycopg2.Error:
            return False
        finally:
            if connect:
                connect.close()
    else:
        return True


def common_authorization(func_to_decorate):
    @wraps(func_to_decorate)
    def wrap(self, *args, **kwargs):
        if utils.is_auth_needed():
            content_type = request.headers.get('Content-Type')

            if content_type and content_type.split(";")[0] != 'application/json' \
                    and request.headers.get('Content-Length'):
                return "Invalid request body: Content Type is not json", http.client.BAD_REQUEST

            backup_request = request.get_json() or {}

            for k in list(backup_request.keys()):
                if k not in self.allowed_fields:
                    return "Unknown field: %s" % k.encode('utf-8'), http.client.BAD_REQUEST

            databases = backup_request.get('databases') or []

            cred = request.authorization
            if not cred:
                abort(401, 'Credentials should be provided for this endpoint')

            databases_count = len(databases)
            if databases_count == 1:
                dbname = databases[0]
                connection_properties = \
                    configs.connection_properties(username=cred.username, password=cred.password, database='postgres')
                connect = None
                try:
                    connect = psycopg2.connect(**connection_properties)
                    with connect.cursor() as cur:
                        cur.execute("""
                            SELECT pg_catalog.pg_get_userbyid(d.datdba) as Owner
                            FROM pg_catalog.pg_database d WHERE d.datname = %s
                            ORDER BY 1;
                            """, (dbname,))
                        database_owner = cur.fetchone()[0]
                        if database_owner == cred.username:
                            return func_to_decorate(self, *args, **kwargs)
                        else:
                            abort(403, 'You are not authorized to perform such action')
                finally:
                    if connect:
                        connect.close()
            elif not cred.username == configs.postgresql_user():
                abort(403, 'You are not authorized to perform such action')
            else:
                return func_to_decorate(self, *args, **kwargs)
        else:
            return func_to_decorate(self, *args, **kwargs)

    return wrap


if os.getenv("DEBUG") and os.getenv("DEBUG").lower() == 'true':
    logging.getLogger().setLevel(logging.DEBUG)


def schedule_granular_backup(scheduler):
    cron_pattern = configs.granular_cron_pattern()
    if cron_pattern.lower() != 'none' and os.getenv("GRANULAR_BACKUP_SCHEDULE") != "":
        if utils.is_mirror_env():
            logging.info('It is a mirror env')
            return
        logging.info('Start schedule granular backup')
        databases = configs.dbs_to_granular_backup()
        backup_request = {'databases': databases, 'namespace': 'schedule'}
        items = cron_pattern.split(' ', 5)
        minute, hour, day, month, day_of_week = items[0], items[1], items[2], items[3], items[4]

        granular_backup_request = GranularBackupRequestEndpoint()

        return scheduler.add_job(
            granular_backup_request.perform_granular_backup,
            'cron',
            [backup_request],
            minute=minute,
            hour=hour,
            day=day,
            month=month,
            day_of_week=day_of_week)


def schedule_diff_backup(scheduler):
    cron_pattern = configs.diff_cron_pattern()
    logging.info(f'DIFF SHEDULE {os.getenv("DIFF_SCHEDULE")}')
    if cron_pattern.lower() != 'none' and os.getenv("DIFF_SCHEDULE") is not None:
        logging.info('Start schedule diff backup')
        items = cron_pattern.split(' ', 5)
        logging.info(f"{items} cron items")
        minute, hour, day, month, day_of_week = items[0], items[1], items[2], items[3], items[4]

        diff_backup_request = DiffBackupRequestEndpoint()

        return scheduler.add_job(
            diff_backup_request.perform_diff_backup,
            'cron',
            minute=minute,
            hour=hour,
            day=day,
            month=month,
            day_of_week=day_of_week)

def schedule_incr_backup(scheduler):
    cron_pattern = configs.incr_cron_pattern()
    logging.info(f'INCR SHEDULE {os.getenv("INCR_SCHEDULE")}')
    if cron_pattern.lower() != 'none' and os.getenv("INCR_SCHEDULE") is not None:
        logging.info('Start schedule incr backup')
        items = cron_pattern.split(' ', 5)
        logging.info(f"{items} cron items")
        minute, hour, day, month, day_of_week = items[0], items[1], items[2], items[3], items[4]

        incr_backup_request = IncrBackupRequestEndpoint()

        return scheduler.add_job(
            incr_backup_request.perform_incr_backup,
            'cron',
            minute=minute,
            hour=hour,
            day=day,
            month=month,
            day_of_week=day_of_week)

class GranularBackupsListEndpoint(flask_restful.Resource):

    def __init__(self):
        self.log = logging.getLogger('BackupsListEndpoint')
        self.s3 = storage_s3.AwsS3Vault() if os.environ['STORAGE_TYPE'] == "s3" else None

    @auth.login_required
    def get(self):
        # for gke full backup
        # if os.getenv("GOOGLE_APPLICATION_CREDENTIALS"):
        #     self.log.info('Getting GKE backup list')
        #     client = utils.GkeBackupApiCaller()
        #     response = client.backup_list()
        #     return response
        status = {}
        storage = configs.backups_storage()

        if self.s3:
            if not self.s3.is_s3_storage_path_exist(storage):
                return "Backups in s3 storage does not exist.", http.client.NOT_FOUND
            namespaces = self.s3.get_granular_namespaces(storage)
        elif not os.path.exists(storage):
            return "Backups storage does not exist.", http.client.NOT_FOUND

        for namespace in os.listdir(storage) if not self.s3 else namespaces:
            if not backups.is_valid_namespace(namespace):
                continue

            status[namespace] = {}
            if self.s3:
                backup_ids = self.s3.get_backup_ids(storage, namespace)
            for backup in os.listdir(backups.build_namespace_path(namespace)) if not self.s3 else backup_ids:
                status_file = backups.build_backup_status_file_path(backup, namespace)
                if self.s3:
                    try:
                        if self.s3.is_file_exists(status_file):
                            status_file = self.s3.read_object(status_file)
                            backup_status = json.loads(status_file)
                            status[namespace][backup] = {
                                'status': backup_status.get('status'),
                                'created': backup_status.get('created'),
                                'expirationDate': backup_status.get('expirationDate')
                            }
                        else:
                            self.log.error("Cannot find status file in bucket with backup id {}".format(backup))
                            status[namespace][backup] = {'status': 'Unknown'}

                    except ValueError:
                        self.log.exception("Cannot read status file")
                        status[namespace][backup] = {'status': 'Unknown'}

                elif os.path.isfile(status_file):
                    with open(status_file, 'r') as f:
                        try:
                            backup_status = json.load(f)
                            status[namespace][backup] = {
                                'status': backup_status.get('status'),
                                'created': backup_status.get('created'),
                                'expirationDate': backup_status.get('expirationDate')
                            }
                        except ValueError:
                            self.log.exception("Cannot read status file")
                            status[namespace][backup] = {'status': 'Unknown'}
                else:
                    status[namespace][backup] = {'status': 'Unknown'}

        return status, http.client.OK


class GranularBackupRequestEndpoint(flask_restful.Resource):

    def __init__(self):
        self.log = logging.getLogger('BackupRequestEndpoint')
        self.allowed_fields = ['backupId',
                               'namespace',
                               'databases',
                               'keep',
                               'compressionLevel',
                               'externalBackupPath']

    def perform_granular_backup(self, backup_request):
        # # for gke full backup
        # if os.getenv("GOOGLE_APPLICATION_CREDENTIALS"):
        #     self.log.info('Perform GKE backup')
        #     client = utils.GkeBackupApiCaller()
        #     backup_id = client.perform_backup()
        #     if "error" not in backup_id:
        #         return {
        #             'backupId': backup_id
        #         }, http.client.ACCEPTED
        #     else:
        #         return backup_id, http.client.BAD_REQUEST

        self.log.info('Perform granular backup')

        for k in list(backup_request.keys()):
            if k not in self.allowed_fields:
                self.log.exception("Unknown field: %s" % k.encode('utf-8'))
                return "Unknown field: %s" % k.encode('utf-8'), http.client.BAD_REQUEST

        databases = backup_request.get('databases') or []
        namespace = backup_request.get('namespace') or configs.default_namespace()
        if databases:
            baselist = utils.get_database_list(databases)

        if not isinstance(databases, list) and not isinstance(databases, tuple):
            self.log.exception("Field 'database' must be an array.")
            return "Field 'database' must be an array.", http.client.BAD_REQUEST

        if not backups.is_valid_namespace(namespace):
            self.log.exception("Invalid namespace name: %s." % namespace.encode('utf-8'))
            return "Invalid namespace name: %s." % namespace.encode('utf-8'), http.client.BAD_REQUEST

        for database in databases:
            if backups.is_database_protected(database):
                self.log.exception("Database '%s' is not suitable for backup/restore." % database)
                return "Database '%s' is not suitable for backup/restore." % database, http.client.FORBIDDEN

            if database not in baselist:
                self.log.exception("Database '%s' does not exist" % database)
                return "Database '%s' does not exist" % database, http.client.BAD_REQUEST

        backup_id = backups.generate_backup_id()
        backup_request['backupId'] = backup_id

        worker = pg_backup.PostgreSQLDumpWorker(databases, backup_request)

        worker.start()

        return {
                   'backupId': backup_id
               }, http.client.ACCEPTED

    @auth.login_required
    @common_authorization
    def post(self):
        content_type = request.headers.get('Content-Type')

        if content_type and content_type.split(";")[0] != 'application/json' \
                and request.headers.get('Content-Length'):
            return "Invalid request body: Content Type is not json", http.client.BAD_REQUEST

        backup_request = request.get_json() or {}

        return self.perform_granular_backup(backup_request)


class GranularBackupStatusEndpoint(flask_restful.Resource):

    def __init__(self):
        self.log = logging.getLogger('BackupRequestEndpoint')
        self.s3 = storage_s3.AwsS3Vault() if os.environ['STORAGE_TYPE'] == "s3" else None

    @auth.login_required
    def get(self, backup_id):
        if not backup_id:
            return "Backup ID is not specified.", http.client.BAD_REQUEST
        # for gke full backup
        # if os.getenv("GOOGLE_APPLICATION_CREDENTIALS"):
        #     self.log.info('Getting GKE backup status')
        #     client = utils.GkeBackupApiCaller()
        #     response = client.backup_status(backup_id)
        #     return response

        namespace = flask.request.args.get('namespace') or configs.default_namespace()

        if not backups.is_valid_namespace(namespace):
            return "Invalid namespace name: %s." % namespace.encode('utf-8'), http.client.BAD_REQUEST

        external_backup_path = flask.request.args.get('externalBackupPath') or None
        external_backup_root = None
        if external_backup_path is not None:
            external_backup_root = backups.build_external_backup_root(external_backup_path)
        backup_status_file = backups.build_backup_status_file_path(backup_id, namespace, external_backup_root)
        if self.s3:
            try:
                status = self.s3.read_object(backup_status_file)
                logging.info(status)

            except:
                return "Backup in bucket is not found.", http.client.NOT_FOUND
            return json.loads(status), http.client.OK
        else:
            if not os.path.isfile(backup_status_file):
                return "Backup is not found.", http.client.NOT_FOUND

            return utils.get_json_by_path(backup_status_file), http.client.OK


class GranularBackupStatusJSONEndpoint(flask_restful.Resource):

    def __init__(self):
        self.log = logging.getLogger('BackupRequestEndpoint')
        self.allowed_fields = ['backupId', 'namespace', 'externalBackupPath']
        self.s3 = storage_s3.AwsS3Vault() if os.environ['STORAGE_TYPE'] == "s3" else None

    @auth.login_required
    def post(self):
        backup_request = flask.request.get_json() or {}

        for k in list(backup_request.keys()):
            if k not in self.allowed_fields:
                return "Unknown field: %s" % k.encode('utf-8'), http.client.BAD_REQUEST

        backup_id = backup_request.get('backupId')
        namespace = backup_request.get('namespace') or configs.default_namespace()

        if not backups.is_valid_namespace(namespace):
            return "Invalid namespace name: %s." % namespace.encode('utf-8'), http.client.BAD_REQUEST

        if not backup_request:
            return "Request body is empty.", http.client.BAD_REQUEST

        if not backup_id:
            return "Backup ID is not specified.", http.client.BAD_REQUEST

        external_backup_path = backup_request.get('externalBackupPath')
        external_backup_root = None
        if external_backup_path is not None:
            external_backup_root = backups.build_external_backup_root(external_backup_path)
        status_path = backups.build_backup_status_file_path(backup_id, namespace, external_backup_root)

        if self.s3:
            try:
                status = self.s3.read_object(status_path)
                logging.info(status)

            except:
                return "Backup in bucket is not found.", http.client.NOT_FOUND
            return json.loads(status), http.client.OK
        else:
            if not os.path.isfile(status_path):
                return "Backup is not found.", http.client.NOT_FOUND

            with open(status_path) as f:
                return json.load(f), http.client.OK


class GranularRestoreRequestEndpoint(flask_restful.Resource):

    def __init__(self):
        self.log = logging.getLogger('BackupRequestEndpoint')
        self.allowed_fields = ['backupId', 'namespace', 'databases', 'force', 'restoreRoles', 'databasesMapping',
                               'externalBackupPath', 'singleTransaction', "dbaasClone"]
        self.s3 = storage_s3.AwsS3Vault() if os.environ['STORAGE_TYPE'] == "s3" else None

    @auth.login_required
    @superuser_authorization
    def post(self):
        restore_request = flask.request.get_json() or {}
        # for gke full backup
        # if os.getenv("GOOGLE_APPLICATION_CREDENTIALS"):
        #     self.log.info('Perform GKE restore')
        #     client = utils.GkeBackupApiCaller()
        #     response = client.restore(restore_request)
        #     return response

        for k in list(restore_request.keys()):
            if k not in self.allowed_fields:
                return "Unknown field: %s" % k.encode('utf-8'), http.client.BAD_REQUEST

        databases = restore_request.get('databases') or []
        databases_mapping = restore_request.get('databasesMapping') or {}

        if not isinstance(databases, list) and not isinstance(databases, tuple):
            return "Field 'database' must be an array.", http.client.BAD_REQUEST

        if not isinstance(databases_mapping, dict):
            return "Field 'database_mapping' must be a dictionary.", http.client.BAD_REQUEST

        backup_id = restore_request.get('backupId')
        if not backup_id:
            return "Backup ID is not specified.", http.client.BAD_REQUEST

        namespace = restore_request.get('namespace') or configs.default_namespace()

        if not backups.is_valid_namespace(namespace):
            return "Invalid namespace name: %s." % namespace.encode('utf-8'), http.client.BAD_REQUEST

        external_backup_path = restore_request.get('externalBackupPath')
        external_backup_root = None
        if external_backup_path is not None:
            external_backup_root = backups.build_external_backup_root(external_backup_path)
        backup_details_file = backups.build_backup_status_file_path(backup_id, namespace, external_backup_root)

        if self.s3:
            try:
                status = self.s3.read_object(backup_details_file)
            except:
                return "Backup in bucket is not found.", http.client.NOT_FOUND
            backup_details = json.loads(status)

        else:
            if not os.path.isfile(backup_details_file):
                return "Backup is not found.", http.client.NOT_FOUND

            with open(backup_details_file, 'r') as f:
                backup_details = json.load(f)

        backup_status = backup_details['status']

        if backup_status != backups.BackupStatus.SUCCESSFUL:
            return "Backup status '%s' is unsuitable status for restore." % backup_status, http.client.FORBIDDEN
        if self.s3:
            databases = list(backup_details.get('databases', {}).keys())
            for database in databases:
                if not self.s3.is_file_exists(backups.build_database_backup_path(backup_id, database,
                                                                                 namespace, external_backup_root)):
                    return "Backup in bucket is not found.", http.client.NOT_FOUND
        elif not backups.backup_exists(backup_id, namespace, external_backup_root):
            return "Backup is not found.", http.client.NOT_FOUND

        ghost_databases = []
        uncompleted_backups = []

        databases = restore_request.get('databases') or list(backup_details.get('databases', {}).keys())

        # dict of owners {"db": "db_owner", ..}
        owners_mapping = {}

        for database in databases:
            database_details = backup_details['databases'].get(database)
            if not database_details:
                ghost_databases.append(database)
                continue
            if database_details['status'] != backups.BackupStatus.SUCCESSFUL:
                uncompleted_backups.append((database, database_details['status']))
                continue

            owners_mapping[database] = database_details.get('owner', 'postgres')

        if ghost_databases:
            return "Databases are not found: %s." % ', '.join([db.encode('utf-8') for db in ghost_databases]), \
                   http.client.NOT_FOUND

        if uncompleted_backups:
            return "Database backup is in unsuitable status for restore: %s." \
                   % ', '.join(['%s: %s' % (i[0].encode('utf-8'), i[1]) for i in uncompleted_backups]), \
                   http.client.FORBIDDEN

        tracking_id = backups.generate_restore_id(backup_id, namespace)
        restore_request['trackingId'] = tracking_id

        # force is false by default
        force = False
        force_param = restore_request.get('force')

        if force_param:
            if isinstance(force_param, str):
                force = force_param == 'true'
            elif type(force_param) is bool:
                force = force_param


        # restore_roles is true by default
        restore_roles = True
        restore_roles_param = restore_request.get('restoreRoles', True)

        if restore_roles_param:
            if isinstance(restore_roles_param, str):
                restore_roles = restore_roles_param == 'true'
            elif type(restore_roles_param) is bool:
                restore_roles = restore_roles_param
        single_transaction = False
        single_transaction_param = restore_request.get('singleTransaction', True)
        if single_transaction_param:
            if isinstance(single_transaction_param, str):
                single_transaction = single_transaction_param == 'true'
        elif type(single_transaction_param) is bool:
            single_transaction = single_transaction_param

        is_dbaas_clone= restore_request.get('dbaasClone')
        worker = pg_restore.PostgreSQLRestoreWorker(databases, force, restore_request, databases_mapping,
                                                    owners_mapping, restore_roles,single_transaction, is_dbaas_clone)

        worker.start()

        return {
                   'trackingId': tracking_id
               }, http.client.ACCEPTED


class TerminateBackupEndpoint(flask_restful.Resource):

    def __init__(self):
        self.log = logging.getLogger("TerminateBackupEndpoint")

    @auth.login_required
    def post(self, backup_id):
        self.log.info("Terminate request accepted for backup {}".format(backup_id))
        cancelled = False

        try:
            for thread in threading.enumerate():
                if thread.name == str(backup_id):
                    thread.cancel()
                    cancelled = thread.is_cancelled()
            if cancelled:
                self.log.info("Backup {} terminated successfully".format(thread.name))
                return Response("Backup %s terminated successfully\n" % backup_id, status=200)
            else:
                self.log.info("There is no active backup with id {}".format(backup_id))
                return Response("There is no active backup with id: %s\n" % backup_id, status=404)
        except Exception as e:
            self.log.exception("Backup {0} termination failed. \n {1}".format(backup_id, str(e)))
            return Response("Backup {} termination failed".format(backup_id), status=500)


class TerminateRestoreEndpoint(flask_restful.Resource):

    def __init__(self):
        self.log = logging.getLogger("TerminateRestoreEndpoint")

    @auth.login_required
    def post(self, tracking_id):
        self.log.info("Terminate request accepted for id {}".format(tracking_id))
        cancelled = False

        try:
            for thread in threading.enumerate():
                if thread.name == str(tracking_id):
                    thread.cancel()
                    cancelled = thread.is_cancelled()
            if cancelled:
                self.log.info("Restore {} terminated successfully".format(thread.name))
                return Response("Restore %s terminated successfully\n" % tracking_id, status=200)
            else:
                self.log.info("There is no active restore with id {}".format(tracking_id))
                return Response("There is no active backup with id: %s\n" % tracking_id, status=404)
        except Exception as e:
            self.log.exception("Restore {0} termination failed. \n {1}".format(tracking_id, str(e)))
            return Response("Restore {} termination failed".format(tracking_id), status=500)

class GranularRestoreStatusEndpoint(flask_restful.Resource):

    def __init__(self):
        self.log = logging.getLogger('BackupRequestEndpoint')
        self.s3 = storage_s3.AwsS3Vault() if os.environ['STORAGE_TYPE'] == "s3" else None

    @auth.login_required
    @superuser_authorization
    def get(self, tracking_id):
        if not tracking_id:
            return http.client.BAD_REQUEST, "Restore tracking ID is not specified."

        # for gke full backup
        # if os.getenv("GOOGLE_APPLICATION_CREDENTIALS"):
        #     self.log.info('Getting GKE restore status')
        #     client = utils.GkeBackupApiCaller()
        #     response = client.restore_status(tracking_id)
        #     return response

        try:
            backup_id, namespace = backups.extract_backup_id_from_tracking_id(tracking_id)
        except Exception as e:
            self.log.exception(e)
            return 'Malformed restore tracking ID.', http.client.BAD_REQUEST

        external_backup_path = flask.request.args.get('externalBackupPath') or None
        external_backup_root = None
        if external_backup_path is not None:
            external_backup_root = backups.build_external_backup_root(external_backup_path)
        restore_status_file = backups.build_restore_status_file_path(backup_id, tracking_id, namespace,
                                                                     external_backup_root)

        if not backups.is_valid_namespace(namespace):
            return "Invalid namespace name: %s." % namespace.encode('utf-8'), http.client.BAD_REQUEST
        if self.s3:
            try:
                status = self.s3.read_object(restore_status_file)
                logging.info(status)

            except:
                return "Backup in bucket is not found.", http.client.NOT_FOUND
            return json.loads(status), http.client.OK
        else:
            if not os.path.isfile(restore_status_file):
                return "Restore is not found.", http.client.NOT_FOUND

            return utils.get_json_by_path(restore_status_file), http.client.OK


class GranularRestoreStatusJSONEndpoint(flask_restful.Resource):

    def __init__(self):
        self.log = logging.getLogger('BackupRequestEndpoint')
        self.allowed_fields = ['trackingId', 'externalBackupPath']
        self.s3 = storage_s3.AwsS3Vault() if os.environ['STORAGE_TYPE'] == "s3" else None

    @auth.login_required
    @superuser_authorization
    def post(self):
        tracking_request = flask.request.get_json() or {}

        for k in list(tracking_request.keys()):
            if k not in self.allowed_fields:
                return "Unknown field: %s" % k.encode('utf-8'), http.client.BAD_REQUEST

        if not tracking_request:
            return "Restore tracking request has empty body.", http.client.BAD_REQUEST

        tracking_id = tracking_request.get('trackingId')

        if not tracking_id:
            return "Restore tracking ID is not specified.", http.client.BAD_REQUEST

        try:
            backup_id, namespace = backups.extract_backup_id_from_tracking_id(tracking_id)
        except Exception as e:
            self.log.exception(e)
            return 'Malformed restore tracking ID.', http.client.BAD_REQUEST

        external_backup_path = tracking_request.get('externalBackupPath')
        external_backup_root = None
        if external_backup_path is not None:
            external_backup_root = backups.build_external_backup_root(external_backup_path)
        restore_status_file = backups.build_restore_status_file_path(backup_id, tracking_id, namespace,
                                                                     external_backup_root)
        if self.s3:
            try:
                status = self.s3.read_object(restore_status_file)
                logging.info(status)

            except:
                return "Backup in bucket is not found.", http.client.NOT_FOUND
            return json.loads(status), http.client.OK
        else:
            if not os.path.isfile(restore_status_file):
                return "Restore is not found.", http.client.NOT_FOUND

            with open(restore_status_file) as f:
                return json.load(f), http.client.OK


class GranularBackupDeleteEndpoint(flask_restful.Resource):

    def __init__(self):
        self.log = logging.getLogger('GranularBackupDeleteEndpoint')
        self.s3 = storage_s3.AwsS3Vault() if os.environ['STORAGE_TYPE'] == "s3" else None

    @auth.login_required
    @superuser_authorization
    def get(self, backup_id):
        return self.process_delete(backup_id)

    @auth.login_required
    @superuser_authorization
    def post(self, backup_id):
        return self.process_delete(backup_id)

    def process_delete(self, backup_id):
        self.log.info("Request to delete backup %s" % backup_id)
        if not backup_id:
            return self.response(backup_id,
                                 "Backup ID is not specified.",
                                 backups.BackupStatus.FAILED,
                                 http.client.BAD_REQUEST)

        # for gke full backup
        # if os.getenv("GOOGLE_APPLICATION_CREDENTIALS"):
        #     self.log.info('Perform GKE backup delete')
        #     client = utils.GkeBackupApiCaller()
        #     response = client.delete_backup(backup_id)
        #     return response

        namespace = flask.request.args.get('namespace') or configs.default_namespace()

        if not is_valid_namespace(namespace):
            return self.response(backup_id,
                                 "Invalid namespace name: %s." % namespace.encode('utf-8'),
                                 backups.BackupStatus.FAILED,
                                 http.client.BAD_REQUEST)

        backup_status_file = build_backup_status_file_path(backup_id, namespace)
        if self.s3:
            try:
                self.s3.read_object(backup_status_file)
            except:
                return "Backup in bucket is not found.", http.client.NOT_FOUND

        elif not os.path.isfile(backup_status_file):
            return self.response(backup_id,
                                 "Backup is not found.",
                                 backups.BackupStatus.FAILED,
                                 http.client.NOT_FOUND)

        try:
            dir = build_backup_path(backup_id, namespace)
            if self.s3:
                self.s3.delete_objects(dir)
            else:
                terminate = TerminateBackupEndpoint()
                terminate.post(backup_id)
                shutil.rmtree(dir)

                # remove namespace dir if no more backups in namespace
                backup_list = os.listdir(build_namespace_path(namespace))
                if len(backup_list) == 0 and namespace != 'default':
                    shutil.rmtree(build_namespace_path(namespace))

        except Exception as e:
            self.log.exception(e)
            return self.response(backup_id,
                                 'An error occurred while deleting backup {} : {}.'.format(backup_id, e),
                                 backups.BackupStatus.FAILED,
                                 http.client.INTERNAL_SERVER_ERROR)

        return self.response(backup_id, "Backup deleted successfully.", backups.BackupStatus.SUCCESSFUL, http.client.OK)

    def response(self, backup_id, message, status, code):
        return {
                   'backupId': backup_id,
                   'message': message,
                   'status': status
               }, code


class GranularBackupHealthEndpoint(flask_restful.Resource):

    def __init__(self):
        self.log = logging.getLogger('GranularBackupHealthEndpoint')
        self.s3 = storage_s3.AwsS3Vault() if os.environ['STORAGE_TYPE'] == "s3" else None

    def get(self):

        status = {}
        namespace = "schedule"
        status[namespace] = {}

        namespace_path = backups.build_namespace_path(namespace)
        if not os.path.exists(namespace_path):
            return status, http.client.OK

        sorted_backups = sorted(os.listdir(namespace_path), reverse=True)
        dump_count = len(sorted_backups)
        space = os.statvfs(namespace_path)
        free_space, total_space = space.f_bfree * space.f_bsize, space.f_blocks * space.f_bsize
        status[namespace]['dump_count'] = dump_count
        status[namespace]['total_space'] = total_space
        status[namespace]['free_space'] = free_space

        if len(sorted_backups) > 0:
            status[namespace]['backup'] = {
                'count': len(sorted_backups)
            }
            last_backup = sorted_backups[-1]
            status_file = backups.build_backup_status_file_path(last_backup, namespace)
            if os.path.isfile(status_file):
                with open(status_file, 'r') as f:
                    try:
                        backup_status = json.load(f)
                        status[namespace]['last'] = {
                            'id': last_backup,
                            'status': backup_status.get('status'),
                            'status_id': backups.get_backup_status_id(backup_status.get('status')),
                            'created': backup_status.get('created'),
                            'expires': backup_status.get('expires'),
                            'expirationDate': backup_status.get('expirationDate')
                        }
                        return status, http.client.OK
                    except ValueError:
                        self.log.exception("Cannot read status file")
                        status[namespace]['last'] = {
                            'id': last_backup,
                            'status': backups.BackupStatus.UNKNOWN,
                            'status_id': backups.get_backup_status_id(backups.BackupStatus.UNKNOWN)
                        }
            else:
                status[namespace]['last'] = {
                    'id': last_backup,
                    'status': backups.BackupStatus.UNKNOWN,
                    'status_id': backups.get_backup_status_id(backups.BackupStatus.UNKNOWN)
                }

        return status, http.client.OK


class GranularBackupDownloadEndpoint(flask_restful.Resource):

    def __init__(self):
        self.log = logging.getLogger("GranularBackupDownloadEndpoint")
        self.s3 = storage_s3.AwsS3Vault() if os.environ['STORAGE_TYPE'] == "Zs3" else None

    @auth.login_required
    def get(self, backup_id):
        self.log.info("Download request accepted ")

        def generate(stream_path):
            stream = io.FileIO(stream_path, "r", closefd=True)
            with stream as f:
                chunk_size = 4096
                while True:
                    data = f.read(chunk_size)
                    if len(data) == 0:
                        f.close()
                        os.remove(stream_path)
                        self.log.info("Download ends ")
                        return
                    yield data

        namespace = flask.request.args.get('namespace') or configs.default_namespace()
        path_for_streaming = utils.get_backup_tar_file_path(backup_id, namespace)
        if path_for_streaming:
            return Response(stream_with_context(
                generate(path_for_streaming)),
                mimetype='application/octet-stream',
                headers=[
                    ('Content-Type', 'application/octet-stream'),
                    ('Content-Disposition',
                     "pg_granular_backup_{}.tar.gz".format(
                         backup_id))
                ])
        else:
            return Response("Cannot find backup ", status=404)



class DiffBackupRequestEndpoint(flask_restful.Resource):

    def __init__(self):
        self.log = logging.getLogger('DifferentialBackup')
        self.allowed_fields = ['timestamp']

    def perform_diff_backup(self):

        self.log.info('Perform diff backup')

        backup_id = backups.generate_backup_id()
        payload = {'timestamp':backup_id}
        r = requests.post("http://pgbackrest:3000/backup/diff", payload)
        if r.status_code == 200:
            return {
                'backupId': backup_id
            }, http.client.ACCEPTED
        else:
            return r.status_code


    def post(self):
        content_type = request.headers.get('Content-Type')

        # if content_type and content_type.split(";")[0] != 'application/json' \
        #         and request.headers.get('Content-Length'):
        #     return "Invalid request body: Content Type is not json", http.client.BAD_REQUEST


        return self.perform_diff_backup()

class IncrBackupRequestEndpoint(flask_restful.Resource):

    def __init__(self):
        self.log = logging.getLogger('IncrementalBackup')
        self.allowed_fields = ['timestamp']

    def perform_incr_backup(self):

        self.log.info('Perform incremental backup')

        backup_id = backups.generate_backup_id()
        payload = {'timestamp':backup_id}
        r = requests.post("http://pgbackrest:3000/backup/incr", payload)
        if r.status_code == 200:
            return {
                'backupId': backup_id
            }, http.client.ACCEPTED
        else:
            return r.status_code


    def post(self):
        return self.perform_incr_backup()

class GranularBackupStatusInfoEndpoint(flask_restful.Resource):

    def __init__(self):
        self.log = logging.getLogger('GranularBackupStatusMetricEndpoint')
        self.s3 = storage_s3.AwsS3Vault() if os.environ['STORAGE_TYPE'] == "s3" else None

    @auth.login_required
    def get(self):
        self.log.info("Backups metric gathering")
        storage = configs.backups_storage()
        s3 = None
        if os.environ['STORAGE_TYPE'] == "s3":
            s3 = backups.get_s3_client()
            namespaces = s3.get_granular_namespaces(storage)

        all_backups = []

        for namespace in os.listdir(storage) if not s3 else namespaces:
            if s3:
                backup_ids = s3.get_backup_ids(storage, namespace)

            for backup_id in os.listdir(build_namespace_path(namespace)) if not s3 else backup_ids:
                status_file = build_backup_status_file_path(backup_id, namespace)
                if s3:
                    try:
                        if s3.is_file_exists(status_file):
                            status_file = s3.read_object(status_file)
                            backup_details = json.loads(status_file)
                            all_backups.append(self.build_backup_info(backup_details))
                            continue
                        else:
                            self.log.error("Cannot find status file in bucket with backup id {}".format(backup_id))
                            failed_backup = {"backupId": backup_id, "namespace": namespace,  "status": backups.BackupStatus.FAILED}
                            all_backups.append(failed_backup)
                            continue
                    except ValueError:
                        self.log.exception("Cannot read status file")

                if not os.path.isfile(status_file):
                    failed_backup = {"backupId": backup_id, "namespace": namespace, "status": backups.BackupStatus.FAILED}
                    all_backups.append(failed_backup)
                    continue
                else:
                    backup_details = utils.get_json_by_path(status_file)
                    all_backups.append(self.build_backup_info(backup_details))
        response = {"granular": all_backups}

        return response, http.client.OK

    def build_backup_info(self, backup):

        backupInfo = {
            "backupId": backup.get("backupId", "UNDEFINED"),
            "namespace": backup.get("namespace", "UNDEFINED"),
            "status": backup.get("status", "UNDEFINED"),
            "expirationDate": backup.get("expirationDate", "UNDEFINED"),
            "created": backup.get("created", "UNDEFINED"),
        }

        return backupInfo



app = Flask("GranularREST")
collector_endpoint = os.getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "")
if collector_endpoint != "":
    collector_endpoint = "http://" + collector_endpoint
    NAMESPACE_PATH = '/var/run/secrets/kubernetes.io/serviceaccount/namespace'
    ns = open(NAMESPACE_PATH).read()
    resource = Resource(attributes={
        SERVICE_NAME: "postgresql-backup-daemon-" + ns
    })
    provider = TracerProvider(resource=resource)
    processor = BatchSpanProcessor(OTLPSpanExporter(endpoint=collector_endpoint, insecure=True))
    provider.add_span_processor(processor)
    FlaskInstrumentor().instrument_app(app=app, tracer_provider=provider, excluded_urls="health,/health,v2/health,/v2/health")
api = flask_restful.Api(app)

api.add_resource(GranularBackupsListEndpoint, '/backups')
api.add_resource(GranularBackupRequestEndpoint, '/backup/request')
api.add_resource(GranularBackupStatusEndpoint, '/backup/status/<backup_id>')
api.add_resource(GranularBackupStatusJSONEndpoint, '/backup/status')
api.add_resource(GranularRestoreRequestEndpoint, '/restore/request')
api.add_resource(TerminateBackupEndpoint, '/terminate/<backup_id>')
api.add_resource(TerminateRestoreEndpoint, '/restore/terminate/<tracking_id>')
api.add_resource(GranularRestoreStatusEndpoint, '/restore/status/<tracking_id>')
api.add_resource(GranularRestoreStatusJSONEndpoint, '/restore/status')
api.add_resource(GranularBackupDeleteEndpoint, '/delete/<backup_id>')
api.add_resource(GranularBackupHealthEndpoint, '/health')
api.add_resource(GranularBackupDownloadEndpoint, '/backup/download/<backup_id>')
api.add_resource(DiffBackupRequestEndpoint, '/backup/diff')
api.add_resource(IncrBackupRequestEndpoint, '/backup/incr')
api.add_resource(GranularBackupStatusInfoEndpoint, '/backup/info')

scheduler = BackgroundScheduler()
scheduler.start()
scheduler.add_job(backups.sweep_manager, 'interval', seconds=configs.eviction_interval())
schedule_granular_backup(scheduler)

# Add pgbackrest scheduler
backrest_scheduler = BackgroundScheduler()
backrest_scheduler.start()
schedule_diff_backup(backrest_scheduler)
schedule_incr_backup(backrest_scheduler)