# Copyright (c) Microsoft Corporation.
# All rights reserved.
#
# This code is licensed under the MIT License.

"""This module wraps Cloud Shell's IMDS-like interface inside an OAuth2-like helper"""
import json
import logging
import os


logger = logging.getLogger(__name__)


def _is_running_in_cloud_shell():
    return os.environ.get("AZUREPS_HOST_ENVIRONMENT", "").startswith("cloud-shell")


def _scope_to_resource(scope):
    cloud_shell_supported_audiences = [  # Came from https://msazure.visualstudio.com/One/_git/compute-CloudShell?path=/src/images/agent/env/envconfig.PROD.json
        "https://management.core.windows.net/",
        "https://management.azure.com/",
        "https://graph.windows.net/",
        "https://vault.azure.net",
        "https://datalake.azure.net/",
        "https://outlook.office365.com/",
        "https://graph.microsoft.com/",
        "https://batch.core.windows.net/",
        "https://analysis.windows.net/powerbi/api",
        "https://storage.azure.com/",
        "https://rest.media.azure.net",
        "https://api.loganalytics.io",
        "https://ossrdbms-aad.database.windows.net",
        "https://www.yammer.com",
        "https://digitaltwins.azure.net",
        "0b07f429-9f4b-4714-9392-cc5e8e80c8b0",
        "822c8694-ad95-4735-9c55-256f7db2f9b4",
        "https://dev.azuresynapse.net",
        "https://database.windows.net",
        "https://quantum.microsoft.com",
        "https://iothubs.azure.net",
        "2ff814a6-3304-4ab8-85cb-cd0e6f879c1d",
        "https://azuredatabricks.net/",
        "ce34e7e5-485f-4d76-964f-b3d2b16d1e4f",
        "https://azure-devices-provisioning.net"
        ]
    for a in cloud_shell_supported_audiences:
        if scope.startswith(a):  # This is an experimental approach
            return a
    return scope  # Some scope would work as-is, such as the SSH Cert scope


def _acquire_token(http_client, scopes, **kwargs):
    kwargs.pop("correlation_id", None)  # IMDS does not use correlation_id
    resp = http_client.post(
        "http://localhost:50342/oauth2/token",
        data=dict(
            kwargs.pop("data", {}),
            resource=" ".join(map(_scope_to_resource, scopes))),
        headers=dict(kwargs.pop("headers", {}), Metadata="true"),
        **kwargs)
    if resp.status_code >= 300:
        logger.debug("Cloud Shell IMDS error: %s", resp.text)
        cs_error = json.loads(resp.text).get("error", {})
        return {k: v for k, v in {
            "error": cs_error.get("code"),
            "error_description": cs_error.get("message"),
            }.items() if v}
    payload = json.loads(resp.text)
    oauth2_response = {
        "access_token": payload["access_token"],
        "expires_in": int(payload["expires_in"]),
        "token_type": payload.get("token_type", "Bearer"),
        }
    if payload.get("refresh_token"):
        oauth2_response["refresh_token"] = payload["refresh_token"]
    return oauth2_response

