# Copyright (c) Microsoft Corporation.
# All rights reserved.
#
# This code is licensed under the MIT License.

"""This module wraps Cloud Shell's IMDS-like interface inside an OAuth2-like helper"""
import json
import logging
import os
try:  # Python 2
    from urlparse import urlparse
except:  # Python 3
    from urllib.parse import urlparse


logger = logging.getLogger(__name__)


def _is_running_in_cloud_shell():
    return os.environ.get("AZUREPS_HOST_ENVIRONMENT", "").startswith("cloud-shell")


def _scope_to_resource(scope):  # This is an experimental reasonable-effort approach
    cloud_shell_supported_audiences = [
        "https://analysis.windows.net/powerbi/api",  # Came from https://msazure.visualstudio.com/One/_git/compute-CloudShell?path=/src/images/agent/env/envconfig.PROD.json
        "https://pas.windows.net/CheckMyAccess/Linux/.default",  # Cloud Shell accepts it as-is
        ]
    for a in cloud_shell_supported_audiences:
        if scope.startswith(a):
            return a
    u = urlparse(scope)
    if u.scheme:
        return "{}://{}".format(u.scheme, u.netloc)
    return scope  # There is no much else we can do here


def _acquire_token(http_client, scopes, **kwargs):
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
    ## Note: Decided to not surface resource back as scope,
    ##       because they would cause the downstream OAuth2 code path to
    ##       cache the token with a different scope and won't hit them later.
    #if payload.get("resource"):
    #    oauth2_response["scope"] = payload["resource"]
    if payload.get("refresh_token"):
        oauth2_response["refresh_token"] = payload["refresh_token"]
    return oauth2_response

