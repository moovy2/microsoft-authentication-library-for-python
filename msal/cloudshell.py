# Copyright (c) Microsoft Corporation.
# All rights reserved.
#
# This code is licensed under the MIT License.

"""This module wraps Cloud Shell's IMDS-like interface inside an OAuth2-like helper"""
import base64
import json
import logging
import os
import time
try:  # Python 2
    from urlparse import urlparse
except:  # Python 3
    from urllib.parse import urlparse
from .oauth2cli.oidc import decode_part


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


def _acquire_token(http_client, scopes, client_id=None, data=None):
    resp = http_client.post(
        "http://localhost:50342/oauth2/token",
        data=dict(
            data or {},
            resource=" ".join(map(_scope_to_resource, scopes))),
        headers={"Metadata": "true"},
        )
    if resp.status_code >= 300:
        logger.debug("Cloud Shell IMDS error: %s", resp.text)
        cs_error = json.loads(resp.text).get("error", {})
        return {k: v for k, v in {
            "error": cs_error.get("code"),
            "error_description": cs_error.get("message"),
            }.items() if v}
    imds_payload = json.loads(resp.text)
    BEARER = "Bearer"
    oauth2_response = {
        "access_token": imds_payload["access_token"],
        "expires_in": int(imds_payload["expires_in"]),
        "token_type": imds_payload.get("token_type", BEARER),
        }
    expected_token_type = (data or {}).get("token_type", BEARER)
    if oauth2_response["token_type"] != expected_token_type:
        return {  # Generate a normal error (rather than an intrusive exception)
            "error": "broker_error",
            "error_description": "token_type {} is not supported by this version of Azure Portal".format(
                expected_token_type),
            }
    parts = imds_payload["access_token"].split(".")

    # The following default values are useful in SSH Cert scenario
    client_info = {  # Default value, in case the real value will be unavailable
        "uid": "user",
        "utid": "cloudshell",
        }
    now = time.time()
    preferred_username = "currentuser@cloudshell"
    oauth2_response["id_token_claims"] = {  # First 5 claims are required per OIDC
        "iss": "cloudshell",
        "sub": "user",
        "aud": client_id,
        "exp": now + 3600,
        "iat": now,
        "preferred_username": preferred_username,  # Useful as MSAL account's username
        }

    if len(parts) == 3:  # Probably a JWT. Use it to derive client_info and id token.
        try:
            # Data defined in https://docs.microsoft.com/en-us/azure/active-directory/develop/access-tokens#payload-claims
            jwt_payload = json.loads(decode_part(parts[1]))
            client_info = {
                # Mimic a real home_account_id,
                # so that this pseudo account and a real account would interop.
                "uid": jwt_payload.get("oid", "user"),
                "utid": jwt_payload.get("tid", "cloudshell"),
                }
            oauth2_response["id_token_claims"] = {
                "iss": jwt_payload["iss"],
                "sub": jwt_payload["sub"],  # Could use oid instead
                "aud": client_id,
                "exp": jwt_payload["exp"],
                "iat": jwt_payload["iat"],
                "preferred_username": jwt_payload.get("preferred_username")  # V2
                    or jwt_payload.get("unique_name")  # V1
                    or preferred_username,
                }
        except ValueError:
            logger.debug("Unable to decode jwt payload: %s", parts[1])
    oauth2_response["client_info"] = base64.b64encode(
        # Mimic a client_info, so that MSAL would create an account
        json.dumps(client_info).encode("utf-8")).decode("utf-8")
    oauth2_response["id_token_claims"]["tid"] = client_info["utid"]  # TBD

    ## Note: Decided to not surface resource back as scope,
    ##       because they would cause the downstream OAuth2 code path to
    ##       cache the token with a different scope and won't hit them later.
    #if imds_payload.get("resource"):
    #    oauth2_response["scope"] = imds_payload["resource"]
    if imds_payload.get("refresh_token"):
        oauth2_response["refresh_token"] = imds_payload["refresh_token"]
    return oauth2_response

