"""This module is an adaptor to the underlying broker.
PyMsalRuntime is the package providing broker's functionality.

PyMsalRuntime currently supports these Windows versions, listed in this MSFT internal link
https://github.com/AzureAD/microsoft-authentication-library-for-cpp/pull/2406/files
"""
from threading import Event
import json
import logging
import uuid

import pymsalruntime  # ImportError would be raised on unsupported platforms such as Windows 8
    # Its API description is available in site-packages/pymsalruntime/PyMsalRuntime.pyi

logger = logging.getLogger(__name__)


class RedirectUriError(ValueError):
    pass


class _CallbackData:
    def __init__(self):
        self.signal = Event()
        self.auth_result = None

    def complete(self, auth_result):
        self.signal.set()
        self.auth_result = auth_result


def _convert_error(error, client_id):
    context = error.get_context()  # Available since pymsalruntime 0.0.4
    if "AADSTS50011" in context:  # In WAM, this could happen on both interactive and silent flows
        raise RedirectUriError(  # This would be seen by either the app developer or end user
            "MsalRuntime won't work unless this one more redirect_uri is registered to current app: "
            "ms-appx-web://Microsoft.AAD.BrokerPlugin/{}".format(client_id))
    return {
        "error": "broker_error",  # Note: Broker implies your device needs to be compliant.
            # You may use "dsregcmd /status" to check your device state
            # https://docs.microsoft.com/en-us/azure/active-directory/devices/troubleshoot-device-dsregcmd
        "error_description": "{}. Status: {}, Error code: {}, Tag: {}".format(
            context,
            error.get_status(), error.get_error_code(), error.get_tag()),
        }


def _read_account_by_id(account_id):
    """Return the callback result which contains the account or error"""
    callback_data = _CallbackData()
    pymsalruntime.read_account_by_id(
        account_id,
        "correlation_id",
        lambda result, callback_data=callback_data: callback_data.complete(result)
        )
    callback_data.signal.wait()
    return callback_data.auth_result


def _convert_result(result, client_id):  # Mimic an on-the-wire response from AAD
    error = result.get_error()
    if error:
        return _convert_error(error, client_id)
    id_token_claims = json.loads(result.get_id_token()) if result.get_id_token() else {}
    account = result.get_account()
    assert account, "Account is expected to be always available"
    ## Note: As of pymsalruntime 0.1.0, only wam_account_ids property is available
    #account.get_account_property("wam_account_ids")
    return_value = {k: v for k, v in {
        "access_token": result.get_access_token(),
        "expires_in": result.get_access_token_expiry_time(),
        "id_token_claims": id_token_claims,
        "client_info": account.get_client_info(),
        "_account_id": account.get_account_id(),
        }.items() if v}
    granted_scopes = result.get_granted_scopes()  # New in pymsalruntime 0.3.x
    if granted_scopes:
        return_value["scope"] = " ".join(granted_scopes)  # Mimic the on-the-wire data format
    return return_value


def _get_new_correlation_id():
    return str(uuid.uuid4())


def _signin_silently(authority, client_id, scopes, correlation_id=None, **kwargs):
    params = pymsalruntime.MSALRuntimeAuthParameters(client_id, authority)
    params.set_requested_scopes(scopes)
    callback_data = _CallbackData()
    for k, v in kwargs.items():  # This can be used to support domain_hint, max_age, etc.
        if v is not None:
            params.set_additional_parameter(k, str(v))
    pymsalruntime.signin_silently(
        params,
        correlation_id or _get_new_correlation_id(),
        lambda result, callback_data=callback_data: callback_data.complete(result))
    callback_data.signal.wait()
    return _convert_result(callback_data.auth_result, client_id)


def _signin_interactively(
        authority, client_id, scopes,
        window=None,
        prompt=None,
        login_hint=None,
        claims=None,
        correlation_id=None,
        **kwargs):
    params = pymsalruntime.MSALRuntimeAuthParameters(client_id, authority)
    params.set_requested_scopes(scopes)
    params.set_redirect_uri("placeholder")  # pymsalruntime 0.1 requires non-empty str,
        # the actual redirect_uri will be a value hardcoded by the underlying WAM
    if prompt:
        if prompt == "select_account":
            if login_hint:
                # FWIW, AAD's browser interactive flow would honor select_account
                # and ignore login_hint in such a case.
                # But pymsalruntime 0.3.x would pop up a meaningless account picker
                # and then force the account_hint user to re-input password. Not what we want.
                # https://identitydivision.visualstudio.com/Engineering/_workitems/edit/1744492
                login_hint = None  # Mimicing the AAD behavior
                logger.warning("Using both select_account and login_hint is ambiguous. Ignoring login_hint.")
            params.set_select_account_option(
                pymsalruntime.SelectAccountOption.SHOWLOCALACCOUNTSCONTROL)
        else:
            logger.warning("prompt=%s is not supported by this module", prompt)
    for k, v in kwargs.items():  # This can be used to support domain_hint, max_age, etc.
        if v is not None:
            params.set_additional_parameter(k, str(v))  # TODO: End-to-end test
    if claims:
        params.set_decoded_claims(claims)
    callback_data = _CallbackData()
    pymsalruntime.signin_interactively(
        window or pymsalruntime.get_console_window() or pymsalruntime.get_desktop_window(),  # Since pymsalruntime 0.2+
        params,
        correlation_id or _get_new_correlation_id(),
        login_hint or "",
        lambda result, callback_data=callback_data: callback_data.complete(result))
    callback_data.signal.wait()
    return _convert_result(callback_data.auth_result, client_id)


def _acquire_token_silently(
        authority, client_id, account_id, scopes, claims=None, correlation_id=None):
    account = _read_account_by_id(account_id)
    error = account.get_error()
    if error:
        return _convert_error(error, client_id)
    if not account.get_account():  # It happens when the account was not created by broker
        return
    params = pymsalruntime.MSALRuntimeAuthParameters(client_id, authority)
    params.set_requested_scopes(scopes)
    if claims:
        params.set_decoded_claims(claims)
    callback_data = _CallbackData()
    pymsalruntime.acquire_token_silently(
        params,
        correlation_id or _get_new_correlation_id(),
        account.get_account(),
        lambda result, callback_data=callback_data: callback_data.complete(result))
    callback_data.signal.wait()
    return _convert_result(callback_data.auth_result, client_id)


def _acquire_token_interactively(
        authority,
        client_id,
        account_id,
        scopes,
        prompt=None,  # TODO
        claims=None,
        extra_scopes_to_consent=None,  # TODO
        max_age=None,  # TODO
        correlation_id=None,
        window=None,
        **kwargs):
    raise NotImplementedError("We ended up not currently using this function")
    account = _read_account_by_id(account_id)
    error = account.get_error()
    if error:
        return _convert_error(error, client_id)
    params = pymsalruntime.MSALRuntimeAuthParameters(client_id, authority)
    params.set_requested_scopes(scopes)
    if claims:
        params.set_decoded_claims(claims)
    for k, v in kwargs.items():  # This can be used to support domain_hint, max_age, etc.
        if v is not None:
            params.set_additional_parameter(k, str(v))
    callback_data = _CallbackData()
    pymsalruntime.acquire_token_interactively(
        window or pymsalruntime.get_console_window() or pymsalruntime.get_desktop_window(),  # Since pymsalruntime 0.2+
        params,
        correlation_id or _get_new_correlation_id(),
        account.get_account(),
        lambda result, callback_data=callback_data: callback_data.complete(result))
    callback_data.signal.wait()
    return callback_data.auth_result

