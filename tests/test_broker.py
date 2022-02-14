from tests import unittest
import logging
import sys

if not sys.platform.startswith("win"):
    raise unittest.SkipTest("requires Windows")
from msal.wam import (  # Import them after the platform check
    _signin_interactively, _acquire_token_silently, RedirectUriError)


logging.basicConfig(level=logging.DEBUG)

class TestWam(unittest.TestCase):
    _authority = "https://login.microsoftonline.com/common"
    _scopes = ["https://graph.microsoft.com/.default"]

    def test_interactive_then_silent(self):
        client_id = "26a7ee05-5602-4d76-a7ba-eae8b7b67941"  # A pre-configured test app

        result = _signin_interactively(self._authority, client_id, self._scopes)
        self.assertIsNotNone(result.get("access_token"), result)

        account_id = result["_account_id"]
        result = _acquire_token_silently(self._authority, client_id, account_id, self._scopes)
        self.assertIsNotNone(result.get("access_token"), result)

    def test_unconfigured_app_should_raise_exception(self):
        client_id = "289a413d-284b-4303-9c79-94380abe5d22"  # A test app without proper redirect_uri
        with self.assertRaises(RedirectUriError):
            _signin_interactively(self._authority, client_id, self._scopes)
        # Note: _acquire_token_silently() would raise same exception,
        #       we skip its test here due to the lack of a valid account_id

    def test_login_hint(self):
        pass  # TODO

    def test_signin_interactively_and_select_account(self):
        client_id = "26a7ee05-5602-4d76-a7ba-eae8b7b67941"  # A pre-configured test app
        print("An account picker UI will pop up. See whether the auth result matches your account")
        result = _signin_interactively(
            self._authority, client_id, self._scopes, prompt="select_account")
        self.assertIsNotNone(result.get("access_token"), result)
        import pprint; pprint.pprint(result)

