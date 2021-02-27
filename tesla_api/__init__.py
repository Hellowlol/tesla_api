import asyncio
import base64
import hashlib
import json
import logging
import re
import secrets
from copy import deepcopy
from datetime import datetime, timedelta
from pprint import pprint
from urllib.parse import parse_qs, urlparse

import aiohttp

from .energy import Energy
from .exceptions import (ApiError, AuthenticationBlockedError,
                         AuthenticationError, MissingCredentials,
                         VehicleUnavailableError)
from .vehicle import Vehicle

TESLA_API_BASE_URL = "https://owner-api.teslamotors.com/"
API_URL = f"{TESLA_API_BASE_URL}api/1"

V2TOKEN_URL = f"{TESLA_API_BASE_URL}oauth/token"
V3TOKEN_URL = "https://auth.tesla.com/oauth2/v3/token"

V3_AUTH_TOKEN_URL = "https://auth.tesla.com/oauth2/v3/authorize"
V3_AUTH_TOKEN_URL_EXCHANGE = "https://auth.tesla.com/oauth2/v3/token"

V3OAUTH_CLIENT_ID = "ownerapi"
V2OAUTH_CLIENT_ID = "81527cff06843c8634fdc09e8ac0abefb46ac849f38fe1e431c2ef2106796384"
EPOCH = datetime.fromtimestamp(0)

_LOGGER = logging.getLogger(__name__)


class TeslaApiClient:
    callback_update = None  # Called when vehicle's state has been updated.
    callback_wake_up = None  # Called when attempting to wake a vehicle.
    timeout = 30  # Default timeout for operations such as Vehicle.wake_up().

    def __init__(
        self,
        email=None,
        password=None,
        token=None,
        on_new_token=None,
        session=None,
        code=None,
        long_live_token=True,
        mfa_code="",
    ):
        """Creates client from provided credentials.

        If token is not provided, or is no longer valid, then a new token will
        be fetched if email and password are provided.

        If on_new_token is provided, it will be called with the newly created token.
        This should be used to save the token, both after initial login and after an
        automatic token renewal. The token is returned as a string and can be passed
        directly into this constructor.
        """
        assert token is not None or (email is not None and password is not None)
        self._own_session = False
        self._code = code
        self._email = email
        self._password = password
        self._new_token_callback = on_new_token
        self._sso_oauth = json.loads(token) if token else {}
        self._expires_in = EPOCH
        self.code_verifier = secrets.token_urlsafe(64)
        self.token_refreshed = False
        self.long_live_token = long_live_token
        self._mfa_code = mfa_code
        self._ttl_short_token = EPOCH

        if session is None:
            self._session = aiohttp.ClientSession()
        else:
            self._session = session
            self._own_session = True

    @property
    def expires_in(self):
        return self._expires_in

    @expires_in.setter
    def expires_in(self, value):
        self._expires_in = value
        _LOGGER.debug("Setting new expires_in %s", value)

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        if self._own_session is True:
            await self.close()

    async def close(self):
        """Close the session if it was created automatically,
        if its passed as a argument they need to close it manually.
        """
        if self._own_session is False:
            await self._session.close()
            await asyncio.sleep(500)

    def _get_headers(self):
        return {"Authorization": "Bearer {}".format(self._sso_oauth["access_token"])}

    async def handle_mfa(self, transaction_id, passcode=None):
        _LOGGER.debug("Handling mfa.")
        headers = {
            "User-Agent": "Mozilla/5.0 (Linux; Android 10; Pixel 3 Build/QQ2A.200305.002; wv) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/85.0.4183.81 Mobile Safari/537.36",
            "x-tesla-user-agent": "TeslaApp/3.10.9-433/adff2e065/android/10",
            "X-Requested-With": "com.teslamotors.tesla",
        }

        # passcodes have to be in this format if multiple mfa devices
        # passcode = {"32d6c32c-b14a-4cef-1337-36f819d1fb4b": "1223456"}
        # passcode = {"Johns iphone": "123456"}
        # This is ok with only 1 mfa.
        # passcode = "123456"

        passcode = passcode or self._mfa_code
        if isinstance(passcode, dict):
            pc = list(passcode.values())[0]
        else:
            pc = passcode

        async with self._session.get(
            f"https://auth.tesla.com/oauth2/v3/authorize/mfa/factors?transaction_id={transaction_id}"
        ) as resp:
            data = await resp.json()

        devices = data["data"]
        # check if we have multiple mfa devices.
        if len(devices) > 1:
            if isinstance(passcode, dict):
                idents = passcode.keys()[0]

                for device in devices:
                    for key, value in device.items():
                        if key == idents:
                            factor_id = device["id"]
        else:
            factor_id = devices[0]["id"]

        params = {
            "transaction_id": transaction_id,
            "factor_id": factor_id,
            "passcode": pc,
        }

        async with self._session.post(
            "https://auth.tesla.com/oauth2/v3/authorize/mfa/verify",
            json=params,
            headers=headers,
        ) as verify_rsp:
            try:
                resp_json = await verify_rsp.json()
                _LOGGER.debug("MFA ok status %s", resp_json["data"]["valid"])
                return resp_json["data"]["valid"]
            except Exception as e:
                # TODO fix the exception.
                ffs = await verify_rsp.text()
                _LOGGER.debug("Shit happend during verify mfa")
                _LOGGER.exception(ffs)
                raise

    async def get_authorization_code(self, email, password) -> str:
        """Get authorization code from the oauth3 login method and possible verify mfa if needed and provided."""
        # https://tesla-api.timdorr.com/api-basics/authentication#step-2-obtain-an-authorization-code
        _LOGGER.debug("Trying to get authorization code")
        email = email or self._email
        password = password or self._password

        if not email or not password:
            raise MissingCredentials

        code_challenge = base64.urlsafe_b64encode(
            hashlib.sha256(self.code_verifier.encode()).hexdigest().encode()
        )
        state = secrets.token_urlsafe(64)

        query = {
            "client_id": V3OAUTH_CLIENT_ID,
            "code_challenge": code_challenge.decode(),
            "code_challenge_method": "S256",
            "redirect_uri": "https://auth.tesla.com/void/callback",
            "response_type": "code",
            "scope": "openid email offline_access",
            "state": state,
            # login_hint: self._email
        }

        async with self._session.get(V3_AUTH_TOKEN_URL, params=query) as resp:
            response_page = await resp.text()
            if resp.status == 403 and "<title>Tesla - Error</title>":
                _LOGGER.debug("%s", response_page)
                raise AuthenticationError("403, probable stuck in WAF..")
            elif resp.status != 200 and not "<title>" in response_page:
                raise AuthenticationError
            # Should add some other check here.
            elif resp.status == 303:
                # see other, make sure we update the V3_AUTH_TOKEN_URL for the correct region.
                pass

        input_fields = (
            f.group(1) for f in re.finditer(r"<input ([^>]+)>", response_page)
        )
        input_fields = (
            (re.search(r'name="(.*?)"', f), re.search(r'value="(.*?)"', f))
            for f in input_fields
        )
        form_data = {
            name.group(1): value.group(1) if value else ""
            for name, value in input_fields
        }
        form_data["identity"] = email
        form_data["credential"] = password
        TRIES = 0

        # This inlined as we need access to the same form data.
        async def do_request_auth():
            async with self._session.post(
                V3_AUTH_TOKEN_URL,
                data=form_data,
                params=query,
                headers={},
                allow_redirects=False,
            ) as resp:
                nonlocal TRIES
                TRIES += 1
                if resp.status == 401:
                    raise AuthenticationError("Incorrect login")
                elif resp.status == 403:
                    raise AuthenticationBlockedError("403")
                if resp.status == 200:
                    page = await resp.text()

                    if "/mfa/verify" in page:
                        mfa_ok = await self.handle_mfa(form_data["transaction_id"])
                        if mfa_ok:
                            # retry request
                            if TRIES > 2:
                                _LOGGER.debug("Tried %s times, stopping", TRIES)
                                # Just so we don't block the account if a mistake was made.
                                return
                            return await do_request_auth()

                    errors = json.loads(
                        re.search(r"var messages = (.*);", page).group(1)
                    )
                    _LOGGER.debug("possible errors %s", errors)
                    raise AuthenticationError(errors.get("_", errors))
                    _LOGGER.debug("%s", page)

                redirect_location = resp.headers["Location"]
                args = parse_qs(urlparse(redirect_location).query)
                if args["state"][0] != state:
                    raise AuthenticationError("Incorrect state (possible CSRF attack).")

                return args["code"][0]

        return await do_request_auth()

    async def get_sso_auth_token(self, code):
        """Get sso auth token."""
        # https://tesla-api.timdorr.com/api-basics/authentication#step-2-obtain-an-authorization-code
        _LOGGER.debug("Trying to exchange authentication code to bearer token")
        if not code:
            _LOGGER.debug("No authorization code provided")
            return

        oauth = {
            "client_id": V3OAUTH_CLIENT_ID,
            "grant_type": "authorization_code",
            "code": code,
            "code_verifier": self.code_verifier,
            "redirect_uri": "https://auth.tesla.com/void/callback",
        }

        req = await self._session.post(
            V3_AUTH_TOKEN_URL_EXCHANGE,
            data=oauth,
        )
        data = await req.json()
        self._ttl_short_token = datetime.utcnow() + timedelta(
            seconds=data.get("expires_in", 300)
        )

        return data

    async def refresh_access_token(self, refresh_token):
        """Refresh access token from sso."""
        # https://tesla-api.timdorr.com/api-basics/authentication#refreshing-an-access-token
        if not refresh_token:
            _LOGGER.debug("Missing refresh token")
            return
        _LOGGER.debug("Refreshing access token with refresh_token")
        oauth = {
            "client_id": V3OAUTH_CLIENT_ID,
            "grant_type": "refresh_token",
            "refresh_token": refresh_token,
            "scope": "openid email offline_access",
        }
        auth = await self._session.post(
            V3_AUTH_TOKEN_URL_EXCHANGE,
            data=oauth,
        )

        # patched to test refresh
        # self._ttl_short_token = datetime.utcnow() + timedelta(seconds=60)
        self._ttl_short_token = datetime.utcnow() + timedelta(
            seconds=auth.get("expires_in", 300)
        )
        data = await auth.json()

        if self.long_live_token is True:
            # Use v3 access_token to get a bearer token thats valid 45 days
            lt_token_data = await self.get_bearer_token(data["access_token"])
            # refresh token seems to be valid over the 300 sec that the v3 access token is valid.
            lt_token_data["refresh_token"] = refresh_token
            return lt_token_data
        return data

    async def get_bearer_token(self, access_token):
        """Get bearer token. This is used by the owners API. This token is valid for 45 days."""
        # https://tesla-api.timdorr.com/api-basics/authentication#step-4-exchange-bearer-token-for-access-token
        if not access_token:
            _LOGGER.debug("Missing access token")
            return
        _LOGGER.debug("Exchanging access_token to get a bearer token.")
        oauth = {
            "client_id": V2OAUTH_CLIENT_ID,
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
        }
        head = {
            "Authorization": f"Bearer {access_token}",
        }
        auth = await self._session.post(V2TOKEN_URL, headers=head, data=oauth)

        return await auth.json()

    async def get(self, endpoint, params=None):
        await self.check_auth()
        url = f"{API_URL}/{endpoint}"

        headers = self._get_headers()
        response_json = {}

        #_LOGGER.debug("url %s headers: %s params:%s", url, headers, params)

        async with self._session.get(url, headers=headers, params=params) as resp:
            response_json = await resp.json()

        if "error" in response_json:
            if "vehicle unavailable" in response_json["error"]:
                raise VehicleUnavailableError()
            raise ApiError(response_json["error"])

        return response_json["response"]

    async def post(self, endpoint, data=None):
        await self.check_auth()
        url = f"{API_URL}/{endpoint}"
        headers = self._get_headers()

        _LOGGER.debug("url %s headers: %s data:%s", url, headers, data)

        async with self._session.post(
            url, headers=self._get_headers(), json=data
        ) as resp:
            response_json = await resp.json()

        if "error" in response_json:
            if "vehicle unavailable" in response_json["error"]:
                raise VehicleUnavailableError()
            raise ApiError(response_json["error"])

        return response_json["response"]

    async def check_auth(self):
        now = datetime.utcnow()

        if self._sso_oauth.get("access_token") and (
            not self._code and not self._email and not self._password
        ):
            _LOGGER.debug(
                "Access granted directly using exteral access token with no means to refresh it."
            )

        if now > self.expires_in:
            _LOGGER.debug("The oauth token expired at %s", self.expires_in)
            self.token_refreshed = False
            auth = {}
            if (self._code or (self._email and self._password)) and (
                not self._sso_oauth
                or (
                    now > self._sso_oauth.get("expires_in", EPOCH)
                    and not self._sso_oauth.get("refresh_token")
                )
            ):
                if self._email and self._password:
                    self._code = await self.get_authorization_code(
                        self._email, self._password
                    )

                auth = await self.get_sso_auth_token(self._code)
                if "error" in auth:
                    if not self._email or not self._password:
                        raise AuthenticationError(
                            "The code param in the constructor was invalid and no username or no password was provided."
                        )

            elif self._sso_oauth.get("refresh_token") and now > self._sso_oauth.get(
                "expires_in", EPOCH
            ):

                auth = await self.refresh_access_token(
                    refresh_token=self._sso_oauth.get("refresh_token")
                )

            if auth:
                self._sso_oauth = {
                    "access_token": auth["access_token"],
                    # This should be able to add this safely as the refresh token is v3 regardless
                    # handled by refresh_access_token
                    "refresh_token": auth["refresh_token"],
                }
                self._token = auth["access_token"]

                # Check if this is v3 or v2 access token.
                if "created_at" in auth:
                    # v2
                    expires_in = datetime.utcfromtimestamp(
                        auth["created_at"]
                    ) + timedelta(seconds=auth["expires_in"])

                    self._sso_oauth["expires_in"] = expires_in
                    self.expires_in = expires_in
                else:
                    # v3
                    self._sso_oauth["expires_in"] = self._ttl_short_token
                    self.expires_in = self._ttl_short_token
                    self._sso_oauth["refresh_token"] = auth.get("refresh_token")

                self.token_refreshed = True
                # _LOGGER.debug("Saving new auth info %s", self._sso_oauth)

                if self._new_token_callback:
                    cb_data = deepcopy(self._sso_oauth)
                    cb_data["expires_in"] = self.expires_in.isoformat()
                    asyncio.create_task(self._new_token_callback(json.dumps(cb_data)))

    async def list_vehicles(self):
        v = await self.get("vehicles")
        return [Vehicle(self, vehicle) for vehicle in await self.get("vehicles")]

    async def get_vehicle(self, name):
        list_vehicles = await self.list_vehicles()
        return next([i for i in list_vehicles if i.get("title") == name], None)

    async def list_energy_sites(self):
        return [
            Energy(self, product["energy_site_id"])
            for product in await self.get("products")
            if "energy_site_id" in product
        ]
