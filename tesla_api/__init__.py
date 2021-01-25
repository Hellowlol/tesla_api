import asyncio
import json
import logging
from datetime import datetime, timedelta

import aiohttp

from .energy import Energy
from .exceptions import ApiError, AuthenticationError, VehicleUnavailableError
from .vehicle import Vehicle

TESLA_API_BASE_URL = "https://owner-api.teslamotors.com/"
TOKEN_URL = TESLA_API_BASE_URL + "oauth/token"
API_URL = TESLA_API_BASE_URL + "api/1"

OAUTH_CLIENT_ID = "81527cff06843c8634fdc09e8ac0abefb46ac849f38fe1e431c2ef2106796384"
OAUTH_CLIENT_SECRET = "c7257eb71a564034f9419ee651c7d0e5f7aa6bfbd18bafb5c5c033b093bb2fa3"

_LOGGER = logging.getLogger(__name__)


class TeslaApiClient:
    callback_update = None  # Called when vehicle's state has been updated.
    callback_wake_up = None  # Called when attempting to wake a vehicle.
    timeout = 30  # Default timeout for operations such as Vehicle.wake_up().

    def __init__(
        self, email=None, password=None, token=None, on_new_token=None, session=None
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
        self._email = email
        self._password = password
        self._token = json.loads(token) if token else None
        self._new_token_callback = on_new_token

        if session is None:
            self._session = aiohttp.ClientSession()
        else:
            self._session = session
            self._own_session = True

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

    async def _get_token(self, data):
        request_data = {
            "client_id": OAUTH_CLIENT_ID,
            "client_secret": OAUTH_CLIENT_SECRET,
        }
        request_data.update(data)

        async with self._session.post(TOKEN_URL, data=request_data) as resp:
            response_json = await resp.json()
            if resp.status == 401:
                raise AuthenticationError(response_json)

        # Send token to application via callback.
        if self._new_token_callback:
            asyncio.create_task(self._new_token_callback(json.dumps(response_json)))

        return response_json

    async def _get_new_token(self):
        return await self._get_token(
            {"grant_type": "password", "email": self._email, "password": self._password}
        )

    async def _refresh_token(self, refresh_token):
        return await self._get_token(
            {"grant_type": "refresh_token", "refresh_token": refresh_token}
        )

    async def authenticate(self):
        if not self._token:
            self._token = await self._get_new_token()

        expiry_time = timedelta(seconds=self._token["expires_in"])
        expiration_date = (
            datetime.fromtimestamp(self._token["created_at"]) + expiry_time
        )

        if datetime.utcnow() >= expiration_date:
            _LOGGER.debug("Token is expired")
            self._token = await self._refresh_token(self._token["refresh_token"])

    def _get_headers(self):
        return {"Authorization": "Bearer {}".format(self._token["access_token"])}

    async def get(self, endpoint, params=None):
        await self.authenticate()
        url = f"{API_URL}/{endpoint}"

        headers = self._get_headers()
        response_json = {}

        _LOGGER.debug("url %s headers: %s params:%s", url, headers, params)

        async with self._session.get(url, headers=headers, params=params) as resp:
            response_json = await resp.json()

        if "error" in response_json:
            if "vehicle unavailable" in response_json["error"]:
                raise VehicleUnavailableError()
            raise ApiError(response_json["error"])

        return response_json["response"]

    async def post(self, endpoint, data=None):
        await self.authenticate()
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

    async def list_vehicles(self):
        v = await self.get("vehicles")
        _LOGGER.debug("%s", v)
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
