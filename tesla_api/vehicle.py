"""Vehicle related stuff."""
import asyncio
import json
import logging
import time
from datetime import datetime
from typing import Optional, Union

from .battery import Battery
from .charge import Charge
from .climate import Climate
from .config import Config
from .controls import Controls
from .exceptions import ApiError, VehicleUnavailableError
from .gui import Gui
from .media import Media
from .misc import Dict, execute_callback, mile_to_km
from .state import State

_LOGGER = logging.getLogger(__name__)


class Vehicle:

    """Main class to interact with the vehicle

    Attributes:
        battery (`~tesla_api.battery.Battery`): Battery related stuff
        charge (`~tesla_api.charge.Charge`): Charge related stuff
        climate (`~tesla_api.climate.Climate`): Climate related stuff
        config (`~tesla_api.config.Config`): Config related stuff
        controls (`~tesla_api.controls.Controls`): Controls related stuff
        gui (`~tesla_api.gui.Gui`): Gui related stuff
        media (`~tesla_api.media.Media`): Media related stuff
        status (`~tesla_api.state.State`): Status related stuff
    """

    def __init__(
        self,
        api_client: "TeslaApiClient",
        data: Dict = Dict,
        lock: Optional[Union[None, asyncio.Lock]] = None,
    ):
        """Summary

        Args:
            api_client (`~tesla_api.controls.Controls`): Client used to calls so the api.
            data (Dict, optional): Data from the api.
            lock (Optional[Union[None, asyncio.Lock]], optional): Better safe then sorry.
        """
        if lock is None:
            self._lock = asyncio.Lock()
        else:
            self._lock = lock

        self._api_client = api_client
        self._data = Dict(data)

        self.battery = Battery(self)
        self.charge = Charge(self)
        self.climate = Climate(self)
        self.controls = Controls(self)
        self.media = Media(self)
        self.gui = Gui(self)
        self.status = State(self)
        self.config = Config(self)
        self._stream_task = None

    async def get_charge_state(self):
        """Get the charge state as a dict

        Returns:
            dict: Response from the api
        """
        data = await self._api_client.get(
            f"vehicles/{self.id}/data_request/charge_state"
        )
        async with self._lock:
            if "charge_state" not in self._data:
                self._data["charge_state"].update(data)
            self._data["charge_state"].update(data)
        return data

    async def get_climate_state(self):
        data = await self._api_client.get(
            f"vehicles/{self.id}/data_request/climate_state"
        )
        async with self._lock:
            if "climate_state" not in self._data:
                self._data["climate_state"] = {}
            self._data["climate_state"].update(data)
        return data

    async def compose_image(self, view, size=640):
        """Compose a image

        Args:
            view (str): Valid views STUD_3QTR, STUD_SEAT, STUD_SIDE, STUD_REAR and STUD_WHEEL
            size (int, optional): Size of the image.

        Returns:
            bytes: bytes for png.
        """
        params = {
            "model": "m" + self.vin[3].lower(),
            "bkba_opt": 1,
            "view": view,
            "size": size,
            "options": ",".join(self.option_codes),
        }

        url = "https://static-assets.tesla.com/v1/compositor/"
        async with self._api_client._session.get(url, params=params) as resp:
            img = await resp.read()
            return img

    async def address(self, lat=None, lon=None, service="nominatim"):
        """Find the street adresse the car is on

        Args:
            service (str, optional): What type of geodecoder should be used.

        Returns:
            str: Street adresse of the car is located on.
        """
        try:
            from geopy.geocoders import Nominatim, get_geocoder_for_service
            from geopy.adapters import AioHTTPAdapter
        except ImportError:
            _LOGGER.debug("Can't find the current addresse without geopy")
            return

        service = get_geocoder_for_service(service)
        lat = lat or self._data["drive_state"]["latitude"]
        lon = lon or self._data["drive_state"]["longitude"]

        async with service(
            user_agent="teslaapi",
            adapter_factory=AioHTTPAdapter,
        ) as geolocator:
            location = await geolocator.reverse(
                (
                    lat,
                    lon,
                ),
                exactly_one=True,
            )
        # Ideally this should be in the local format of that country.
        # https://github.com/mirumee/google-i18n-address if Nominatim is used.
        # Some providers seem to fix that, arcgis, but i couldnt figure out how
        # to get the clostst street number if it was at the opposite side of the road.
        _LOGGER.debug("Lat %s lon %s is %s", lat, lon, location.address)

        return location.address

    async def _command(self, command_endpoint, data=None, _retry=True):
        """Handles vehicle commands with the common reason/result response.

        Args:
            command_endpoint: The final part of the endpoint (after /command/).
            data: Optional JSON data to send with the request.
            _retry (bool, optional): Description

        Raises:
            ApiError: Description
            ApiError on unsuccessful response.

        Returns:
            TYPE: Description
        """
        # Commands won't work if car is offline, so try and wake car first.
        if self.state != "online":
            await self.wake_up()

        endpoint = f"vehicles/{self.id}/command/{command_endpoint}"
        try:
            res = await self._api_client.post(endpoint, data)
        except VehicleUnavailableError:
            # If first attempt, retry with a wake up.
            if _retry:
                self._data["state"] = "offline"
                return await self._command(command_endpoint, data, _retry=False)
            raise

        if res.get("result") is not True:
            raise ApiError(res.get("reason", ""))

        return True

    def _update_vehicle(self, state):
        """This should proable be changed.

        Args:
            state (TYPE): some kind of data.
        """
        self._data.update(state)

        if self._api_client.callback_update is not None:
            execute_callback(self._api_client.callback_update, self)

    async def nearby_charging_sites(self):
        """Get nearby charging sites"""
        return await self._api_client.get(f"vehicles/{self.id}/nearby_charging_sites")

    async def is_mobile_access_enabled(self):
        """Is mobile access enabled.

        Returns:
            TYPE: Description
        """
        return await self._api_client.get(f"vehicles/{self.id}/mobile_enabled")

    async def get_data(self):
        """Full all info about the cars.

        Returns:
            TYPE: Description
        """
        data = await self._api_client.get(f"vehicles/{self.id}/vehicle_data")
        async with self._lock:
            self._data.update(data)
        # Wft is this used for anyway?
        # self._update_vehicle({k: v for k, v in data.items()})
        return data

    async def full_update(self):
        """Do a full update."""
        await self.get_data()

    async def get_state(self):
        """Get state of the cars.

        Returns:
            dict: Json of the state of the car.
        """
        data = await self._api_client.get(
            f"vehicles/{self.id}/data_request/vehicle_state"
        )
        async with self._lock:
            if "vehicle_state" not in self._data:
                self._data["vehicle_state"] = {}
            self._data["vehicle_state"].update(data)

        return data

    async def get_drive_state(self):
        """Get drive state

        Returns:
            dict: dict of drive state.
        """
        data = await self._api_client.get(
            f"vehicles/{self.id}/data_request/drive_state"
        )

        async with self._lock:
            if "drive_state" not in self._data:
                self._data["drive_state"] = {}
            self._data["drive_state"].update(data)

        return data

    async def get_gui_settings(self):
        """Get gui settings.

        Returns:
            dict: dict of gui settings
        """
        data = await self._api_client.get(
            f"vehicles/{self.id}/data_request/gui_settings"
        )
        async with self._lock:
            if "gui_settings" not in self._data:
                self._data["gui_settings"] = {}
            self._data["gui_settings"].update(data)

        return data

    async def wake_up(self, timeout=-1):
        """Attempt to wake up the car.

        Vehicle will be online when this function returns successfully.

        Args:
            timeout: Seconds to keep attempting wakeup. Set to None to run until complete.
                Defaults to timeout attribute on TeslaApiClient.

        Raises:
            VehicleUnavailableError: Timeout exceeded without success.
        """
        if timeout is None:
            delay = 2
        else:
            if timeout <= 0:
                timeout = self._api_client.timeout
            delay = timeout / 100

        #_LOGGER.debug("delay %s", delay)

        async def _wake():
            """real wake command."""
            part_url = f"vehicles/{self.id}/wake_up"
            state = await self._api_client.post(part_url)
            #_LOGGER.debug("wake state %s", state)
            self._update_vehicle(state)
            while self._data["state"] != "online":
                await asyncio.sleep(delay)
                state = await self._api_client.post(f"vehicles/{self.id}/wake_up")
                self._update_vehicle(state)
            else:
                _LOGGER.debug("Woke the vehicle at %s", datetime.now())

        if self._api_client.callback_wake_up is not None:
            execute_callback(self._api_client.callback_wake_up, self)

        try:
            await asyncio.wait_for(_wake(), timeout)
        except asyncio.TimeoutError:
            raise VehicleUnavailableError()

    async def remote_start(self, password=None):
        """Enable keyless driving (must start car within a 2 minute window).

        password - The account password to reauthenticate.

        Args:
            password (None, optional): password to your telsa account

        Returns:
            bool: True on successfull command

        Raises:
            ValueError: Description
        """
        password = password or self._api_client._password
        if password is None:
            raise ValueError(
                "password is required to be passed or in used for authentication."
            )

        return await self._command("remote_start_drive", data={"password": password})

    async def share(self, value="", locale="en-US", timestamp_ms=None):
        """Sends a location for the car to start navigation or play a video in theatre mode

        Args:
            value (str): The address or video URL to set as the navigation destination.
            locale (str): ISO 639-1 standard language code
            timestamp_ms (None, int):

        """
        tms = timestamp_ms or time.time() * 1000
        data = {
            "type": "share_ext_content_raw",
            "value": {"android.intent.extra.TEXT": ""},
            "locale": locale,
            "timestamp_ms": int(tms),
        }

        return await self._api_client.post(
            f"vehicles/{self.id}/command/share", data=data
        )

    async def refresh(self):
        """Refresh attributes for this class."""
        data = await self._api_client.get(f"vehicles/{self.id}")
        # For some reason the api seems to include vehicle_config,
        # for this one we only want stuff for the attributes
        # so we are gonna remove other info.
        for key in [
            "charge_state",
            "climate_state",
            "drive_state",
            "gui_settings",
            "vehicle_config",
            "vehicle_state",
        ]:
            data.pop(key, None)

        async with self._lock:
            self._data.update(data)

        return data

    @property
    def vin(self):
        return self._data["vin"]

    def _format_distance_unit(self, value) -> float:
        # Use the helper.
        distance_format = self._data["gui_settings"]["gui_distance_units"]

        if distance_format == "km/hr":
            value = mile_to_km(value)

        return value

    @property
    def odometer(self) -> float:
        """The odometer in the gui format"""
        return self._format_distance_unit(self._data["vehicle_state"]["odometer"])

    @property
    def api_version(self) -> int:
        """Api version

        Returns:
            int: The api version
        """
        return self._data["vehicle_state"]["api_version"]

    @property
    def car_version(self) -> str:
        """Car version

        Returns:
            str: Fx 2020.44.10.1 955dc1dd145e
        """
        return self._data["vehicle_state"]["car_version"]

    @property
    def last_update(self) -> datetime:
        """Last update in datetime utc"""
        timestamp = self._data["vehicle_state"]["timestamp"]
        return datetime.utcfromtimestamp(timestamp / 1000)

    @property
    def id(self) -> str:
        return self._data["id"]

    @property
    def vehicle_id(self) -> str:
        """The id used for the car used by other endpoints. like streaming and summon."""
        return self._data["vehicle_id"]

    @property
    def id_s(self):
        return self._data["id_s"]

    @property
    def in_service(self) -> bool:
        return self._data["in_service"]

    @property
    def state(self) -> str:
        return self._data["state"]

    @property
    def access_type(self) -> str:
        return self._data["access_type"]

    @property
    def name(self) -> Optional[str]:
        """Display name

        Returns:
            str: the name the owner has given the car or None
        """
        return self._data["display_name"]

    @property
    def tokens(self) -> list:
        return self._data["tokens"]

    @property
    def color(self) -> str:
        return self._data["color"] or self._data["vehicle_config"]["exterior_color"]

    @property
    def option_codes(self) -> list:
        """Option codes

        Note:
            These can not be trusted.

        """
        return self._data["option_codes"].split(",")

    async def streaming(self, cb_data=None, cb_disconnect=None):
        """Stream updates using websocked and updates the attrs of the class."""
        await self.cancel_streaming()
        self._stream_task = asyncio.create_task(
            self._api_client.streaming(
                self, cb_data=cb_data, cb_disconnect=cb_disconnect
            )
        )
    
    async def cancel_streaming(self):
        if self._stream_task is not None:
            self._stream_task.cancel()
            try:
                await self._stream_task
                self._stream_task = None
            except asyncio.CancelledError:
                pass

