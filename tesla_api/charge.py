from datetime import datetime, timedelta
from typing import Optional, Union

from .base import Stub
from .misc import mile_to_km


class Charge(Stub):

    async def refresh(self):
        return await self._vehicle.get_charge_state()

    async def open_charge_port(self):
        """Open charge port."""
        return await self._vehicle._command("charge_port_door_open")

    async def close_charge_port(self):
        """Close charge port."""
        return await self._vehicle._command("charge_port_door_close")

    async def start_charging(self):
        """Start charging."""
        return await self._vehicle._command("charge_start")

    async def stop_charging(self):
        """Stop charging."""
        return await self._vehicle._command("charge_stop")

    async def set_standard_range_limit(self):
        return await self._vehicle._command("charge_standard")

    async def set_max_range_limit(self):
        return await self._vehicle._command("charge_max_range")

    async def set_charge_limit(self, percentage: int):
        """Set charge limit."""
        percentage = round(percentage)

        if not (50 <= percentage <= 100):
            raise ValueError("Percentage should be between 50 and 100")

        return await self._vehicle._command("set_charge_limit", {"percent": percentage})


    @property
    def charge_current_request(self):
        return self._vehicle._data["charge_state"]["charge_current_request"]

    @property
    def charge_current_request_max(self):
        return self._vehicle._data["charge_state"]["charge_current_request_max"]

    @property
    def charge_enable_request(self):
        return self._vehicle._data["charge_state"]["charge_enable_request"]

    @property
    def charge_energy_added(self):
        """kWh added into the battery."""
        return self._vehicle._data["charge_state"]["charge_energy_added"]

    @property
    def charge_limit(self):
        """kWh added into the battery."""
        return self._vehicle._data["charge_state"]["charge_limit_soc"]

    @property
    def charge_limit_max(self):
        """kWh added into the battery."""
        return self._vehicle._data["charge_state"]["charge_limit_soc_max"]

    @property
    def charge_limit_min(self):
        """kWh added into the battery."""
        return self._vehicle._data["charge_state"]["charge_limit_soc_min"]

    @property
    def charge_limit_std(self):
        """kWh added into the battery."""
        return self._vehicle._data["charge_state"]["charge_limit_soc_std"]

    @property
    def charge_miles_added_ideal(self):
        """kWh added into the battery."""
        return self._vehicle._data["charge_state"]["charge_miles_added_ideal"]

    @property
    def charge_miles_added_rated(self):
        """Rated range added in km added into the battery."""
        return self._vehicle._data["charge_state"]["charge_miles_added_rated"]

    @property
    def charge_km_added_ideal(self):
        """kWh added into the battery."""
        return mile_to_km(self.charge_miles_added_ideal)

    @property
    def charge_km_added_rated(self):
        """Rated range added in km added into the battery."""
        return mile_to_km(self.charge_miles_added_rated)

    @property
    def charge_port_cold_weather_mode(self):
        # is this the charge port heater, if we it should be renamed.
        return self._vehicle._data["charge_state"]["charge_port_cold_weather_mode"]

    @property
    def charge_port_door_open(self):
        # is this the charge port heater, if we it should be renamed.
        return self._vehicle._data["charge_state"]["charge_port_door_open"]

    @property
    def charge_port_latch(self):
        # this should be bool but i assume mypy uses True
        value = self._vehicle._data["charge_state"]["charge_port_latch"]
        if value and value.lower() == "engaged":
            return True
        else:
            return False

    @property
    def charge_rate(self):
        """The charge speed in kWh."""
        return self._vehicle._data["charge_state"]["charge_rate"]

    @property
    def charge_to_max_range(self):
        """The max charge range to 100%."""
        return self._vehicle._data["charge_state"]["charge_to_max_range"]

    @property
    def actual_current(self):
        """The charge speed in kWh."""
        return self._vehicle._data["charge_state"]["charger_actual_current"]

    @property
    def phases(self):
        """How many phases does the car charge with."""
        return self._vehicle._data["charge_state"]["charger_phases"]

    @property
    def pilot_current(self):
        """The charge speed in amps."""
        return self._vehicle._data["charge_state"]["charger_pilot_current"]

    @property
    def power(self):
        """Charge power in kWh"""
        return self._vehicle._data["charge_state"]["charger_power"]

    @property
    def voltage(self):
        """Charge power in kWh"""
        return self._vehicle._data["charge_state"]["charger_voltage"]

    @property
    def charging_state(self):
        """Only seen Charging as state"""
        return self._vehicle._data["charge_state"]["charging_state"]

    @property
    def conn_charge_cable(self):
        """charge cabel connection?"""
        return self._vehicle._data["charge_state"]["conn_charge_cable"]

    @property
    def estimated_battery_range(self):
        return self._vehicle._data["charge_state"]["est_battery_range"]

    @property
    def fast_charger_brand(self):
        return self._vehicle._data["charge_state"]["fast_charger_brand"]

    @property
    def fast_charger_present(self):
        return self._vehicle._data["charge_state"]["fast_charger_present"]

    @property
    def fast_charger_type(self):
        return self._vehicle._data["charge_state"]["fast_charger_type"]

    @property
    def managed_charging_active(self):
        """Is managed charing active."""
        return self._vehicle._data["charge_state"]["managed_charging_active"]

    @property
    def managed_charging_start_time(self) -> Optional[Union[None, bool]]:
        # is this planned departure? is null value.
        return self._vehicle._data["charge_state"]["managed_charging_start_time"]

    @property
    def managed_charging_user_canceled(self):
        # is this planned departure? is null value.
        return self._vehicle._data["charge_state"]["managed_charging_user_canceled"]

    @property
    def max_range_charge_counter(self):
        # is this planned departure? is null value.
        return self._vehicle._data["charge_state"]["max_range_charge_counter"]

    @property
    def minutes_to_full_charge(self):
        # is this planned departure? is null value.
        return self._vehicle._data["charge_state"]["minutes_to_full_charge"]

    @property
    def scheduled_charging_pending(self):
        # is this planned departure? is null value.
        return self._vehicle._data["charge_state"]["scheduled_charging_pending"]

    @property
    def scheduled_charging_start_time(self):
        # is this planned departure? is null value.
        return self._vehicle._data["charge_state"]["scheduled_charging_start_time"]

    @property
    def fully_charged_at(self):
        #return self._vehicle._data["charge_state"]["time_to_full_charge"]
        # check that the timestamp updated.
        return self.timestamp + timedelta(minutes=self.minutes_to_full_charge)

    @property
    def timestamp(self):
        """Datetime from the last time the data was updated."""
        value = self._vehicle._data["charge_state"]["timestamp"]
        return datetime.utcfromtimestamp(value / 1000)

    @property
    def trip_charging(self):
        """Trip charging."""
        return self._vehicle._data["charge_state"]["trip_charging"]


    @property
    def user_charge_enable_request(self):
        # Wtf is this used for?
        return self._vehicle._data["charge_state"]["user_charge_enable_request"]
