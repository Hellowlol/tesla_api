import pytest


@pytest.mark.asyncio
async def test_Vehicle_Charge_attributes(vehicle):
    charge = vehicle.charge
    assert charge.actual_current == 0
    assert charge.battery_heater_on is False
    assert charge.battery_level == 60
    assert charge.battery_range == 185.92
    assert charge.charge_current_request == 16
    assert charge.charge_current_request_max == 16
    assert charge.charge_enable_request is True
    assert charge.charge_energy_added == 22.66
    assert charge.charge_km_added_ideal == 57.478406760703415
    assert charge.charge_km_added_rated == 57.478406760703415
    assert charge.charge_limit == 69
    assert charge.charge_limit_max == 100
    assert charge.charge_limit_min == 50
    assert charge.charge_limit_std == 90
    assert charge.charge_miles_added_ideal == 92.5
    assert charge.charge_miles_added_rated == 92.5
    assert charge.charge_port_cold_weather_mode is False
    assert charge.charge_port_door_open is False
    assert charge.charge_port_latch is True
    assert charge.charge_rate == 0.0
    assert charge.charge_to_max_range is False
    assert charge.charging_state == "Disconnected"
    assert charge.conn_charge_cable == "<invalid>"
    assert charge.estimated_battery_range == 140.2
    assert charge.fast_charger_brand == "<invalid>"
    assert charge.fast_charger_present is False
    assert charge.fast_charger_type == "<invalid>"
    assert str(charge.fully_charged_at.date()) == "2020-11-18"
    assert charge.ideal_battery_range == 185.92
    assert charge.managed_charging_active is False
    assert charge.managed_charging_start_time is None
    assert charge.managed_charging_user_canceled is False
    assert charge.max_range_charge_counter == 0
    assert charge.minutes_to_full_charge == 0
    assert charge.not_enough_power_to_heat is None
    assert charge.phases is None
    assert charge.pilot_current == 16
    assert charge.power == 0
    assert charge.scheduled_charging_pending is False
    assert charge.scheduled_charging_start_time is None
    assert charge.soc is False
    assert str(charge.timestamp.date()) == "2020-11-18"
    assert charge.trip_charging is False
    assert charge.usable_battery_level == 60
    assert charge.user_charge_enable_request is None
    assert charge.voltage == 2



@pytest.mark.asyncio
async def test_Vehicle_Charge_refresh(vehicle):
    charge = vehicle.charge

    data = await charge.refresh()
    assert isinstance(data, dict)


@pytest.mark.asyncio
async def test_Vehicle_Charge_open_charge_port(vehicle):
    charge = vehicle.charge
    assert await charge.open_charge_port() is True


@pytest.mark.asyncio
async def test_Vehicle_Charge_close_charge_port(vehicle):
    charge = vehicle.charge
    assert await charge.close_charge_port() is True


@pytest.mark.asyncio
async def test_Vehicle_Charge_set_charge_limit(vehicle):
    charge = vehicle.charge

    with pytest.raises(ValueError):
        assert await charge.set_charge_limit(1337)

    assert await charge.set_charge_limit(69) is True


@pytest.mark.asyncio
async def test_Vehicle_Charge_set_standard_range_limit(vehicle):
    charge = vehicle.charge
    assert await charge.set_standard_range_limit() is True


@pytest.mark.asyncio
async def test_Vehicle_Charge_set_max_range_limit(vehicle):
    charge = vehicle.charge
    assert await charge.set_max_range_limit() is True

@pytest.mark.asyncio
async def test_Vehicle_Charge_start_charging(vehicle):
    charge = vehicle.charge
    assert await charge.start_charging() is True

@pytest.mark.asyncio
async def test_Vehicle_Charge_stop_charging(vehicle):
    charge = vehicle.charge
    assert await charge.stop_charging() is True
