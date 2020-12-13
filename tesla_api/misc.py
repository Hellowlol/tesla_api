"""Misc helpers."""


class Dict(dict):
    """Just a helper that includes a tip in KeyError excetion to the user."""
    def __init__(self, arg):
        super().__init__(arg)

    def __missing__(self, key):
        raise KeyError(f"{key} is missing. Try using vehicle.refresh()")


def mile_to_km(value):
    """Convert from mile to km"""
    return value / 1.6093


def km_to_mile(value):
    """Convert from km to mile"""
    return value * 0.621371


def c_to_f(value):
    """Convert celsius to farenheit"""
    return value * 1.8 + 32


def cast(value):
    """Helper"""
    if isinstance(value, str):
        return False if value == "0" else True
    if isinstance(value, int):
        return value != 0
    raise ValueError("%s expects value that can be bool")