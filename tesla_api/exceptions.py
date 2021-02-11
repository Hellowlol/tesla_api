class AuthenticationError(Exception):
    def __init__(self, error):
        super().__init__('Authentication to the Tesla API failed: {}'.format(error))


class ApiError(Exception):
    def __init__(self, error):
        super().__init__('Tesla API call failed: {}'.format(error))
        self.reason = error


class VehicleUnavailableError(Exception):
    def __init__(self):
        super().__init__('Vehicle failed to wake up.')


class MissingCredentials(Exception):
    def __init__(self, error):
        super().__init__("Missing username and/or password")


class AuthenticationBlockedError(Exception):
    def __init__(self, error):
        super().__init__('Authentication to the Tesla API failed: {}'.format(error))
