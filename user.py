import json

# a user class
class User:
    def __init__(self, is_online: bool, ip_address: str, port: int, name: str):
        self.is_online = is_online
        self.ip_address = ip_address
        self.port = port
        self.name = name

    # converts the class to json
    def to_json(self) -> str:
        return json.dumps({
            "is_online": self.is_online,
            "ip_address": self.ip_address,
            "port": self.port,
            "name": self.name
        })
    # used to identify user only based on their address
    def address_is_equal(self, port: int, ip_address):
        return ip_address == self.ip_address and port == self.port

    def __str__(self):
        return self.to_json()

    def __eq__(self, other):
        if not isinstance(other, User):
            return False
        return (self.ip_address == other.ip_address and self.port == other.port and self.name == other.name and
                self.is_online == other.is_online)

    # creates a user instance from json input
    @classmethod
    def from_json(cls, string: str) -> "User":
        d = json.loads(string)
        return User(d["is_online"], d["ip_address"], d["port"], d["name"])