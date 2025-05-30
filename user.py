import json

class User:
    def __init__(self, is_online: bool, ip_address: str, port: int, name: str):
        self.is_online = is_online
        self.ip_address = ip_address
        self.port = port
        self.name = name

    def to_json(self) -> str:
        return json.dumps({
            "is_online": self.is_online,
            "ip_address": self.ip_address,
            "port": self.port,
            "name": self.name
        })

    def __eq__(self, other):
        if not isinstance(other, User):
            return False
        return (self.ip_address == other.ip_address and self.port == other.port and self.name == other.name and
                self.is_online == other.is_online)

    @classmethod
    def from_json(cls, string: str) -> "User":
        d = json.loads(string)
        return User(d["is_online"], d["ip_address"], d["port"], d["name"])