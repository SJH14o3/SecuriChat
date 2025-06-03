import json
from timestamp import Timestamp
from user import User

# online user class
class OnlineUser(User):
    def __init__(self, ip_address: str, port: int, name: str, username: str, public_key: str, profile_picture,
                 last_seen: Timestamp):
        super().__init__(username, name, public_key, profile_picture, last_seen)
        self.ip_address = ip_address
        self.port = port
        self.name = name
        self.username = username
        self.public_key = public_key
        self.profile_picture = profile_picture
        self.is_online = True

    # converts the class to json
    def to_json(self) -> str:
        return json.dumps({
            "ip_address": self.ip_address,
            "port": self.port,
            "name": self.name,
            "username": self.username,
            "public_key": self.public_key,
            "profile_picture": self.profile_picture,
        })
    # used to identify user only based on their address
    def address_is_equal(self, port: int, ip_address):
        return ip_address == self.ip_address and port == self.port

    def __str__(self):
        return self.to_json()

    def __eq__(self, other):
        if not isinstance(other, OnlineUser):
            return False
        return self.ip_address == other.ip_address and self.port == other.port and self.name == other.name

    def compare_usernames(self, user: User) -> bool:
        return user.username == self.username

    # creates a user instance from json input
    @classmethod
    def from_json(cls, string: str) -> "OnlineUser":
        d = json.loads(string)
        return OnlineUser(d["ip_address"], d["port"], d["name"], d["username"], d["public_key"], d["profile_picture"], Timestamp.get_now())