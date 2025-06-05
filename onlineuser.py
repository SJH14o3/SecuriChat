import json
from timestamp import Timestamp
from user import User

# online user class
class OnlineUser(User):
    def __init__(self, ip_address: str, port: int, name: str, username: str, public_key: str, profile_picture,
                 last_seen: Timestamp):
        super().__init__(username, name, public_key, profile_picture, last_seen)
        self.ip_address = ip_address
        self.port = str(port)  # Convert port to string
        self.name = name
        self.username = username
        self.public_key = public_key
        self.profile_picture = profile_picture
        self.is_online = True

    # converts the class to json
    def to_json(self):
        return json.dumps({
            "ip_address": self.ip_address,
            "port": self.port,
            "name": self.name,
            "username": self.username,
            "public_key": self.public_key
        })
    # used to identify user only based on their address
    def address_is_equal(self, port: int, ip_address):
        return ip_address == self.ip_address and str(port) == self.port

    def __str__(self):
        return f"user: {self.username}, name: {self.name}, ip_address: {self.ip_address}, port: {self.port}"

    def __eq__(self, other):
        if not isinstance(other, OnlineUser):
            return False
        return self.username == other.username and self.ip_address == other.ip_address and self.port == other.port

    def compare_usernames(self, user: User) -> bool:
        return user.username == self.username

    # creates a user instance from json input
    @classmethod
    def from_json(cls, string: str) -> "OnlineUser":
        d = json.loads(string)
        return OnlineUser(d["ip_address"], d["port"], d["name"], d["username"], d["public_key"], None, Timestamp.get_now())