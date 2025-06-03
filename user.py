from timestamp import Timestamp

# a default user class. useful for offline users.
class User:
    def __init__(self, username: str, name:str, public_key: str, profile_picture, last_seen: Timestamp):
        self.username = username
        self.name = name
        self.public_key = public_key
        self.profile_picture = profile_picture
        self.last_seen = last_seen
        self.is_online = False