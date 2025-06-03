import time
from typing import List
from onlineuser import OnlineUser
from threading import Lock
from datetime import datetime

# log class. each client and server will have one of this class
class Log:
    def __init__(self, path):
        self.path = f"logs/{path}.log" # for server, log is saved into server.log and for client is saved to {it's port}.log
        self.lock = Lock() # lock is needed since app is multithreaded

    # append log to the path
    def append_log(self, message):
        with self.lock:
            with open(self.path, "a") as log:
                log.write(f"{TimeUtils.get_readable_time()}->{message}\n")

    # converts a user list into a single string
    @staticmethod
    def get_users_as_single_string(users: List[OnlineUser]):
        out = []
        if len(users) == 0:
            return "no users"
        for user in users:
            out.append(user.__str__())
        return "users: " + ','.join(out)

    def append_users_logs(self, header, users: List[OnlineUser]):
        with self.lock:
            with open(self.path, "a") as log:
                log.write(f"{TimeUtils.get_readable_time()}->{header}: {self.get_users_as_single_string(users)}\n")

# used to get current time in a comprehensible format
class TimeUtils:
    @staticmethod
    def get_readable_time():
        current_time = time.time()
        dt = datetime.fromtimestamp(current_time)
        readable_time = dt.strftime('%Y-%m-%d %H:%M:%S') + f'.{dt.microsecond // 1000:03d}'
        return readable_time