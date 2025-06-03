from datetime import datetime
# timestamp class used for user last seen and messages. stored in a 14 digit integer (8 bytes)
class Timestamp:
    def __init__(self, time_stamp: int):
        self.timestamp = time_stamp

    def __str__(self) -> str:
        return str(self.timestamp)

    def get_year(self) -> int:
        return self.timestamp // 10**10  # First 4 digits

    def get_month(self) -> int:
        return (self.timestamp // 10 ** 8) % 100  # 5th–6th digits

    def get_day(self) -> int:
        return (self.timestamp // 10 ** 6) % 100  # 7th–8th digits

    def get_hour(self) -> int:
        return (self.timestamp // 10 ** 4) % 100  # 9th–10th digits

    def get_minute(self) -> int:
        return (self.timestamp // 10 ** 2) % 100  # 11th–12th digits

    def get_second(self) -> int:
        return self.timestamp % 100  # 13th–14th digits

    def get_date(self) -> int:
        return self.timestamp // 10 ** 6

    def get_time_pretty(self, seconds: bool = False) -> str:
        return f"{self.get_hour():02d}:{self.get_month():02d}:{self.get_second():02d}" if seconds else f"{self.get_hour():02d}:{self.get_month():02d}"

    # create instance base on input string
    @staticmethod
    def convert_string_timestamp(input_str: str):
        return Timestamp(int(input_str))

    # create instance with input time
    @staticmethod
    def create_instance_with_time(year: int, month: int, day: int, hour: int, minute: int, second: int):
        tm = [f"{year:04d}", f"{month:02d}", f"{day:02d}", f"{hour:02d}", f"{minute:02d}", f"{second:02d}"]
        return Timestamp.convert_string_timestamp(''.join(tm))

    # create right now time stamp
    @staticmethod
    def get_now():
        return Timestamp.convert_string_timestamp((datetime.now().strftime("%Y%m%d%H%M%S")))

