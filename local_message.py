from timestamp import Timestamp

class LocalMessage:
    def __init__(self, message_id: int, recipient_username: str = None, message_type: int = 0, 
                 is_income: bool = False, message: str = None, timestamp: Timestamp = None, 
                 is_read: bool = True, sender_id: str = None, recipient_id: str = None,
                 content: str = None, chunks_received: int = None, total_chunks: int = None,
                 file_path: str = None, file_size: int = None, file_name: str = None):
        # Support both old and new schema
        self.message_id = message_id
        self.recipient_username = recipient_username  # For backward compatibility
        self.sender_id = sender_id or recipient_username
        self.recipient_id = recipient_id or recipient_username
        self.message_type = message_type
        self.is_income = is_income
        self.message = message or content  # Support both old and new field names
        self.content = content or message  # Support both old and new field names
        self.timestamp = timestamp or Timestamp.get_now()
        self.is_read = is_read
        # File transfer related fields
        self.chunks_received = chunks_received
        self.total_chunks = total_chunks
        self.file_path = file_path
        self.file_size = file_size
        self.file_name = file_name 