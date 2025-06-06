from PySide6.QtCore import QByteArray, QBuffer, QIODevice
from PySide6.QtGui import QImage

# this file contains all flags and project global variables
SERVER_PING = "900"
SERVER_CONNECT_OK = "901"
SERVER_LOGIN_OK = "902"
SERVER_OK = "903"
SERVER_LOG_OFF_OK = "904"

CLIENT_IS_ONLINE = "800"
CLIENT_SIGN_IN_REQUEST = "801"
CLIENT_FETCH_ONLINE_USERS_REQUEST = "802"
CLIENT_CHECK_SERVER_AVAILABILITY = "803"
CLIENT_TEMPORARILY_LOGIN_REQUEST = "804"
CLIENT_LOG_OFF = "805"
CLIENT_LOGIN_REQUEST = "806"
CLIENT_PEER_MESSAGE = "807"
CLIENT_ACK_OK = "808"
CLIENT_GET_DISPLAY_NAME = "809"
CLIENT_GET_PROFILE_PICTURE = "810"

ILLEGAL_REQUEST = "700"
BUFFER = "701"

DATABASE_SIGNIN_SUCCESS = "600"
DATABASE_SIGNIN_USERNAME_CONFLICT = "601"
DATABASE_SIGNIN_FAILURE = "602"
DATABASE_LOGIN_SUCCESS = "603"
DATABASE_LOGIN_USERNAME_NOT_FOUND = "604"
DATABASE_LOGIN_PASSWORD_MISSMATCH = "605"
DATABASE_ENCRYPTION_FAILED = "606"
DATABASE_USERNAME_NOT_FOUND = "607"

MESSAGE_TYPE_TEXT = "text"
MESSAGE_TYPE_FILE = "file"

# used to print request name
def convert_to_request_name(request):
    if request == SERVER_PING:
        return "server-ping-request"
    elif request == SERVER_CONNECT_OK:
        return "server-connect-ok"
    elif request == SERVER_LOGIN_OK:
        return "server-login-ok"
    elif request == SERVER_OK:
        return "server-ok"
    elif request == SERVER_LOG_OFF_OK:
        return "server-logoff-ok"
    elif request == CLIENT_IS_ONLINE:
        return "client-is-online"
    elif request == CLIENT_SIGN_IN_REQUEST:
        return "client-sign-in-request"
    elif request == CLIENT_FETCH_ONLINE_USERS_REQUEST:
        return "client-fetch-online-users-request"
    elif request == CLIENT_CHECK_SERVER_AVAILABILITY:
        return "client-check-server-availability"
    elif request == CLIENT_TEMPORARILY_LOGIN_REQUEST:
        return "client-temporarily-login-request"
    elif request == CLIENT_LOG_OFF:
        return "client-logoff-ok"
    elif request == ILLEGAL_REQUEST:
        return "illegal-request"
    elif request == DATABASE_SIGNIN_SUCCESS:
        return "database-signin-success"
    elif request == DATABASE_SIGNIN_USERNAME_CONFLICT:
        return "database-signin-username-conflict"
    elif request == DATABASE_SIGNIN_FAILURE:
        return "database-signin-failure"
    elif request == DATABASE_LOGIN_SUCCESS:
        return "database-log-login-success"
    elif request == DATABASE_LOGIN_USERNAME_NOT_FOUND:
        return "database-log-login-username-not found"
    elif request == DATABASE_LOGIN_PASSWORD_MISSMATCH:
        return "database-log-password-mismatch"
    elif request == DATABASE_ENCRYPTION_FAILED:
        return "database-encryption-failed"
    elif request == BUFFER:
        return "buffer"
    return "invalid"

# converts QImage to bytes. used in transmitting messages through socket
def convert_q_image_to_bytes(image: QImage) -> bytes:
    byte_array = QByteArray()
    buffer = QBuffer(byte_array)
    buffer.open(QIODevice.WriteOnly)
    image.save(buffer, "PNG")
    buffer.close()
    return bytes(byte_array)