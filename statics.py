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

ILLEGAL_REQUEST = "700"

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
    return "invalid"