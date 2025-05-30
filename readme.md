# SecuriChat
a Computer Networks project
by Sajjad Jalili and Sina Ghani Abadi

## Server
server will await for clients to connect

## Client
when a client starts running, first it will check if server is online, then it will prompt the user to sign-in or login

### fetching online users
every three seconds, server will ping all clients. if clients don't response, server will assume that they are offline.
every five seconds, a client will fetch all online users from server. all online users are sent in one message
from server since this project is not large scaled