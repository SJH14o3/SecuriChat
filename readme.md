# SecuriChat
a Computer Networks project
by Sajjad Jalili and Sina Ghani Abadi

## Server
first server will reset logs folder and creates database if it doesn't exist.
then it will start a thread to ping every online user every three seconds. if a user don't respond, they will be removed as an online user.
when a user signs in or logs in, they will be added to online users. their listening socket address will be stored.
on main thread, server will await for clients to connect and creates a new thread when a user is connected.
when a user signs in, it will store their information on server database.
password and email address for each user are encrypted.
when a user want to log in, first server check that username exists and then checks if password matches.


## Client
when a client starts running, first it will check if server is online, then it will prompt the user to sign-in or login.
note that username, password and emails all have regex. user can also select an image as profile.
upon signing in, a local database, private and public RSA keys and an AES key will be made.
upon logging in/signing in, a temporary folder for storing medias will be made and a log file with listener port will be made too.
every five seconds, a client will fetch all online users from server to allow peer to peer connection.
clients can select a user to start chat with, and they can see their previous chats. they can only send message or media to online users.
online users are marked with a green circle. when a message is sent, onion routing will be applied to it.
messages are stored on both sides local database. the message content will be encrypted.
when a user receive a message, they will be notified.
upon logging off, temporary folder will be deleted and a message will be sent to server about logging out.


## TCP Connection
all socket connection use TCP protocol especially because this is a reliable chat program.
for sending large datas like images or videos, message is divided into chunks and chunks are sent one by one and
the sender will receive them one by one and reassemble them into one message.

## Onion Routing
We use an onion routing system for secure, anonymous message transmission, inspired by protocols like Tor. Onion routing ensures that messages are encrypted in multiple layers and routed through several nodes, concealing the sender, recipient, and content from intermediaries. In the provided onion routing mechanism, error detection and checksums ensure message integrity and detect corruption or tampering during transmission.
by default the messages go past through 2 middle nodes that means that the messages are encrypted and decrypted twice from the sender to the receiver.

## P2P Connection
The Peer to Peer each logged in user will sets up a listening socket to accept incoming connections,
to handles server pings, and processes encrypted messages from peers. Messages are received in chunks, decrypted using a private key, stored in a local database, and acknowledged to the sender. It sends encrypted messages to peers in chunks, confirms delivery with acknowledgments, and stores sent messages locally. Peer information (IP, port, public key) is managed, and connections can be stopped, with all actions logged for debugging.