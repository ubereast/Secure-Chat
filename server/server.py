import names
import bson
import threading
import socket
import modules.crypto as crypto
import time
import hmac
import sys
import uuid
import os
import dotenv
dotenv.load_dotenv("../.env")
bson.patch_socket()

HEADER_SIZE = 1024


class Client():
    def __init__(self, client, addr) -> None:

        self.socket = client
        self.addr = addr
        self.id = None
        self.nickname = None
        self.public_key = None
        self.room = None

    def send(self, package_type, package_data):
        package = bson.dumps({"type": package_type, "data": package_data})
        header = len(package).to_bytes(HEADER_SIZE, "big")

        try:
            self.socket.send(header)
            self.socket.send(package)
        except socket.error:
            raise socket.error

        return True

    def recv(self):
        try:
            header = int.from_bytes(self.socket.recv(HEADER_SIZE), "big")
            package = bson.loads(self.socket.recv(header))
        except socket.error:
            raise socket.error

        return package


class Server():
    def __init__(self) -> None:

        self.debug = True

        self.host = socket.gethostbyname(socket.gethostname())
        self.port = 10127
        self.format = "utf-8"

        self.version = "0.1"

        try:
            self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.server.bind((self.host, self.port))
            self.server.listen()
        except Exception:
            print("Coult not bind server to {} -p {}".format(self.host, self.port))
            sys.exit()

        self.connections = {"main": {"admin": None, "clients": {}, "invited-ids": []}}
        self.connection_history = {}
        self.connection_ban_time = 120

        self.authkey = os.environ["authkey"].encode(self.format)

        self.threads = [
            threading.Thread(target=self.listen),
            threading.Thread(target=self.checks)
        ]

        self.public_key = None

    def start(self):
        crypto.generate_key()
        self.public_key = crypto.public_key

        for thread in self.threads:
            thread.start()

    ###################
    # BASIC FUNCTIONS #
    ###################

    def listen(self):
        print(f"✓ Listening on {self.host} port {self.port}")
        failed = 0
        while True:
            try:
                client, address = self.server.accept()
                address = address[0]
                client = Client(client=client, addr=address)
                if not self.fail2ban(address):
                    client.send("error", "[-] Connection refused")
                    continue
                failed = 0
                threading.Thread(
                    target=self.login,
                    args=(client, )
                ).start()
            except:
                print("[-] Error while waiting for users\r")
                failed += 1
                if failed > 10:
                    return
                continue

    def login(self, client):
        """"""
        try:
            # SERVER KEY EXCHANGE
            client.send("server-auth", None)
            pub_key = client.recv()["data"]

            # CLIENT INFO RECV
            client.send("info", None)
            client_info = client.recv()["data"]

            # CLIENT INFO DECRYPTION
            client_info["nickname"] = crypto.decrypt(client_info["nickname"]).strip()
            client_info["2fa"] = crypto.decrypt(client_info["2fa"])

            if len(client_info["nickname"]) == 0:
                client.send("error", "[-] Please enter nickname")

            if client_info["version"] != self.version:
                client.send("error", "[-] Please update your client")
                return

            if client_info["nickname"] != client_info["nickname"].lower():
                client_info["nickname"] = client_info["nickname"].lower()
                client.send("nick-change", client_info["nickname"])

            def nick_dup(nick):
                for room in self.connections:
                    for client_id in self.connections[room]["clients"]:
                        if self.connections[room]["clients"][client_id].nickname == nick:
                            return True
                return False

            # CHECK NICKNAME DUPLICATE
            nick_change = False
            while nick_dup(client_info["nickname"]):
                nick_change = True
                client_info["nickname"] = names.get_first_name().lower()

            if nick_change:
                client.send("nick-warning", client_info["nickname"])

            # 2FA
            if not self.debug:
                if not str(client_info["2fa"]) == str(self.totp()):
                    client.send("error", "[-] Invalid 2FA key")
                    return

            id = str(uuid.uuid4())

            # CLIENT OBJECT
            client.nickname = client_info["nickname"]
            client.public_key = pub_key
            client.id = id
            client.room = "main"

            # PUBLIC-KEY EXCHANGE
            self.key_exchange(client)

            # CHATROOM LIST EXCHANGE
            for room in self.connections:
                client.send("new-room", room)

            # JOIN MESSAGE
            self.broadcast(
                "notification",
                "{} joined!".format(client_info["nickname"]),
                client,
                "main",
            )
            self.connections["main"]["clients"][id] = client

            # REM CONNECTION HISTORY
            try:
                del self.connection_history[client.addr]
            except KeyError:
                pass

            # USER RECV/SEND THREAD
            try:
                client.send("accepted", None)
                threading.Thread(target=self.handle, args=(client,)).start()
            except Exception:
                pass

        except socket.error:
            pass

    def broadcast(self, package_type, package_data, client, room):
        if room is None:
            for room in self.connections:
                for user in self.get_clients(room):
                    user.send(package_type, package_data)
            return
        for id, user in self.connections[room]["clients"].items():
            if client is not None:
                if id == client.id and not id is None:
                    continue
            try:
                user.send(package_type, package_data)
            except Exception:
                pass

    def handle(self, client):
        while True:
            try:
                message = client.recv()
                if message is None:
                    raise socket.error
                if message["type"] == "message":
                    try:
                        room = client.room
                        if room in message["data"]:
                            room = message["data"]["room"]
                        self.connections[room]["clients"][message["data"]["id"]].send("message", message["data"]["message"])
                    except KeyError:
                        pass
                elif message["type"] == "create-chatroom":
                    self.remove_empty()
                    if message["data"] in self.connections:
                        client.send("warning",
                                    "[-] Chatroom name already in use")
                        continue
                    self.connections[message["data"]] = {
                        "admin": client.id,
                        "clients": {client.id: client},
                        "invited-ids": [],
                    }
                    self.join_room(client, message["data"])
                    self.broadcast("new-room", message["data"], client, None)
                elif message["type"] == "nick-change":
                    message["data"] = crypto.decrypt(message["data"])
                    if len(message["data"].strip()) == 0:
                        continue
                    is_in_use = False
                    for room in self.connections.values():
                        for client_id in room["clients"].values():
                            if (client_id.nickname == message["data"]):
                                client.send("warning", "Nickname already taken")
                                is_in_use = True
                                break
                    if not is_in_use:
                        self.broadcast(
                            "notification",
                            "{} is now known as {}".format(client.nickname, message["data"]),
                            None,
                            None,
                        )
                        self.broadcast(
                            "user-info-change",
                            {
                                "id": client.id,
                                "user": {
                                    "id": client.id,
                                    "key": client.public_key,
                                    "nick": message["data"],
                                    "room": client.room,
                                },
                            },
                            client,
                            None,
                        )
                        client.nickname = message["data"]
                        client.send("nick-change", client.nickname)
                elif message["type"] == "invite":
                    if not self.connections[client.room]["admin"] == client.id:
                        continue
                    self.connections[message["data"]["room"]]["invited-ids"].append(
                        message["data"]["id"]
                    )
                    self.connections[message["data"]["invite_room"]]["clients"][message["data"]["id"]].send(
                        "invite-req",
                        message["data"]["room"]
                    )
                elif message["type"] == "join":
                    if not message["data"] in self.connections:
                        client.send("warning", "room does not exist")
                        continue
                    if client.id in self.connections[message["data"]]["invited-ids"]:
                        self.connections[message["data"]]["invited-ids"].remove(client.id)
                        self.join_room(client, message["data"])
                        self.broadcast(
                            "notification",
                            "{} joined the room".format(client.nickname), client, message["data"])
                    else:
                        client.send(
                            "warning",
                            "You are not allowed to join this room!",
                        )
                elif message["type"] == "leave":
                    if client.room == "main":
                        continue
                    self.broadcast(
                        "notification",
                        "{} left the room".format(client.nickname),
                        client,
                        client.room,
                    )
                    client.send("notification", "You left the room")
                    self.join_room(client, "main")
                    self.remove_empty()
                elif message["type"] == "file":
                    if message["data"]["id"] in self.connections[client.room]["clients"]:
                        message["data"]["message"]["id"] = client.id
                        self.connections[client.room]["clients"][message["data"]["id"]].send("file", message["data"]["message"])
                elif message["type"] == "file-received":
                    self.connections[client.room]["clients"][message["data"]["id"]].send("file-received", None)
                else:
                    client.send("warning", "Invalid message type")
            except socket.error:
                try:
                    del self.connections[client.room]["clients"][client.id]
                except KeyError:
                    pass
                self.broadcast(
                    "remove-user",
                    {
                        "id": client.id,
                        "room": client.room
                    },
                    client,
                    None,
                )
                self.remove_empty()
                return

    ###################
    # EXTRA FUNCTIONS #
    ###################

    def fail2ban(self, addr):
        if not addr in self.connection_history:
            self.connection_history[addr] = [time.time() / 1000]
            return True
        else:
            self.connection_history[addr].append(time.time() / 1000)
        last60seconds = 0
        for timestamp in self.connection_history[addr]:
            if time.time() / 1000 - timestamp < self.connection_ban_time:
                last60seconds += 1
            else:
                self.connection_history[addr].remove(timestamp)
        if last60seconds > 5:
            return False
        return True

    def key_exchange(self, client):
        for key, room in self.connections.items():
            for id, user in room["clients"].items():
                if id == client.id:
                    continue
                try:
                    user.send("key", {"pub_key": client.public_key, "id": client.id, "nickname": client.nickname, "room": client.room})
                    client.send("key", {"pub_key": user.public_key, "id": user.id, "nickname": user.nickname, "room": user.room})
                except Exception:
                    pass

    def join_room(self, client, room):
        del self.connections[client.room]["clients"][client.id]
        client.room = room
        self.connections[room]["clients"][client.id] = client
        self.broadcast("user-info-change", {"id": client.id, "user": {"key": client.public_key, "nick": client.nickname, "room": client.room}}, client, None)
        time.sleep(0.2)
        client.send("room-change", room)

    def totp(self):
        now = int(time.time() // 30)
        msg = now.to_bytes(8, "big")
        digest = hmac.new(self.authkey, msg, "sha1").digest()
        offset = digest[19] & 0xF
        code = digest[offset: offset + 4]
        code = int.from_bytes(code, "big") & 0x7FFFFFFF
        code = code % 1000000
        return "{:06d}".format(code)

    def get_clients(self, room):
        clients = []
        for client in self.connections[room]["clients"].values():
            clients.append(client)
        return clients

    def remove_empty(self):
        empty = []
        for room in self.connections:
            if room == "main":
                continue
            if len(self.connections[room]["clients"]) == 0:
                empty.append(room)
                self.broadcast("del-room", room, None, None)
        for room in empty:
            del self.connections[room]

    def checks(self):
        while True:
            self.remove_empty()
            for thread in self.threads:
                if not thread.is_alive():
                    thread.start()
            time.sleep(60)


if __name__ == "__main__":
    server = Server()
    server.start()
