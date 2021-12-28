import os
import socket
import threading
from colorama import Fore, Style
from tabulate import tabulate
from modules.chat import Chat
import modules.crypto as crypto
import bson
import uuid
import yaml
import names
import requests
import hashlib

HEADER_SIZE = 1024


class Client(object):

    def __init__(self) -> None:

        self.conf = self.read_conf()
        self.format = "utf-8"

        self.host = None
        self.port = self.conf["server"]["port"]
        self.client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self.auth = None
        self.nickname = os.getlogin().lower()

        self.id = None
        self.room = "main"
        self.last_invite_room = None
        self.server_pub = requests.get("https://k43-server.de/chat/public.pem").text.replace("\\n", "\n").encode(self.format)

        self.userlist = {}
        self.chatrooms = []
        self.threads = []

        self.version = "0.1"

        self.tui = None
        self.chat = None

        self.file_directory = os.path.join(os.path.expanduser('~/Documents'), "SecureMessage")
        self.check_dir_path()

        self.unmanaged_packages = []

    def start(self):
        self.print("✅ Starting Secure-Chat Client", color="green")
        crypto.generate_key()
        self.print("\r✅ Generated key pair", color="green")
        for addr in self.conf["server"]["hosts"]:
            if addr == "localhost":
                addr = socket.gethostbyname(socket.gethostname())
            try:
                self.client.connect((addr, self.port))
                self.host = addr
                break
            except socket.error:
                continue
        if not self.host:
            self.print("[-] Could not connect to server", color="red")
            return
        self.print("✅ Connected to {}".format(self.host), color="green")
        if self.conf["user"]["use-random"] is None:
            use_random_nick = input("Do you want to use a random nickname? [Y/n]: ")
            if use_random_nick.lower() == "y" or use_random_nick == "":
                self.conf["user"]["use-random"] = True
            else:
                self.conf["user"]["use-random"] = False
        if self.conf["user"]["tui"] is None:
            tui = input("Do you want to use the terminal interface? [Y/n]: ")
            if tui.lower() == "y" or tui == "":
                self.conf["user"]["tui"] = True
            else:
                self.conf["user"]["tui"] = False
        self.tui = self.conf["user"]["tui"]
        if self.tui:
            self.chat = Chat()
        self.auth = input("Verification code: ")

        if self.conf["user"]["use-random"]:
            self.nickname = names.get_first_name().lower()

        self.threads.append(threading.Thread(target=self.thread_receive).start())
        self.threads.append(threading.Thread(target=self.thread_handle_package).start())
        if self.tui:
            self.chat.tb.start()
            self.chat._change_user_name(f"{self.nickname}@{self.room}")
            self.chat._change_user_name("{}@{}".format(self.nickname, self.room))
            self.chat._update_user_list(self.userlist, self.room)
            self.chat.writeCallBack = self.thread_user_input
            self.chat.tb.update()
        else:
            self.threads.append(threading.Thread(target=self.thread_user_input).start())
        self.save_conf()

    ###################
    # BASIC FUNCTIONS #
    ###################

    def recv(self):
        header = int.from_bytes(self.client.recv(HEADER_SIZE), "big")
        package = bson.loads(self.client.recv(header))
        return package

    def send(self, packet_type, packet_data):
        package = bson.dumps({"type": packet_type, "data": packet_data})
        header = len(package).to_bytes(HEADER_SIZE, "big")

        self.client.send(header)
        self.client.send(package)
        return True

    def broadcast(self, package_type="message", package_data=None):
        for user in self.userlist.values():
            if user["room"] == self.room:
                if package_type == "message":
                    crypto.generate_aes_key()
                    package_data["messagedata"], package_data["nonce"] = crypto.aes_encrypt(package_data["messagedata"])
                    package_data["key"] = crypto.encrypt(crypto.AES_KEY, user["key"])
                    package_data["fingerprint"] = crypto.aes_encrypt(package_data["fingerprint"])
                if package_type == "file":
                    crypto.generate_aes_key()
                    package_data["name"] = crypto.encrypt(package_data["name"], user["key"])
                    package_data["filedata"], package_data["nonce"] = crypto.aes_encrypt(package_data["filedata"])
                    package_data["key"] = crypto.encrypt(crypto.AES_KEY, user["key"])
                self.send(package_type, {"message": package_data, "id": user["id"]})

    def print(self, text, color="white"):
        if self.tui and self.chat.tb.started:
            self.chat.print(text, color)
        else:
            if color == "dim":
                print("{}{}{}".format(Style.DIM, text, Style.RESET_ALL))
            elif color == "green":
                print("{}{}{}".format(Fore.GREEN, text, Style.RESET_ALL))
            elif color == "red":
                print("{}{}{}".format(Fore.RED, text, Style.RESET_ALL))
            elif color == "yellow":
                print("{}{}{}".format(Fore.YELLOW, text, Style.RESET_ALL))
            elif color == "cyan":
                print("{}{}{}".format(Fore.CYAN, text, Style.RESET_ALL))
            elif color == "magenta":
                print("{}{}{}".format(Fore.MAGENTA, text, Style.RESET_ALL))
            elif color == "light-magenta":
                print("{}{}{}".format(Fore.LIGHTMAGENTA_EX, text, Style.RESET_ALL))
            else:
                print(text)

    ###########
    # THREADS #
    ###########

    def thread_handle_package(self):
        while True:
            if len(self.unmanaged_packages) > 0:
                message = self.unmanaged_packages.pop(0)

                if message["type"] == "message":
                    data = message["data"]
                    data["key"] = crypto.decrypt(data["key"], decodeData=False)
                    dec_message = crypto.aes_decrypt(data["messagedata"], data["key"], data["nonce"], True)
                    self.print(str(dec_message), color=["white", "bold"])
                    continue

                elif message["type"] == "file":
                    data = message["data"]
                    data["key"] = crypto.decrypt(data["key"], decodeData=False)
                    file = open(f'{self.file_directory}/{crypto.decrypt(data["name"])}{data["ext"]}', 'wb')
                    decr = crypto.aes_decrypt(data["filedata"], data["key"], data["nonce"], False)
                    fingerprint = hashlib.sha256(decr).hexdigest()
                    if fingerprint == data["fingerprint"]:
                        self.print("Hash matches", color="green")
                    else:
                        self.print("Hash does not match", color="red")
                    file.write(decr)
                    self.print(f"Received file {crypto.decrypt(data['name'])}{data['ext']}")
                    file.close()

                elif message["type"] == "nick-change":
                    nickname = message["data"]
                    if self.tui:
                        self.chat._change_user_name(f"{nickname}@{self.room}")

                elif message["type"] == "error":
                    self.print(message["data"], color="red")
                    self.client.close()

                elif message["type"] == "accepted":
                    self.print(f"{self.nickname} joined!", color="cyan")
                    continue

                elif message["type"] == "server-auth":
                    self.send("key", crypto.public_key)
                    continue

                elif message["type"] == "info":
                    self.send(
                        "info",
                        {"nickname": crypto.encrypt(self.nickname, self.server_pub),
                         "version": self.version,
                         "2fa": crypto.encrypt(self.auth, self.server_pub)})
                    continue

                elif message["type"] == "key":
                    key = message["data"]["pub_key"]
                    id = message["data"]["id"]
                    user_nickname = message["data"]["nickname"]
                    room = message["data"]["room"]
                    self.userlist[id] = {
                        "key": key,
                        "nick": user_nickname,
                        "room": room,
                        "id": id}
                    if self.tui:
                        self.chat._update_user_list(self.userlist, self.room)
                    continue

                elif message["type"] == "remove-user":
                    user_id = message["data"]["id"]
                    try:
                        self.print("{} left".format(
                            self.userlist[user_id]["nick"]), color="cyan")
                        del self.userlist[user_id]
                    except KeyError:
                        pass
                    if self.tui:
                        self.chat._update_user_list(self.userlist, self.room)
                    continue

                elif message["type"] == "remove-all":
                    self.userlist = {}
                    continue

                elif message["type"] == "new-room":
                    if not message["data"] in self.chatrooms:
                        self.chatrooms.append(message["data"])
                    continue

                elif message["type"] == "del-room":
                    if message["data"] in self.chatrooms:
                        self.chatrooms.remove(message["data"])

                elif message["type"] == "room-change":
                    self.room = message["data"]
                    self.print("Joined room {}".format(message["data"]), color="green")
                    if self.tui:
                        self.chat._change_user_name(
                            "{}@{}".format(self.nickname, message["data"]))
                        self.chat._update_user_list(self.userlist, self.room)
                    continue

                elif message["type"] == "notification":
                    self.print(message["data"], color="cyan")
                    continue

                elif message["type"] == "warning":
                    self.print(message["data"], color="yellow")
                    continue

                elif message["type"] == "user-info-change":
                    # self.print(pub_keys[message["data"]["id"]])
                    if message["data"]["id"] in self.userlist:
                        self.userlist[message["data"]["id"]] = message["data"]["user"]
                        if self.tui:
                            self.chat._update_user_list(self.userlist, self.room)

                elif message["type"] == "nick-warning":
                    self.print("Nickname already taken", color="yellow")
                    self.print(
                        "Your new nickname: {}".format(
                            message["data"]
                        ), color="cyan"
                    )
                    self.print("You can change it using /nick", color="cyan")
                    self.nickname = message["data"]
                    if self.tui:
                        self.chat._change_user_name("{}@{}".format(self.nickname, self.room))

                elif message["type"] == "invite-req":
                    self.print(
                        "Got invited to room: {}".format(message["data"]),
                        color="green",
                    )
                    self.last_invite_room = message["data"]

                else:
                    self.print("Could not resolve message")
                    continue

    def thread_receive(self):
        while True:
            try:
                package = self.recv()
                self.unmanaged_packages.append(package)
            except socket.error:
                self.print("[-] Disconnected from Server", color="red")
                return

    def thread_user_input(self, user_input=None):
        while True:
            if not self.tui:
                user_input = input("")
            if user_input.startswith("/"):
                cmd = user_input.replace("/", "").lower()
                self.handle_command(cmd.strip())
            elif len(user_input) > 0:
                if self.tui:
                    self.print(f"[{self.nickname}] {user_input}",
                               color=["white", "bold"])
                self.broadcast("message", {"messagedata": "{}: {}".format(self.nickname, user_input)})
            if self.tui:
                return

    ###################
    # EXTRA FUNCTIONS #
    ###################

    def check_dir_path(self):
        if not os.path.exists(self.file_directory):
            self.print("Created directory for files at {}".format(self.file_directory.replace("/", "\\")), color="cyan")
            os.mkdir(self.file_directory)

    def handle_command(self, cmd):
        if cmd == "exit":
            self.client.close()

        elif cmd == "leave":
            self.send("leave", None)

        elif cmd == "clear":
            if self.tui:
                self.chat.tb.clear_text_items("setup", "Chat")
            else:
                os.system("cls" if os.name == "nt" else "clear")

        elif cmd == "help":
            commands = [
                ["/clear", "clear terminal"],
                ["/whisper <nickname>", "whisper to a user"],
                ["/chatroom <name>", "create room"],
                ["/invite <nickname>", "invite user to room *"],
                ["/join", "join chatroom"],
                ["/kick <username>", "kick user from room *"],
                ["/block <name>", "block user"],
                ["/nick <nickname>", "change nickname"],
                ["/file <filepath>", "send file"],
                ["/list", "list users"],
                ["/leave", "leave room"],
                ["/exit", "exit chat"],
            ]
            table = tabulate(commands, tablefmt="plain")
            for line in table.split("\n"):
                self.print(line, color="magenta")
            self.print("* Requires admin priviliges", color="yellow")

        elif cmd == "list":
            room_list = {self.room: ["you"]}
            for user in self.userlist.values():
                if user["room"] in room_list:
                    room_list[user["room"]].append(user["nick"])
                else:
                    room_list[user["room"]] = [user["nick"]]
            for key, value in room_list.items():
                if key == self.room and not self.tui:
                    self.print(f"{key}: {', '.join(value)}", color="light-magenta")
                else:
                    self.print(f"{key}: {', '.join(value)}", color="magenta")

        elif cmd.startswith("whisper"):
            try:
                name = cmd.split(" ")[1]
            except BaseException:
                self.print("[-] Invalid input", color="yellow")
                return
            whisper_id = None
            whisper_room = None
            for id in self.userlist:
                if self.userlist[id]["nick"] == name:
                    whisper_id = id
                    whisper_room = self.userlist[id]["room"]
                    break
            if whisper_id:
                msg = cmd
                msg = msg.replace(name, "").replace("whisper", "").strip()
                self.print("You whispered to {}: {}".format(
                    name, msg), color="magenta")
                self.send(
                    "message",
                    {
                        "message": "{} whispered to you: {}".format(
                            self.nickname, msg
                        ),
                        "id": whisper_id,
                        "room": whisper_room
                    },
                )
            else:
                self.print("[-] Could not find user", color="yellow")

        elif cmd.startswith("chatroom"):
            if not len(cmd.split(" ")) == 2:
                self.print("[-] Invalid chatroom name", color="yellow")
                return
            name = cmd.split(" ")[1]
            self.send("create-chatroom", name)

        elif cmd.startswith("nick"):
            if not len(cmd.split(" ")) == 2:
                self.print("[-] Invalid chatroom name", color="yellow")
                return
            name = cmd.split(" ")[1]
            for user in self.userlist:
                if self.userlist[user]["nick"] == name:
                    self.print("Nickname already taken", color="yellow")
                    return
            nickname = name
            self.send("nick-change", crypto.encrypt(name, self.server_pub))

        elif cmd.startswith("invite"):
            try:
                name = cmd.split(" ")[1]
            except BaseException:
                self.print("[-] Invalid input")
                return
            whisper_id = None
            whisper_room = None
            for id in self.userlist:
                if self.userlist[id]["nick"] == name:
                    whisper_id = id
                    whisper_room = self.userlist[id]["room"]
                    break
            if whisper_id:
                self.send(
                    "invite",
                    {
                        "room": self.room,
                        "id": whisper_id,
                        "invite_room": whisper_room},
                )
            else:
                self.print("[-] Could not find user", color="yellow")

        elif cmd.startswith("join"):
            name = None
            if len(cmd.split(" ")) == 2:
                name = cmd.split(" ")[1]
            if self.last_invite_room:
                name = self.last_invite_room
            if not name:
                self.print("[-] Invalid input", color="yellow")
            self.send(
                "join",
                name,
            )

        elif cmd.startswith("file"):
            if len(cmd.split(" ")) > 1:
                path = cmd.replace("file", "").replace('"', '').strip()
                exists = os.path.exists(path)
                if exists:
                    data = open(path, 'rb')
                    l = data.read()
                    fingerprint = hashlib.sha256(l).hexdigest()
                    size = os.path.getsize(path)
                    if size > 150000000:  # 150 MB
                        self.print("[-] Filesize to big (max 150MB)", color="yellow")
                        return
                    ext = os.path.splitext(path)[1]
                    # name = path.replace("\\", "/").split("/")[-1].replace(ext, "")
                    name = str(uuid.uuid4())
                    self.broadcast("file", {
                        "filedata": l, "name": name, "ext": ext, "fingerprint": fingerprint})
                else:
                    self.print("[-] File does not exist", color="yellow")
            else:
                self.print("[-] Invalid input", color="yellow")

        else:
            self.print(
                "[-] Could not find command. Type /help for list of commands",
                color="yellow")

    def read_conf(self):
        with open('config.yaml', 'r') as file:
            try:
                conf = yaml.safe_load(file)
                return conf
            except yaml.YAMLError as exc:
                print(exc)

    def save_conf(self):
        with open(r"config.yaml", 'w') as file:
            try:
                yaml.dump(self.conf, file)
            except yaml.YAMLError as exc:
                print(exc)


client = Client()
client.start()
