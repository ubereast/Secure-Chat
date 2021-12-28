import modules.terminalTextBoxes as ttb
import threading


class Chat:
    """ """

    def __init__(self, userName="", debug=False):
        """ """
        self.tb = ttb.TerminalTextBoxes(
            userName, self.character_callback, self.enter_callback
        )
        self.tb.create_text_box_setup("setup")

        self.tb.create_text_box(
            "setup", "Chat", hOrient=ttb.H_ORIENT["left"],
            wTextIndent=1, frameAttr="blue", frameChar="singleLine")
        self.tb.create_text_box(
            "setup", "Online", 20, frameAttr="red", hOrient=ttb.H_ORIENT
            ["right"])
        # self.tb.create_text_box(
        #     "setup", "Chatrooms", 15, frameAttr="green", hOrient=ttb.H_ORIENT
        #     ["right"])

        if debug:
            self.tb.create_text_box(
                "setup", "Debug", 20, frameAttr="yellow", hOrient=ttb.H_ORIENT["left"]
            )

        self.tb.set_focus_box("setup", "Chat")

        # self.tb.start()
        self.writeCallBack = None
        self.userName = userName

    def character_callback(self, char):
        """ """

    def enter_callback(self, message):
        """ """
        if self.writeCallBack:
            threading.Thread(target=self.writeCallBack, args=(message, )).start()

    def received_message(self, message):
        self.tb.add_text_item("setup", "Chat", message, attributes=["white"])
        self.tb.update()

    def _update_user_list(self, userList, my_room):
        self.tb.clear_text_items("setup", "Online")
        room_list = {my_room: ["you"]}
        for user in userList.values():
            if user["room"] in room_list:
                room_list[user["room"]].append(user["nick"])
            else:
                room_list[user["room"]] = [user["nick"]]
        for key, value in room_list.items():
            self.tb.add_text_item("setup", "Online", f" - {key}")
            for user in value:
                self.tb.add_text_item("setup", "Online", "   - " + user)
        self.tb.update()
        return

    def _change_user_name(self, userName):
        self.userName = userName
        self.tb._change_user_name(userName)
        self.tb.update()

    def print(self, text, color="white"):
        self.tb.add_text_item(
            "setup", "Chat", str(text),
            attributes=color)
        self.tb.update()

    def log(self, *args):
        try:
            self.tb.add_text_item(
                "setup", "Debug", " ".join(args),
                attributes=["white"])
            self.tb.update()
        except:
            pass
