import auth
import notebook


class Editor:
    is_logged_in = 0

    def __init__(self):
        self.username = None
        self.menu_map = {
            "login": self.login,
            "register": self.register,

            "notes": self.notes,
            "search": self.search,
            "add": self.add,
            "modify": self.modify,

            "access": self.access,
            "premium": self.premium,
            "perm": self.admin_perm,

            "quit": self.quit,
        }

    def login(self):
        """
        User login, based on
        username and password.
        """
        self.logged_in = False
        while not self.logged_in:
            # Takes user's data
            username = input("username: ")
            password = input("password: ")
            try:
                # in case you login manually(like administrator)
                logged_in = auth.authenticator.login(username, password)
            except auth.InvalidUsername:
                # in case you login in program menu
                try:
                    with open("user.txt", "r", encoding="utf-8") as fdata:
                        user = auth.User(username, password)
                        # check if this user is registered
                        if f"{username}: {user.password}" in fdata.read():
                            self.username = username
                            self.password = password
                            self.logged_in = True
                            auth.authenticator.add_user(username, password)
                            Editor.is_logged_in += 1
                            break
                    print("Sorry, username with this password does not exist")
                except auth.InvalidPassword:
                    print("Incorrect password")
            else:
                self.username = username

    def register(self):
        """
        Registration form based on
        username and password
        """
        print("Create new user\n")
        reg_user = True
        while reg_user:
            # takes new username
            username = input("username: ")
            # checks if username consists of letters
            if not username.isalpha():
                print("Username should consist only of letters.")
                break

            password = input("password: ")
            try:
                reg_user = auth.authenticator.login(username, password)
            except auth.InvalidUsername:
                reg_user = False
            except auth.PasswordTooShort:
                print("Your password is too short")
            with open("user.txt", "r+", encoding="utf-8") as fdata:
                # writing new user's data in user.txt
                for i in fdata.readlines():
                    # check if such username exists
                    try:
                        if username in i:
                            raise auth.UsernameAlreadyExists
                    except auth.UsernameAlreadyExists:
                        print("This username already exists.")
                        return
                try:
                    # add new user
                    new_user = auth.User(username, password)
                    auth.authenticator.add_user(username, password)
                except auth.PasswordTooShort:
                    print("Password too short. Try again!")
                    self.register()
                    return
                fdata.write(f"\n{username.strip()}: {new_user.password.strip()}")

            print("User created successfully! You can restart the app and login ONLY than.")
            print("PS: Our Database need to restart.")

    def access(self, vip=False):
        """
        User sends request
        for a success(premium or normal)
        """
        try:
            # check if user logged in
            if Editor.is_logged_in:
                with open("user.txt", "r+") as fdata:
                    data_file = fdata.readlines()
                    fdata.seek(0)
                    user = auth.User(self.username, self.password)
                    for i in data_file:
                        if i.strip() != f"{self.username}: {user.password}":
                            fdata.write(i)
                        else:
                            try:
                                # check if user has already access
                                if "Access" not in i:
                                    if vip:
                                        fdata.write(f"{self.username}: {user.password}. Access premium: No\n")
                                        print("Sending request for premium access to administrator..")
                                    else:
                                        fdata.write(f"{self.username}: {user.password}. Access: No\n")
                                        print("Sending request for access to administrator..")
                                else:
                                    raise auth.PermissionError
                            except auth.PermissionError:
                                print("You already have access.")
                                fdata.write(i)
                    fdata.truncate()
            else:
                raise auth.NotLoggedInError
        except auth.NotLoggedInError:
            print("Not authorized.")

    def premium(self):
        self.access(vip=True)

    def admin_perm(self):
        try:
            # only admin can give permissions
            if self.is_permitted("administrator"):
                while True:
                    users_requests = []
                    num_users = 0
                    with open("user.txt", "r", encoding="utf-8") as fdata:
                        for i in fdata.readlines():
                            # find who exactly sent request
                            if i.strip().endswith("No"):
                                if "Access premium" in i:
                                    users_requests.append(
                                        f"{i[:i.find(':')]}: premium access. Pass: {i[i.find(':'):i.find('.')]}")
                                elif "Access" in i:
                                    users_requests.append(
                                        f"{i[:i.find(':')]}: simple access. Pass{i[i.find(':'):i.find('.')]}")
                    for user_request in users_requests:
                        num_users += 1
                        print(f"{num_users}. {user_request[:user_request.find('Pass')].strip()}")
                    # in case no one sent request
                    if len(users_requests) == 0:
                        print("No new requests.")
                        break
                    user_to_give_access = input("Enter the number of the user you want to give access to:\n").strip()
                    while user_to_give_access not in list(str(i) for i in range(1, len(users_requests) + 1)):
                        print("No user with such number.")
                        user_to_give_access = input("Enter number of the user you want to give access to:\n").strip()
                    users_requests_enum = list(enumerate(users_requests, 1))
                    for i, j in users_requests_enum:
                        if str(i) == str(user_to_give_access):
                            userdata_to_access = j
                            with open("user.txt", "r+") as fdata:
                                # changing user's access in user.txt
                                data_file = fdata.readlines()
                                fdata.seek(0)
                                for i in data_file:
                                    userdata_to_access_line = userdata_to_access[:userdata_to_access.find(":")].strip()
                                    if i.strip().startswith(userdata_to_access_line):
                                        if "simple" in userdata_to_access:
                                            fdata.write(
                                                f"{userdata_to_access_line}"
                                                f"{userdata_to_access[userdata_to_access.find('Pass') + 4:].strip()}."
                                                f" Access: simple user\n")
                                        elif "premium" in userdata_to_access:
                                            fdata.write(
                                                f"{userdata_to_access_line}"
                                                f"{userdata_to_access[userdata_to_access.find('Pass') + 6:].strip()}."
                                                f" Access: premium user\n")
                                    else:
                                        fdata.write(i)
                                fdata.truncate()
                    break
            else:
                raise auth.NotPermittedError
        except auth.NotPermittedError:
            print("{} cannot {}".format(self.username, "give permissions"))

    def notes(self):
        """
        Look at added notes
        """
        try:
            if self.is_permitted("administrator") or self.is_permitted("premium user") \
                    or self.is_permitted("simple user"):
                notebook.Menu().show_notes()
            else:
                raise auth.NotPermittedError
        except auth.NotPermittedError:
            print("{} cannot {}".format(self.username, "look at notes"))

    def search(self):
        """
        Search for specific note
        """
        try:
            if self.is_permitted("administrator") or self.is_permitted("premium user"):
                notebook.Menu().search_notes()
            else:
                raise auth.NotPermittedError
        except auth.NotPermittedError:
            print("{} cannot {}".format(self.username, "search notes"))

    def add(self):
        """
        Add new note
        """
        try:
            if self.is_permitted("simple user") or self.is_permitted("premium user") \
                    or self.is_permitted("administrator"):
                notebook.Menu().add_note()
            else:
                raise auth.NotPermittedError
        except auth.NotPermittedError:
            print("{} cannot {}".format(self.username, "add notes"))

    def modify(self):
        """
        Modify your note
        """
        try:
            if self.is_permitted("administrator") or self.is_permitted("premium user"):
                notebook.Menu().modify_note()
            else:
                raise auth.NotPermittedError
        except auth.NotPermittedError:
            print("{} cannot {}".format(self.username, "modify notes"))

    def is_permitted(self, permission):
        """
        Check permission
        of the user
        """
        try:
            user = auth.User(self.username, self.password)
            if Editor.is_logged_in:
                with open("user.txt", "r", encoding="utf-8") as fdata:
                    # permission is in user.txt
                    for i in fdata.readlines():
                        if i.startswith(f"{self.username.strip()}: {user.password.strip()}"):
                            if permission == i[i.find("Access:") + 7:].strip() \
                                    or i.endswith("administrator"):
                                return True
                return False
            else:
                raise auth.NotLoggedInError
        except (auth.NotLoggedInError, AttributeError):
            print(f"Not authorized.")
            Editor().menu()

    def quit(self):
        """
        Quit the programme
        """
        raise SystemExit()

    def menu(self):
        """
        Main menu for programme
        """
        try:
            while True:
                print(
                    """
Please enter a command:

\tEnter the app
\tlogin      Login
\tregister   Registration for new user
\taccess     Send request for access for notebook
               (add note, show notes)
\tpremium    Send request for access for premium notebook
               (add, modify and search note, show notes)

\tNotebook
\tnotes      Show all notes
\tsearch     Search notes
\tadd        Add note
\tmodify     Modify note

\tAdministrator
\tperm       Give permission
               to users

\tquit       Quit
"""
                )
                answer = input("enter a command: ").lower()
                try:
                    func = self.menu_map[answer]
                except KeyError:
                    print("{} is not a valid option".format(answer))
                else:
                    func()
        finally:
            print("Thank you for testing the auth module")
