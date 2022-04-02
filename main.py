from auth_driver import Editor
import auth

# Set up administrator
admin = auth.User("Kateryna", "iamadmin123")
with open("user.txt", "r+") as fdata:
    if not fdata.readline().strip().endswith("administrator"):
        fdata.write(f"{admin.username}: {admin.password}. Access: administrator\n")

# Adding permissions for user access
auth.authorizor.add_permission("administrator")
auth.authorizor.add_permission("No")
auth.authorizor.add_permission("simple user")
auth.authorizor.add_permission("premium user")

Editor().menu()
