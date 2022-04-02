# Notebook with registration
![](https://github.com/KateKo04/NotebookAuth/blob/main/photos/notebook.png)

## Files
* auth.py, auth_driver.py, notebook.py, main.py
* user.txt - "database"(has already registered two users and administrator)
* playground.txt - how the programme runs

## Register new user

User enters his/her name.

If such user already exists, invokes auth.UsernameAlreadyExists.

If the password is too short(less than 6 characters), invokes auth.PasswordTooShort.

User data is written to user.txt. For instance: 

olenka: 1e8ddb517f469e63a170c65f2343862619a956430afbf6b9b0a69b5db2386060.

Password is being hashed.

!From the beginning, file user.txt already contains one user(administrator). 

Data of administartor is written in main.py.

## Login

Here we check, if user with such username exists. If no, than invokes auth.InvalidUsername.

Also, if password is not correct, than invokes auth.InvalidPassword. 

## Request for access(simple and premium)

With simple access user can only add and look at notes.

With premium user can additionally search and modify notes.

If user wants to get simple access, he/she enters - access.

If premium, than - premium

How user looks in both cases in user.txt(after request is sent):

andriyko: b367b8673df399403058fdff3b088e39dd8913dcffc2844f45ec8bb78840a67c. Access: No

olenka: 1e8ddb517f469e63a170c65f2343862619a956430afbf6b9b0a69b5db2386060. Access premium: No

Before the request is being sent, programme checks, if user is logged in and if he/she already has access.

If user already has access, invokes auth.PermissionError.

## Give the permission

Only administrator can give access(in menu: Adminstrator - perm)

If admin gives simple access to user:

andriyko: b367b8673df399403058fdff3b088e39dd8913dcffc2844f45ec8bb78840a67c. Access: simple user

If admin gives premium access to user:

olenka: 1e8ddb517f469e63a170c65f2343862619a956430afbf6b9b0a69b5db2386060. Access: premium user

## In each case, programme checks whether
1) user is logged in. If no, invokes auth.NotLoggedInError.
2) user has access to specipic option. If no, invokes auth.NotPermittedError.
3) specific option exists in menubar. If no, invokes KeyError.
