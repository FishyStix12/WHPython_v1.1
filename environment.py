import os

def get_environment_variables():
    """Retrieve and return the environment variables."""
    print("[*] In environment module.")
    return os.environ

if __name__ == "__main__":
    environment_variables = get_environment_variables()
    for key, value in environment_variables.items():
        print(f"{key}: {value}")