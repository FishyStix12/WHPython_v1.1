import os

def list_files(directory):
    """
    Recursively lists all files in a directory.

    Args:
        directory (str): The directory to start listing files from.

    Returns:
        list: A list of strings, where each string is a file path.
    """
    files = []
    for dirpath, dirnames, filenames in os.walk(directory):
        for filename in filenames:
            files.append(os.path.join(dirpath, filename))
    return files

def run(**args):
    """
    This function lists all files in all directories starting from the current directory.

    Args:
        **args: Arbitrary keyword arguments (not used in this function).

    Returns:
        str: A string containing the names of all files in all directories.
    """
    print("[*] In dirlistener module.")
    files = list_files(".")
    return str(files)