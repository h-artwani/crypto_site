import os

def list_folders(folder_path):
    """
    Returns a list of all subdirectories in the specified directory.
    """
    folders = []
    for item in os.listdir(folder_path):
        item_path = os.path.join(folder_path, item)
        if os.path.isdir(item_path):
            folders.append(item_path)
    return folders

def empty_folder(folder_path):
    """
    Deletes all files in the specified folder, but leaves the folder itself intact.
    """
    for filename in os.listdir(folder_path):
        file_path = os.path.join(folder_path, filename)
        try:
            if os.path.isfile(file_path) or os.path.islink(file_path):
                os.unlink(file_path)
        except Exception as e:
            print(f"Failed to delete {file_path}. Reason: {e}")

# UPLOAD_FOLDER = "../static/"
# folders = list_folders(UPLOAD_FOLDER)
# print(folders)

# empty_folder("../static/decrypted_files")
