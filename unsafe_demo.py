import os
def delete_user_file(filename: str):
    # Path traversal & shell injection risk
    os.system(f"rm -rf /var/data/{filename}")
