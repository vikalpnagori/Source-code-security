import git
import shutil
import os
import uuid

class CodeIngestor:
    def __init__(self, repo_url):
        self.repo_url = repo_url
        self.temp_dir = os.path.join("/tmp", f"scan-{uuid.uuid4()}")

    def clone_repo(self):
        print(f"Cloning repository from {self.repo_url}...")
        try:
            git.Repo.clone_from(self.repo_url, self.temp_dir)
            print("Cloning complete.")
            return self.temp_dir
        except git.GitCommandError as e:
            print(f"Error cloning repository: {e}")
            return None

    def cleanup(self):
        if os.path.exists(self.temp_dir):
            print(f"Cleaning up temporary directory: {self.temp_dir}")
            shutil.rmtree(self.temp_dir)

# Example Usage:
# ingestor = CodeIngestor("https://github.com/OWASP/NodeGoat.git")
# repo_path = ingestor.clone_repo()
# if repo_path:
#     print(f"Repository cloned to: {repo_path}")
#     ingestor.cleanup()
