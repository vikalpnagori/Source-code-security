import subprocess
import json
import os

class SemgrepScanner:
    def __init__(self, repo_path):
        self.repo_path = repo_path
        self.results = None

    def run_scan(self):
        print("Starting Semgrep scan...")
        # Use subprocess to run the semgrep CLI command.
        # --config=auto selects the best rules for the detected languages.
        # --json ensures the output is in a machine-readable format.
        try:
            command = ['semgrep', '--config=auto', '--json', self.repo_path]
            process = subprocess.run(command, capture_output=True, text=True, check=True)
            self.results = json.loads(process.stdout)
            print("Semgrep scan complete.")
            return self.results
        except subprocess.CalledProcessError as e:
            print(f"Semgrep scan failed with error: {e.stderr}")
            return None
        except json.JSONDecodeError:
            print("Failed to decode Semgrep JSON output.")
            return None

    def save_results(self, output_file="semgrep_results.json"):
        if self.results:
            with open(output_file, 'w') as f:
                json.dump(self.results, f, indent=4)
            print(f"Scan results saved to {output_file}")
            return output_file
        return None

# Example Usage:
# # Assuming repo_path is from the CodeIngestor
# # scanner = SemgrepScanner(repo_path)
# # scan_results = scanner.run_scan()
# # if scan_results:
# #     scanner.save_results()
