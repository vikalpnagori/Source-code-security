from ingestor import CodeIngestor
from scanner import SemgrepScanner
import json

def run_vulnerability_scan(repo_url):
    """
    Orchestrates the entire scan process.
    1. Clones the repository.
    2. Runs the Semgrep scan on the cloned repository.
    3. Saves the raw JSON results.
    4. Cleans up the temporary directory.
    """
    ingestor = CodeIngestor(repo_url)
    repo_path = ingestor.clone_repo()

    if not repo_path:
        return {"status": "error", "message": "Failed to clone repository."}

    try:
        scanner = SemgrepScanner(repo_path)
        scan_results = scanner.run_scan()

        if scan_results:
            output_file_path = scanner.save_results()
            if output_file_path:
                print(f"Successfully completed Phase 1. Raw Semgrep results are in {output_file_path}")
                return {"status": "success", "results_path": output_file_path, "findings_count": len(scan_results.get('results', []))}
            else:
                return {"status": "error", "message": "Failed to save scan results."}
        else:
            return {"status": "error", "message": "Semgrep scan failed."}
    finally:
        ingestor.cleanup()

# To run the full process from the command line:
if __name__ == "__main__":
    # Example repository to scan (a deliberately vulnerable app)
    REPO_TO_SCAN = "https://github.com/OWASP/NodeGoat.git"
    scan_report = run_vulnerability_scan(REPO_TO_SCAN)
    print("\nScan Report:")
    print(json.dumps(scan_report, indent=4))
