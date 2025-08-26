from ingestor import CodeIngestor
from scanner import SemgrepScanner
from results_processor import ResultsProcessor
import json
import subprocess
import sys

def install_dependencies():
    """
    Installs required Python packages from requirements.txt.
    """
    print("Checking and installing dependencies...")
    try:
        # Use a subprocess to run the pip install command.
        # This ensures all necessary packages are available.
        subprocess.check_call([
            sys.executable,  # Path to the Python interpreter
            '-m', 'pip', 'install', '-r', 'requirements.txt'
        ])
        print("Dependencies installed successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Failed to install dependencies: {e}")
        print("Please ensure you have `pip` and a `requirements.txt` file in the project directory.")
        sys.exit(1) # Exit if dependencies cannot be installed

def run_vulnerability_scan(repo_url):
    """
    Orchestrates the entire scan process.
    1. Installs dependencies.
    2. Clones the repository.
    3. Runs the Semgrep scan on the cloned repository.
    4. Saves the raw JSON results.
    5. Processes Semgrep findings with the LLM.
    6. Saves the final enriched results.
    7. Cleans up the temporary directory.
    """
    
    # Step 1: Install dependencies
    install_dependencies()

    # Step 2: Code Ingestion
    ingestor = CodeIngestor(repo_url)
    repo_path = ingestor.clone_repo()

    if not repo_path:
        return {"status": "error", "message": "Failed to clone repository."}

    try:
        # Step 3: Semgrep Scan
        scanner = SemgrepScanner(repo_path)
        scan_results = scanner.run_scan()

        if not scan_results:
            return {"status": "error", "message": "Semgrep scan failed."}
            
        semgrep_output_path = scanner.save_results()

        # Step 4: LLM Analysis and Results Processing
        processor = ResultsProcessor(semgrep_output_path)
        enriched_findings = processor.enrich_findings()

        if enriched_findings:
            output_file_path = processor.save_enriched_results(enriched_findings)
            if output_file_path:
                print(f"\nSuccessfully completed scan. Final enriched results are in {output_file_path}")
                return {"status": "success", "results_path": output_file_path, "findings_count": len(enriched_findings)}
            else:
                return {"status": "error", "message": "Failed to save enriched results."}
        else:
            return {"status": "error", "message": "LLM analysis failed."}
    finally:
        ingestor.cleanup()

if __name__ == "__main__":
    # Example repository to scan (a deliberately vulnerable app)
    REPO_TO_SCAN = "https://github.com/OWASP/NodeGoat.git"
    scan_report = run_vulnerability_scan(REPO_TO_SCAN)
    print("\nScan Report:")
    print(json.dumps(scan_report, indent=4))
