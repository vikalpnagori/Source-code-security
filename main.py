# main.py
from ingestor import CodeIngestor
from scanner import SemgrepScanner
from results_processor import ResultsProcessor
import json
import argparse
import os

def run_vulnerability_scan(repo_url):
    """
    Orchestrates the entire scan process.
    1. Clones the repository.
    2. Runs the Semgrep scan on the cloned repository.
    3. Saves the raw JSON results.
    4. Processes Semgrep findings with the external LLM service.
    5. Saves the final enriched results.
    6. Cleans up the temporary directory.
    """
    if repo_url:
        ingestor = CodeIngestor(repo_url)
        repo_path = ingestor.clone_repo()

        if not repo_path:
            return {"status": "error", "message": "Failed to clone repository."}
    else:
        # Fallback for demonstration if a URL isn't provided,
        # assuming a file from a previous scan exists.
        repo_path = "semgrep_results.json"  # A placeholder for the path to the repo

    semgrep_output_path = "semgrep_results.json"
    
    # Run the semgrep scanner (only if a repo URL was provided)
    if repo_url:
        try:
            scanner = SemgrepScanner(repo_path)
            scan_results = scanner.run_scan()
            if scan_results:
                scanner.save_results(output_file=semgrep_output_path)
            else:
                print("Semgrep scan failed.")
                return {"status": "error", "message": "Semgrep scan failed."}
        finally:
            ingestor.cleanup()

    # Phase 2: LLM Analysis (using the new API-based approach)
    processor = ResultsProcessor(semgrep_output_path)
    enriched_findings = processor.enrich_findings()

    if enriched_findings:
        output_file_path = processor.save_enriched_results(enriched_findings, output_file="final_results.json")
        if output_file_path:
            print(f"\nSuccessfully completed scan. Final enriched results are in {output_file_path}")
            return {"status": "success", "results_path": output_file_path, "findings_count": len(enriched_findings)}
        else:
            return {"status": "error", "message": "Failed to save enriched results."}
    else:
        return {"status": "error", "message": "LLM analysis failed."}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Source Code Vulnerability Scanner")
    parser.add_argument("repo_url", nargs='?', type=str, help="The URL of the Git repository to scan.")
    
    args = parser.parse_args()
    
    if args.repo_url:
        print(f"Starting scan for repository: {args.repo_url}")
        scan_report = run_vulnerability_scan(args.repo_url)
    else:
        print("No repository URL provided. Running scan on existing results file.")
        scan_report = run_vulnerability_scan(None)

    print("\nScan Report:")
    print(json.dumps(scan_report, indent=4))
