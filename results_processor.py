import json
import os
from llm_analyzer import LLMAnalyzer

class ResultsProcessor:
    def __init__(self, semgrep_results_path):
        self.semgrep_results_path = semgrep_results_path
        self.llm_analyzer = LLMAnalyzer()

    def enrich_findings(self):
        if not os.path.exists(self.semgrep_results_path):
            print(f"Error: Semgrep results file not found at {self.semgrep_results_path}")
            return None

        with open(self.semgrep_results_path, 'r') as f:
            raw_findings = json.load(f)

        enriched_findings = []
        findings_list = raw_findings.get('results', [])

        print(f"Processing {len(findings_list)} raw findings with LLM...")
        for finding in findings_list:
            # Extract key information from Semgrep's output
            code_snippet = finding['extra']['lines']
            semgrep_message = finding['extra']['message']
            
            # Call the LLM to analyze the finding
            llm_analysis = self.llm_analyzer.analyze_vulnerability(code_snippet, semgrep_message)
            
            # Combine the Semgrep and LLM data
            enriched_finding = {
                "file_path": finding['path'],
                "line": finding['start']['line'],
                "code_snippet": code_snippet,
                "semgrep_message": semgrep_message,
                "semgrep_severity": finding['extra']['severity'],
                "llm_explanation": llm_analysis['explanation'],
                "llm_risk_score": llm_analysis['risk_score'],
                "remediation_plan": llm_analysis['remediation_plan']
            }
            enriched_findings.append(enriched_finding)
            
        print("LLM analysis complete.")
        return enriched_findings

    def save_enriched_results(self, enriched_results, output_file="final_results.json"):
        if enriched_results:
            with open(output_file, 'w') as f:
                json.dump(enriched_results, f, indent=4)
            print(f"Enriched results saved to {output_file}")
            return output_file
        return None
