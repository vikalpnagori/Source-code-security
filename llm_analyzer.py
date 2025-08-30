import requests
import json
import textwrap

class LLMAnalyzer:
    def __init__(self, api_url="http://localhost:11434/api/generate", timeout=150):
        self.api_url = api_url
        self.timeout = timeout

    def compress_message(self, msg, max_len=20):
        """Removes extra whitespace and limits the length of the message."""
        return ' '.join(msg.strip().split())[:max_len]

    def trim_code(self, code, max_lines=10):
        """Limits the code snippet to avoid overloading small models."""
        lines = code.strip().splitlines()
        return '\n'.join(lines[:max_lines])

    def build_prompt(self, code_snippet, semgrep_message):
        """
        Builds a structured prompt for an instruction-tuned LLM.
        """
        compressed_msg = self.compress_message(semgrep_message)
        trimmed_code = self.trim_code(code_snippet)

        return textwrap.dedent(f"""
            Analyze the following security vulnerability. Provide an explanation, a risk score, and a remediation plan.

            Description: {compressed_msg}

            Code:
            ```
            {trimmed_code}
            ```

            Respond with the following format:
            Explanation:
            Risk Score: (CRITICAL/HIGH/MEDIUM/LOW)
            Remediation Plan:
        """)

    def parse_response(self, llm_text):
        """
        Parses the LLM's response to extract structured data.
        It is resilient to minor formatting deviations.
        """
        output = {
            "explanation": "Could not parse LLM output.",
            "risk_score": "MEDIUM",
            "remediation_plan": "Manual review required."
        }

        # Attempt to find and extract each section
        if "Explanation:" in llm_text:
            output["explanation"] = llm_text.split("Explanation:")[1].strip()

        if "Risk Score:" in llm_text:
            risk_part = llm_text.split("Risk Score:")[1].strip()
            # Split by the next section to get just the score
            if "Remediation Plan:" in risk_part:
                risk_part = risk_part.split("Remediation Plan:")[0].strip()
            output["risk_score"] = risk_part

        if "Remediation Plan:" in llm_text:
            output["remediation_plan"] = llm_text.split("Remediation Plan:")[1].strip()

        # Final cleanup for the explanation (remove trailing risk score text)
        if "Risk Score:" in output["explanation"]:
            output["explanation"] = output["explanation"].split("Risk Score:")[0].strip()

        return output

    def analyze_vulnerability(self, code_snippet, semgrep_message):
        prompt = self.build_prompt(code_snippet, semgrep_message)
        payload = {
            "model": "qwen2.5-coder:3b",
            "prompt": prompt,
            "stream": False
        }

        try:
            print("[LLMAnalyzer] Sending request to LLM...")
            response = requests.post(self.api_url, data=json.dumps(payload), timeout=self.timeout)

            if response.status_code >= 500:
                print(f"[LLMAnalyzer] Server error {response.status_code}")
                return {
                    "explanation": "Ollama server error.",
                    "risk_score": "MEDIUM",
                    "remediation_plan": "Reduce prompt size or restart Ollama."
                }

            response.raise_for_status()
            result = response.json()

            if 'error' in result:
                print(f"[LLMAnalyzer] Ollama returned an error: {result['error']}")
                return {
                    "explanation": "Ollama returned an error.",
                    "risk_score": "MEDIUM",
                    "remediation_plan": "Reduce prompt size or restart Ollama."
                }

            llm_text = result.get('response', '')
            return self.parse_response(llm_text)

        except requests.exceptions.Timeout:
            print("[LLMAnalyzer] Request timed out.")
            return {
                "explanation": "LLM request timed out.",
                "risk_score": "MEDIUM",
                "remediation_plan": "The request took too long. Try a smaller model or a simpler prompt."
            }

        except requests.exceptions.RequestException as e:
            print(f"[LLMAnalyzer] Communication error: {e}")
            return {
                "explanation": "Could not connect to LLM service.",
                "risk_score": "MEDIUM",
                "remediation_plan": "Ensure Ollama is running and accessible."
            }
