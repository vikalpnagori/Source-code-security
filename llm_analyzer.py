from transformers import pipeline

class LLMAnalyzer:
    def __init__(self):
        # We will use a pre-trained model fine-tuned for code analysis.
        # For a truly lightweight setup, a model like CodeBERT is ideal.
        # This setup assumes the model is downloaded and accessible locally.
        try:
            self.nlp = pipeline(
                "text-generation",
                model="Salesforce/codegen-350M-mono",  # Using a small, fast model for demonstration
                device=-1  # Use CPU for broader compatibility
            )
        except Exception as e:
            print(f"Error loading LLM model: {e}")
            self.nlp = None

    def analyze_vulnerability(self, code_snippet, semgrep_message):
        if not self.nlp:
            return {
                "llm_analysis": "LLM not available.",
                "remediation_plan": "Please check the LLM setup.",
                "llm_risk_score": "Unknown"
            }

        # The prompt is crucial for getting the desired output from the LLM.
        prompt = (
            f"A static analysis tool flagged the following code for a potential security vulnerability:\n\n"
            f"Vulnerability Description: {semgrep_message}\n\n"
            f"Code Snippet:\n```\n{code_snippet}\n```\n\n"
            f"Please analyze the code. Explain the vulnerability in detail, provide a risk score (CRITICAL, HIGH, MEDIUM, LOW), and suggest a secure code fix. Format your response clearly with these sections: Explanation, Risk Score, and Remediation Plan."
        )

        try:
            response = self.nlp(prompt, max_length=512, do_sample=False, truncation=True)
            llm_text = response[0]['generated_text']

            # Post-process the LLM's raw output to extract structured data.
            analysis = {}
            sections = llm_text.split("Explanation:")
            if len(sections) > 1:
                analysis_part = sections[1].split("Risk Score:")
                if len(analysis_part) > 1:
                    analysis['explanation'] = analysis_part[0].strip()
                    risk_part = analysis_part[1].split("Remediation Plan:")
                    if len(risk_part) > 1:
                        analysis['risk_score'] = risk_part[0].strip()
                        analysis['remediation_plan'] = risk_part[1].strip()
            
            # Use a default if parsing fails
            if not analysis:
                analysis = {
                    "explanation": "Could not parse LLM output.",
                    "risk_score": "MEDIUM", # Default to medium if LLM output is unparseable.
                    "remediation_plan": "Manual review required."
                }
            
            return analysis

        except Exception as e:
            print(f"Error during LLM analysis: {e}")
            return {
                "explanation": "Error during LLM analysis.",
                "risk_score": "MEDIUM",
                "remediation_plan": "Manual review required."
            }
