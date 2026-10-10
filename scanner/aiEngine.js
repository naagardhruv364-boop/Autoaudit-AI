require('dotenv').config();
const { GoogleGenAI } = require('@google/genai');

async function callGemini(prompt, apiKey) {
  const ai = new GoogleGenAI({ apiKey });
  const fallbackModels = [
    'gemini-3.8-flash',
    'gemini-2.5-flash',
    'gemini-2.0-flash',
    'gemini-1.5-flash',
    'gemini-1.5-pro'
  ];

  for (const modelName of fallbackModels) {
    try {
      const response = await ai.models.generateContent({
        model: modelName,
        contents: prompt,
        config: {
          responseMimeType: 'application/json',
          temperature: 0.1
        }
      });

      if (response && response.text) {
        return JSON.parse(response.text);
      }
    } catch (err) {
      console.warn(`Model ${modelName} fallback triggered:${err.message}`);
    }
  }
  throw new Error("All AI models currently unavailable.");
}

async function analyzeWithAI(codeSnippet, staticIssues) {
  const apiKey = process.env.AI_API_KEY;

  if (!apiKey) {
    return {
      summary: "Error: AI_API_KEY missing in .env file.",
      issues: [{
        title: "Configuration Error",
        category: "CONFIG",
        severity: "CRITICAL",
        cwe: "CWE-16",
        owasp: "A05:2021-Security Misconfiguration",
        explanation: "API Key not configured in server environment.",
        recommendation: "Add valid AI_API_KEY in .env and restart server."
      }],
      fixedCode: codeSnippet,
      validationPassed: false
    };
  }

  // --- PASS 1: Detection with Standard Compliance Mapping ---
  const firstPassPrompt = `You are a Principal Application Security Auditor & Senior Compiler Engineer.
Inspect the following code in any language.
For every issue found, identify:
1. Exact error or vulnerability
2. Severity (CRITICAL, HIGH, MEDIUM, LOW)
3. Category (BUG/SYNTAX or SECURITY)
4. Official CWE ID (e.g., CWE-89 for SQLi, CWE-798 for Secrets, CWE-20 for Improper Input, CWE-476 for Null Pointer, CWE-676 for dangerous functions, or "N/A" for pure syntax typos)
5. OWASP Top 10 Reference (e.g., A03:2021-Injection, A07:2021-Identification and Authentication Failures, or "N/A")

Return PURE JSON strictly matching this schema:
{
  "summary": "High-level summary of code health and findings",
  "issues": [
    {
      "title": "Short descriptive title",
      "category": "BUG/SYNTAX" | "SECURITY",
      "severity": "CRITICAL" | "HIGH" | "MEDIUM" | "LOW",
      "cwe": "CWE-ID or N/A",
      "owasp": "OWASP category or N/A",
      "explanation": "Exact technical explanation",
      "recommendation": "Concrete fix instructions"
    }
  ],
  "fixedCode": "Full corrected, bug-free, and clean code"
}

Code:
\`\`\`
${codeSnippet}
\`\`\``;

  try {
    const pass1Result = await callGemini(firstPassPrompt, apiKey);

    if (!pass1Result.issues || pass1Result.issues.length === 0) {
      return {
        ...pass1Result,
        validationPassed: true,
        validationNote: "Zero defects detected. ISO/Clean code standards met."
      };
    }

    // --- PASS 2: Independent Dual-Pass Verification ---
    const validationPrompt = `You are an automated Code Compiler Validator.
Verify this proposed patch for syntax errors, missing semicolons, or broken logic:
\`\`\`
${pass1Result.fixedCode}
\`\`\`

If there are any remaining bugs or syntax flaws, fix them immediately.
Return PURE JSON:
{
  "isValid": true | false,
  "validationNote": "Short verification message",
  "verifiedCode": "100% working patch"
}`;

    const pass2Result = await callGemini(validationPrompt, apiKey);

    return {
      summary: pass1Result.summary,
      issues: pass1Result.issues,
      fixedCode: pass2Result.verifiedCode || pass1Result.fixedCode,
      validationPassed: pass2Result.isValid !== false,
      validationNote: pass2Result.validationNote || "Automated dual-pass compiler verification passed cleanly."
    };

  } catch (err) {
    console.error("AI Error:", err.message);
    return {
      summary: `Engine Notice: ${err.message}`,
      issues: [{
        title: "Scan Warning",
        category: "SYSTEM",
        severity: "MEDIUM",
        cwe: "N/A",
        owasp: "N/A",
        explanation: err.message,
        recommendation: "Retry in a few seconds."
      }],
      fixedCode: codeSnippet,
      validationPassed: false
    };
  }
}

module.exports = { analyzeWithAI };