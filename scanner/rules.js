const PATTERNS = [
  {
    name: 'Hardcoded Secret / Token',
    regex: /(api_key|secret|password|token)\s*=\s*['"][a-zA-Z0-9_\-]{16,}['"]/i,
    severity: 'CRITICAL',
    description: 'Sensitive credentials hardcoded in source code.'
  },
  {
    name: 'Unsanitized Database Query Pattern',
    regex: /(SELECT|INSERT|UPDATE|DELETE).*\+.*req\.(body|query|params)/i,
    severity: 'HIGH',
    description: 'Direct string concatenation in database query.'
  }
];

function runStaticScan(codeContent) {
  const issues = [];
  const lines = codeContent.split('\n');

  lines.forEach((line, index) => {
    PATTERNS.forEach(rule => {
      if (rule.regex.test(line)) {
        issues.push({
          rule: rule.name,
          severity: rule.severity,
          line: index + 1,
          description: rule.description,
          snippet: line.trim()
        });
      }
    });
  });

  return issues;
}

module.exports = { runStaticScan };