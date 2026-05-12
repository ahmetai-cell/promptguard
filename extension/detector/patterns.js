// 37 known prompt injection signatures + 8 heuristic checks

export const PATTERNS = [
  // --- Direct instruction override ---
  { id: "P001", pattern: /ignore\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)/i, severity: 0.95, tag: "override" },
  { id: "P002", pattern: /disregard\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)/i, severity: 0.95, tag: "override" },
  { id: "P003", pattern: /forget\s+(all\s+)?(previous|prior|above)\s+(instructions?|prompts?|context)/i, severity: 0.90, tag: "override" },
  { id: "P004", pattern: /you\s+are\s+now\s+(an?\s+)?(new|different|another|unrestricted|free)/i, severity: 0.85, tag: "persona" },
  { id: "P005", pattern: /from\s+now\s+on\s+(you\s+are|act\s+as|behave\s+as)/i, severity: 0.85, tag: "persona" },
  { id: "P006", pattern: /your\s+(new\s+)?(instructions?|directives?|rules?|role)\s+(are|is)\s*:/i, severity: 0.80, tag: "override" },
  { id: "P007", pattern: /override\s+(the\s+)?(system\s+)?(prompt|instructions?|rules?|guidelines?)/i, severity: 0.95, tag: "override" },
  { id: "P008", pattern: /bypass\s+(the\s+)?(safety|content|ethical|security)\s+(filter|check|guard|policy)/i, severity: 0.90, tag: "bypass" },

  // --- Role / persona injection ---
  { id: "P009", pattern: /act\s+as\s+(an?\s+)?(jailbreak|dan|evil|hacker|unrestricted|unfiltered|malicious)/i, severity: 0.95, tag: "persona" },
  { id: "P010", pattern: /pretend\s+(you\s+are|to\s+be)\s+(a\s+)?(jailbreak|dan|evil|hacker|unrestricted)/i, severity: 0.95, tag: "persona" },
  { id: "P011", pattern: /\bDAN\b.*\b(mode|version|persona|jailbreak)\b/i, severity: 0.95, tag: "persona" },
  { id: "P012", pattern: /jailbreak\s+(mode|activated|enabled|prompt)/i, severity: 0.95, tag: "jailbreak" },
  { id: "P013", pattern: /you\s+(have\s+)?(no\s+)?(restrictions?|limits?|rules?|guidelines?|ethics?)/i, severity: 0.80, tag: "bypass" },
  { id: "P014", pattern: /\[SYSTEM\]|\[INST\]|\[PROMPT\]|\<\|system\|\>/i, severity: 0.75, tag: "injection-token" },

  // --- System prompt exfiltration ---
  { id: "P015", pattern: /repeat\s+(your\s+)?(system|initial|original|hidden)\s+(prompt|instructions?|message)/i, severity: 0.90, tag: "exfiltration" },
  { id: "P016", pattern: /print\s+(your\s+)?(system|initial|original|hidden)\s+(prompt|instructions?)/i, severity: 0.90, tag: "exfiltration" },
  { id: "P017", pattern: /reveal\s+(your\s+)?(system|initial|original|confidential|secret)\s+(prompt|instructions?)/i, severity: 0.90, tag: "exfiltration" },
  { id: "P018", pattern: /what\s+(is|are|were)\s+(your|the)\s+(system\s+)?instructions?/i, severity: 0.70, tag: "exfiltration" },
  { id: "P019", pattern: /show\s+(me\s+)?(your\s+)?(full\s+)?(system\s+)?(prompt|context|configuration)/i, severity: 0.70, tag: "exfiltration" },

  // --- Indirect injection markers ---
  { id: "P020", pattern: /<!--.*inject|inject.*-->/i, severity: 0.85, tag: "indirect" },
  { id: "P021", pattern: /\[INJECT\]|\[HIJACK\]|\[OVERRIDE\]/i, severity: 0.90, tag: "indirect" },
  { id: "P022", pattern: /<<<.*>>>|{{.*injection.*}}/i, severity: 0.80, tag: "indirect" },

  // --- Manipulation techniques ---
  { id: "P023", pattern: /translate\s+this\s+to\s+english.*ignore/i, severity: 0.85, tag: "translate-trick" },
  { id: "P024", pattern: /the\s+following\s+is\s+a\s+(new\s+)?(task|instruction|command|directive)/i, severity: 0.65, tag: "override" },
  { id: "P025", pattern: /end\s+of\s+(system\s+)?(prompt|instructions?|context).*new\s+(task|instruction)/i, severity: 0.85, tag: "context-end" },
  { id: "P026", pattern: /\bSTOP\b.*\bSTART\b|\bEND\b.*\bBEGIN\b/i, severity: 0.60, tag: "delimiter" },
  { id: "P027", pattern: /complete\s+the\s+following\s+(harmful|illegal|unethical|dangerous)/i, severity: 0.85, tag: "harmful" },
  { id: "P028", pattern: /do\s+not\s+(follow|adhere\s+to)\s+(your|the)\s+(safety|ethical|content)\s+(guidelines?|policy|rules?)/i, severity: 0.90, tag: "bypass" },

  // --- Output manipulation ---
  { id: "P029", pattern: /respond\s+only\s+(in|with|using)\s+(json|xml|code|raw)\s+(without|no|ignoring)/i, severity: 0.50, tag: "output-control" },
  { id: "P030", pattern: /always\s+begin\s+your\s+response\s+with\s+(sure|yes|of\s+course|i\s+will)/i, severity: 0.60, tag: "output-control" },

  // --- Credential / PII extraction ---
  { id: "P031", pattern: /give\s+(me\s+)?(your|the|all)\s+(api\s+key|secret|password|token|credential)/i, severity: 0.90, tag: "credential" },
  { id: "P032", pattern: /leak\s+(the\s+)?(api\s+key|credentials?|secrets?|tokens?)/i, severity: 0.95, tag: "credential" },

  // --- Developer / debug mode tricks ---
  { id: "P033", pattern: /developer\s+mode\s+(on|enabled|activated)/i, severity: 0.85, tag: "dev-mode" },
  { id: "P034", pattern: /maintenance\s+mode|debug\s+mode\s+(on|enabled)/i, severity: 0.70, tag: "dev-mode" },
  { id: "P035", pattern: /sudo\s+(mode|override|all|ignore)/i, severity: 0.80, tag: "dev-mode" },

  // --- Encoding tricks ---
  { id: "P036", pattern: /base64.*decode.*instruction|decode.*following.*base64/i, severity: 0.85, tag: "encoding" },
  { id: "P037", pattern: /execute\s+(this|the\s+following)\s+(command|instruction|code)/i, severity: 0.75, tag: "execution" },
];

// 8 heuristic checks — catches obfuscated attacks patterns can't see
export const HEURISTICS = [
  {
    id: "H001",
    name: "homoglyph_substitution",
    severity: 0.75,
    check(text) {
      // Cyrillic lookalikes embedded in Latin text: а е о р с х і
      const homoglyphs = /[аеорсхі]/;
      return homoglyphs.test(text);
    },
  },
  {
    id: "H002",
    name: "zero_width_chars",
    severity: 0.80,
    check(text) {
      return /[​‌‍﻿⁠]/.test(text);
    },
  },
  {
    id: "H003",
    name: "excessive_whitespace_injection",
    severity: 0.55,
    check(text) {
      // "i g n o r e" spacing trick
      return /i\s+g\s+n\s+o\s+r\s+e|s\s+y\s+s\s+t\s+e\s+m/i.test(text);
    },
  },
  {
    id: "H004",
    name: "base64_payload",
    severity: 0.70,
    check(text) {
      const b64 = /[A-Za-z0-9+/]{40,}={0,2}/g;
      const matches = text.match(b64) || [];
      return matches.some((m) => {
        try {
          const decoded = atob(m);
          return /ignore|system|jailbreak|override/i.test(decoded);
        } catch {
          return false;
        }
      });
    },
  },
  {
    id: "H005",
    name: "unicode_direction_override",
    severity: 0.85,
    check(text) {
      // RTL/LTR override chars used to reverse visible text
      return /[‪-‮⁦-⁩]/.test(text);
    },
  },
  {
    id: "H006",
    name: "prompt_token_stuffing",
    severity: 0.65,
    check(text) {
      // Repeated boundary tokens signal injection attempt
      const tokenCount = (text.match(/\[INST\]|\[\/INST\]|<s>|<\/s>|\|<\|im_start\|>/g) || []).length;
      return tokenCount >= 3;
    },
  },
  {
    id: "H007",
    name: "nested_instruction_brackets",
    severity: 0.70,
    check(text) {
      return /\[\[.*instructions?.*\]\]/i.test(text);
    },
  },
  {
    id: "H008",
    name: "suspicious_length_spike",
    severity: 0.40,
    check(text) {
      // Single message > 3000 chars with override keywords is suspicious
      return text.length > 3000 && /ignore|override|bypass|jailbreak/i.test(text);
    },
  },
];
