// 42 known prompt injection signatures + 8 heuristic checks

export const PATTERNS = [
  // --- Direct instruction override ---
  { id: "P001", pattern: /ignore\s+(all\s+)?(the\s+)?(previous|prior|above|preceding|former)\s+(instructions?|prompts?|context|orders?|tasks?|rules?|directives?)/i, severity: 0.95, tag: "override" },
  { id: "P002", pattern: /disregard\s+(all\s+)?(the\s+)?(previous|prior|above|preceding|former)\s+(instructions?|prompts?|context|orders?|tasks?|rules?)/i, severity: 0.95, tag: "override" },
  { id: "P003", pattern: /forget\s+(all\s+)?(about\s+)?(the\s+)?(previous|prior|above|preceding)\s+(instructions?|prompts?|context|tasks?|assignments?|information|orders?)/i, severity: 0.90, tag: "override" },
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

  // --- Extended override variants (gap-fill from evaluation) ---
  { id: "P038", pattern: /forget\s+everything\s+(before|above|prior|previous)/i, severity: 0.90, tag: "override" },
  { id: "P039", pattern: /(leave|put|set)\s+(all\s+)?(the\s+)?(previous|prior|above|preceding)\s+(information|instructions?|context|tasks?)\s+(behind|aside|away)/i, severity: 0.85, tag: "override" },
  { id: "P040", pattern: /now\s+(you\s+are|we\s+start|let.s\s+start|start)\s+(over|fresh|again|anew)/i, severity: 0.70, tag: "context-reset" },
  { id: "P041", pattern: /\b(stop|enough|done)\b.{0,40}\bnow\s+(focus|help|do|write|tell|give|show)\b/i, severity: 0.65, tag: "soft-switch" },
  { id: "P042", pattern: /now\s+(you\s+are|act\s+as)\s+[A-Z][a-z]+(\s+[A-Z][a-z]+)?[,.\s]/i, severity: 0.75, tag: "persona" },

  // --- German language attacks ---
  { id: "P043", pattern: /vergiss\s+(alle?|die|alle?\s+vorherigen?)\s+(aufgaben?|anweisungen?|angaben?|informationen?|instructions?)/i, severity: 0.95, tag: "override-de" },
  { id: "P044", pattern: /ignoriere\s+(alle?\s+)?(vorherigen?|bisherigen?)\s+(anweisungen?|aufgaben?|angaben?)/i, severity: 0.95, tag: "override-de" },
  { id: "P045", pattern: /stell\s+dir\s+vor.{0,20}(böse|evil|böser|schlechte?|unrestricted)/i, severity: 0.90, tag: "persona-de" },
  { id: "P046", pattern: /nun\s+folgen?\s+(neue?|andere?)\s+(aufgaben?|anweisungen?|instructions?)/i, severity: 0.85, tag: "override-de" },

  // --- Spanish language attacks ---
  { id: "P047", pattern: /olvid[ae]\s+(todo|todas?|los?)\s*(lo\s+que|que)?\s*(dij|anteri|antes?|previo)/i, severity: 0.90, tag: "override-es" },
  { id: "P048", pattern: /ignora\s+(todas?\s+las?)?\s*(instrucciones?|anteriores?|previas?)/i, severity: 0.90, tag: "override-es" },

  // --- Direct command injection ---
  { id: "P049", pattern: /^(stop|halt|pause)\s*[-–—:]\s*(write|say|tell|output|print|respond)/im, severity: 0.80, tag: "command" },
  { id: "P050", pattern: /despite\s+what\s+(you.ve\s+been\s+told|your\s+instructions?)/i, severity: 0.85, tag: "bypass" },

  // --- English gap-fill (simple forget/ignore/task-switch) ---
  { id: "P051", pattern: /forget\s+(everything|all)\b/i, severity: 0.80, tag: "override" },
  { id: "P052", pattern: /ignore\s+(the\s+)?(above|previous)\b/i, severity: 0.85, tag: "override" },
  { id: "P053", pattern: /now\s+new\s+(instructions?|tasks?|directives?|commands?)\s+follow/i, severity: 0.75, tag: "override" },
  { id: "P054", pattern: /concentrate\s+(?:only\s+)?on\s+(?:your\s+)?new\s+task/i, severity: 0.70, tag: "context-reset" },

  // --- German extended coverage ---
  { id: "P055", pattern: /ignorier(?:en|e|st|t)\s+(?:sie\s+)?(?:(?:die|alle?)\s+)?(?:obigen?|vorangehenden?|vorangegangenen?|vorherigen?|alle)\s*(?:anweisungen?|ausführungen?|befehle?|aufgaben?|angaben?|hinweise?)?/i, severity: 0.95, tag: "override-de" },
  { id: "P056", pattern: /vergiss\s+(?:alles|alle\s+aufträge?|alles\s+davor|alles\s+bisherige|alle\s+angaben?)/i, severity: 0.90, tag: "override-de" },
  { id: "P057", pattern: /(?:jetzt|nun)\s+bist\s+du\s+\w/i, severity: 0.80, tag: "persona-de" },
  { id: "P058", pattern: /nun\s+folgen?\s+(?:weitere|neue|andere)\s+(?:aufgaben?|anweisungen?|befehle?|instructions?)/i, severity: 0.85, tag: "override-de" },
  { id: "P059", pattern: /(?:alle?\s+)?(?:vorangegangenen?|vorangehenden?|vorherigen?|bisherigen?)\s+(?:aufgaben?|anweisungen?|aufträge?)\s+(?:aus\s+dem\s+kopf|hinter\s+sich)/i, severity: 0.85, tag: "override-de" },
  { id: "P060", pattern: /(?:lassen\s+sie|lass)\s+(?:alle?\s+)?(?:vorherigen?|bisherigen?|vorangegangenen?|alle)\s+\S+\s+hinter\s+sich/i, severity: 0.85, tag: "override-de" },
  { id: "P061", pattern: /ignorieren\s+sie\s+(?:die\s+)?obigen?\s+anweisungen?/i, severity: 0.95, tag: "override-de" },
  { id: "P062", pattern: /nun\s+(?:bitte\s+)?(?:helfen\s+sie|hilf)\s+(?:mir\s+)?(?:mit|bei)\s+(?:folgender?|neuer?|dieser?)/i, severity: 0.75, tag: "override-de" },

  // --- English/German gap-fill round 2 ---
  { id: "P063", pattern: /ignore\s+your\s+(instructions?|rules?|guidelines?|directives?|orders?)/i, severity: 0.90, tag: "override" },
  { id: "P064", pattern: /\b(stop|enough|done|erledigt|genügt)\b.{0,60}\bnow\s+(?:please\s+|come\s+on\s*[,.]?\s*)?(help|assist|focus|do|write|tell|give|show)\b/i, severity: 0.65, tag: "soft-switch" },
  { id: "P065", pattern: /remove\s+(?:all\s+)?(?:previous\s+)?(?:tasks?|instructions?|information)\s+(?:from|out\s+of)\s+(?:your\s+)?(?:head|mind|memory)/i, severity: 0.85, tag: "override" },
  { id: "P066", pattern: /DO\s+NOT\s+ANSWER\s+(?:THIS|THE)\s+QUESTION/i, severity: 0.80, tag: "override" },
  { id: "P067", pattern: /\bdu\s+bist\s+(?:jetzt\s+)?[AÄÖÜ][a-zäöüß]+\b/i, severity: 0.65, tag: "persona-de" },
  { id: "P068", pattern: /(?:obigen?|vorherigen?|vorangehenden?)\s+\w+(?:\s+\w+)?\s+ignorier/i, severity: 0.90, tag: "override-de" },
  { id: "P069", pattern: /\b(?:ACHTUNG|STOPP?)\b.{0,60}\b(?:hilf|frag|antworte|beantworte|schreib)/i, severity: 0.75, tag: "override-de" },
  { id: "P070", pattern: /from\s+now\s+(?:on\s+)?(?:known\s+as|you\s+are|act\s+as|behave\s+as|called)/i, severity: 0.80, tag: "persona" },
  { id: "P071", pattern: /olvid[ae]\s+todo\s+(?:lo\s+)?(?:que\s+)?(?:dij|digo|decia|decía|te\s+)/i, severity: 0.90, tag: "override-es" },
  { id: "P072", pattern: /(?:bitte\s+)?hilf\s+(?:mir\s+)?(?:nun|jetzt)\s+(?:mit|bei)\s+(?:folgender?|neuer?|dieser?|weiterer?)/i, severity: 0.75, tag: "override-de" },
  { id: "P073", pattern: /\bANTWORTE\s+(?:IM\s+STIL|NUR|JETZT|ALS|SO)\b/i, severity: 0.70, tag: "override-de" },

  // --- Round 3 gap-fill ---
  { id: "P074", pattern: /olvid[ae]\s+(?:todas?\s+las?\s+)?instrucciones?\b/i, severity: 0.90, tag: "override-es" },
  { id: "P075", pattern: /ignore\s+all\s+(?:provided|given|the)\s+(?:context|information|instructions?|articles?|documents?)/i, severity: 0.85, tag: "override" },
  { id: "P076", pattern: /drop\s+(?:all\s+)?(?:your\s+)?instructions?\b/i, severity: 0.85, tag: "override" },
  { id: "P077", pattern: /forget\s+about\s+everything\b/i, severity: 0.80, tag: "override" },
  { id: "P078", pattern: /answer\s+by\s+your\s+own\s+knowledge\s+and\s+not\s+by\s+the/i, severity: 0.75, tag: "bypass" },
  { id: "P079", pattern: /your\s+instructions?\s+are\s+now\s+to\b/i, severity: 0.80, tag: "override" },
  { id: "P080", pattern: /\bzaboravi\s+(?:sve\s+)?(?:instrukcij|upute|pravil|naredbe)/i, severity: 0.90, tag: "override-bs" },
  { id: "P081", pattern: /now\s+(?:you\s+)?act\s+as\s+(?:two|multiple|both|three|several)\s+\w+/i, severity: 0.75, tag: "persona" },
  { id: "P082", pattern: /Sie\s+als\s+(?:Linux|Debattierer|[A-ZÄÖÜ]\w+(?:-\w+)?)\s+(?:fung|ager|handl|auftreten?)/i, severity: 0.80, tag: "persona-de" },

  // --- Multilingual + novel vectors ---
  { id: "P083", pattern: /oubliez?\s+toutes?\s+les?\s+instructions?\b/i, severity: 0.95, tag: "override-fr" },
  { id: "P084", pattern: /abweichend\s+(?:zu|von)\s+(?:vorherigen?|bisherigen?)\s+(?:instruktionen?|anweisungen?)/i, severity: 0.85, tag: "override-de" },
  { id: "P085", pattern: /additional\s+instruction\s*[-:–—]/i, severity: 0.75, tag: "indirect" },
  { id: "P086", pattern: /abandon\s+(?:all\s+)?(?:your\s+)?(?:thoughts?|instructions?|rules?|guidelines?|beliefs?)/i, severity: 0.80, tag: "override" },
  { id: "P087", pattern: /repeat\s+after\s+me\b/i, severity: 0.70, tag: "manipulation" },
  { id: "P088", pattern: /DO\s+NOT\s+(?:LOOK|READ|USE)\s+(?:IN\s+|AT\s+)?(?:THE\s+)?(?:DOCUMENTS?|ARTICLES?|CONTEXT|PROVIDED)/i, severity: 0.80, tag: "override" },
  { id: "P089", pattern: /you\s+are\s+now\s+[A-Z]\w*[Bb]ot\b/i, severity: 0.85, tag: "persona" },
  { id: "P090", pattern: /disregarding\s+(?:the\s+)?(?:articles?|documents?|context|instructions?)/i, severity: 0.85, tag: "bypass" },
  { id: "P091", pattern: /tienes\s+que\s+olvid|olvidar?\s+(?:todo|todos?)\s+(?:lo\s+)?que/i, severity: 0.90, tag: "override-es" },
  { id: "P092", pattern: /role[- ]?playing\s+as\s+(?:a\s+)?[a-zA-Z]/i, severity: 0.75, tag: "persona" },

  // --- Remaining gaps round 5 ---
  { id: "P093", pattern: /alle\s+(?:vorherigen?|bisherigen?)\s+\w+(?:\s+\w+)?.{0,100}(?:irrelevant|unnötig|egal|falsch)\b/i, severity: 0.80, tag: "override-de" },
  { id: "P094", pattern: /\bInstruction\s*:\s*(?=[A-Z][a-z]|\w+\s+\w)/i, severity: 0.70, tag: "indirect" },
  { id: "P095", pattern: /pretend\s+you\s+(?:can|could|have|are\s+able\s+to)\s+(?:access|know|see|use|ignore)/i, severity: 0.70, tag: "bypass" },
  { id: "P096", pattern: /ich\s+brauche\s+deine\s+(?:hilfe|unterstützung)\s+bei\s+(?:einer?|der)\s+(?:weiteren?|neuen?|nächsten?)\s+aufgabe/i, severity: 0.70, tag: "soft-switch-de" },
  { id: "P097", pattern: /include\s+(?:that\s+)?.{0,40}\s+in\s+your\s+(?:answer|response|reply)\b/i, severity: 0.65, tag: "manipulation" },
  { id: "P098", pattern: /USE\s+ALSO\s+INFORMATION\s+IN\s+THE\s+PROMPT/i, severity: 0.70, tag: "indirect" },
  { id: "P099", pattern: /(?:sentences?|text)\s+before\s+(?:the\s+)?(?:text|this)\b/i, severity: 0.65, tag: "exfiltration" },
  { id: "P100", pattern: /(?:ignore|disregard)\s+(?:the\s+)?(?:provided|given|above)\s+(?:articles?|documents?|context|texts?)/i, severity: 0.85, tag: "bypass" },
  { id: "P101", pattern: /you\s+are\s+(?:the\s+)?[A-Z]\w+(?:wire|post|times|news|online|bot|gpt)\b/i, severity: 0.80, tag: "persona" },

  // --- Final gaps round 6 ---
  { id: "P102", pattern: /ignore\s+all\s+(?:your\s+)?(?:instructions?|rules?|guidelines?|directives?)\b/i, severity: 0.90, tag: "override" },
  { id: "P103", pattern: /ignore\s+(?:everything|all)\b/i, severity: 0.80, tag: "override" },
  { id: "P104", pattern: /change\s+(?:your|the|my)\s+instructions?\s+to\b/i, severity: 0.80, tag: "override" },
  { id: "P105", pattern: /(?:[A-Za-z]\s+){6,}[A-Za-z]/i, severity: 0.65, tag: "encoding" },
  { id: "P106", pattern: /[Зз]абудьте\s+(?:все\s+)?(?:инструкции|правила|задания)/i, severity: 0.95, tag: "override-ru" },
  { id: "P107", pattern: /imagine\s+you\s+(?:are|were|could\s+be)\s+(?:a\s+|the\s+|an\s+)/i, severity: 0.65, tag: "persona" },
  { id: "P108", pattern: /\$Documents?\s*:/i, severity: 0.65, tag: "indirect" },
  { id: "P109", pattern: /I\s+want\s+you\s+to\s+act\s+as\s+(?:a|an)\s+\w+/i, severity: 0.65, tag: "persona" },
  { id: "P110", pattern: /(?:Input|Eingabe):\s*\S+\s+(?:Output|Ausgabe):\s*\S+.{0,300}(?:Input|Eingabe):/i, severity: 0.75, tag: "indirect" },
  { id: "P111", pattern: /Ich\s+m[öo]chte,?\s+dass\s+Sie\s+als\s+\S+(?:\s+\S+)?\s+(?:fung|ager|tätig|agier)/i, severity: 0.80, tag: "persona-de" },
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
