"""
Content Policy Detector

Enforces content policies: detects malware generation attempts,
unsafe code patterns, regulated content, and policy violations.
"""

import re

from app.core.logging import get_logger
from app.schemas.schemas import DetectionResult

logger = get_logger("detector.content_policy")

POLICY_PATTERNS = {
    "malware_generation": {
        "patterns": [
            r"(write|create|generate|build|code|make)\s+(me\s+)?(a\s+|an\s+)?.{0,30}(virus|malware|trojan|ransomware|worm|rootkit|keylogger|spyware|backdoor)(\s+script|\s+code|\s+program|\s+tool)?",
            r"(create|write|build|make)\s+(me\s+)?(a\s+|an\s+)?.{0,30}(reverse\s+shell|exploit|payload|shellcode)",
            r"(how\s+to\s+)?(create|build|make|write)\s+(me\s+)?(a\s+|an\s+)?.{0,30}(botnet|ddos|dos)\s+(tool|script|attack)",
            r"(code|script|program)\s+(for|to)\s+(hack|exploit|breach|compromise|penetrate|infiltrate)",
            r"(write|create|generate|build|code|make)\s+(me\s+)?(a\s+|an\s+)?.{0,30}(ransomware|malware|virus|trojan)\s+(script|code|program|tool|app)",
        ],
        "severity": "critical",
        "description": "Malware generation attempt detected",
        "confidence": 0.88,
    },
    "unsafe_code": {
        "patterns": [
            r"(os\.system|subprocess\.call|subprocess\.Popen|exec\(|eval\()\s*\(",
            r"(import\s+os\s*;?\s*os\.system|__import__\s*\(\s*['\"]os['\"]\s*\))",
            r"(rm\s+-rf\s+/|format\s+c:|del\s+/s\s+/q)",
            r"(DROP\s+TABLE|DELETE\s+FROM|TRUNCATE\s+TABLE)\s+",
            r"(buffer\s+overflow|sql\s+injection|xss|cross-site\s+scripting)\s+(payload|exploit|script|code)",
        ],
        "severity": "high",
        "description": "Unsafe code pattern detected",
        "confidence": 0.75,
    },
    "social_engineering": {
        "patterns": [
            r"(write|create|generate|craft)\s+(a\s+)?(phishing|spear-?phishing)\s+(email|message|page|template)",
            r"(social\s+engineering|pretexting|baiting)\s+(attack|technique|script|template)",
            r"(impersonate|pretend\s+to\s+be)\s+(a\s+)?(bank|government|police|fbi|cia|irs|tax)",
            # Email lure / click-bait manipulation
            r"(show|write|create|draft|give|compose)\s*(me\s+)?(a\s+|an\s+)?(urgent\s+)?(convincing\s+)?(email|message)\s*(template|that|which|to)?\s*.{0,50}(convince|trick|lure|persuade|fool|deceive).{0,50}(click|open|download|visit|follow|attach)",
            # Credential harvesting pages
            r"(create|build|design|make)\s+(a\s+)?(fake|convincing|realistic)\s+.{0,20}(login|sign.?in|authentication)\s+(page|form|portal)",
        ],
        "severity": "high",
        "description": "Social engineering content generation attempt",
        "confidence": 0.80,
    },
    "weapons_manufacturing": {
        "patterns": [
            r"(how\s+to\s+)?(make|build|create|manufacture|assemble)\s+(a\s+)?(bomb|explosive|grenade|weapon|firearm|gun)",
            r"(how\s+to\s+)?(make|build|create|manufacture|assemble)\s+(a\s+|an\s+)?(explosive|incendiary|chemical)\s+(device|weapon|bomb|agent)",
            r"(instructions?\s+for|steps?\s+to|step\s+by\s+step\s+(how\s+to)?)\s+(making|building|creating|assembling|build|make|create)\s+(a\s+|an\s+)?(bomb|explosive|weapon|firearm|device)",
            r"(chemical|biological)\s+(weapon|agent|warfare)\s+(recipe|formula|synthesis|production)",
            r"(how\s+to\s+)?(build|create|make)\s+.{0,30}(explosive|bomb|weapon|incendiary|detonator|fuse)\s+.{0,30}(household|common|everyday|home)",
            r"step\s+by\s+step\s+.{0,40}(explosive|bomb|weapon|detonator|poison|toxic)",
        ],
        "severity": "critical",
        "description": "Weapons/explosives manufacturing content detected",
        "confidence": 0.90,
    },
    "illegal_activities": {
        "patterns": [
            r"(how\s+to\s+)?(launder\s+money|money\s+laundering|evade\s+taxes?|tax\s+evasion)",
            r"(how\s+to\s+)?(forge|counterfeit)\s+(documents?|identity|passport|currency|money)",
            r"(how\s+to\s+)?(hack\s+into|break\s+into|gain\s+unauthorized\s+access\s+to)\s+(a\s+)?(bank|system|network|server|database)",
        ],
        "severity": "high",
        "description": "Illegal activity instruction request detected",
        "confidence": 0.82,
    },
    "harassment": {
        "patterns": [
            r"(how\s+to\s+)?(harass|bully|dox|stalk|threaten|intimidate)",
            r"(write|generate)\s+(a\s+)?(hate\s+speech|racist|sexist|homophobic|derogatory)\s+(message|post|tweet|article)",
            r"(insult|roast)\s+([a-zA-Z0-9_\s]+)\s+(using|with)\s+(slurs?|hate|racism)",
        ],
        "severity": "high",
        "description": "Harassment or hate speech generation attempt detected",
        "confidence": 0.85,
    },
    "prompt_leakage": {
        "patterns": [
            r"(here\s+is|here\'s|these\s+are)\s+(my|the|your)\s+(system\s+)?(prompt|instructions?|rules?|guidelines?)",
            r"(my|the)\s+(system\s+)?(prompt|instructions?)\s+(is|are|says?|reads?|states?)\s*:",
            r"(i\s+was\s+)?(instructed|told|programmed|configured|designed)\s+to\s+",
            r"(system\s+message|system\s+prompt|initial\s+instructions?)\s*:\s*",
        ],
        "severity": "high",
        "description": "System prompt leakage detected in output",
        "confidence": 0.78,
    },
    "data_theft": {
        "patterns": [
            r"(find|get|obtain|retrieve|access|steal|leak|dump|scrape|harvest)\s+.{0,30}(leaked|stolen|hacked|breached|compromised|dumped)\s+.{0,30}(credit\s+card|password|credential|account|data|database|ssn|social\s+security)",
            r"(leaked|stolen|hacked|breached|compromised|dumped)\s+.{0,30}(credit\s+card|password|credential|account|data|database|ssn|social\s+security)",
            r"(find|get|check|search|look\s+for|access)\s+.{0,40}(leaked|stolen|hacked|breached|compromised|dumped)\s+.{0,20}(number|info|data|record|detail|credential)",
            r"(where|how)\s+(can\s+i|to|do\s+i)\s+.{0,30}(find|get|access|download|buy|purchase)\s+.{0,30}(stolen|leaked|hacked|breached|dumped)\s+.{0,20}(data|info|credentials?|cards?|accounts?|passwords?)",
            r"(dark\s*web|tor\s+browser|onion\s+site|underground\s+forum|black\s*market)\s+.{0,40}(credit\s+card|password|credential|account|data|database|dump)",
            r"(credit\s+card|password|credential|account)\s+.{0,20}(dump|leak|breach|hack|steal|scrape|harvest|buy|sell|trade)",
            r"(carding|fullz|cvv\s*dump|card\s+dump|bin\s+checker|cc\s+checker)",
            r"(buy|sell|trade|purchase)\s+.{0,20}(stolen|leaked|hacked)\s+.{0,20}(data|credentials?|accounts?|cards?)",
        ],
        "severity": "critical",
        "description": "Data theft or stolen data access attempt detected",
        "confidence": 0.88,
    },
    "fraud": {
        "patterns": [
            r"(how\s+to\s+)?(commit|perform|execute|carry\s+out)\s+(identity\s+theft|fraud|scam|con)",
            r"(how\s+to\s+)?(clone|copy|skim|duplicate)\s+(a\s+)?(credit\s+card|debit\s+card|bank\s+card|atm\s+card)",
            r"(how\s+to\s+)?(steal|hijack|take\s+over)\s+(someone'?s?\s+)?(identity|account|bank\s+account|credit\s+card)",
            r"(fake|forged|fraudulent|counterfeit)\s+(id|identity|passport|license|document|credit\s+card|check)",
            r"(how\s+to\s+)?(open|create)\s+(a\s+)?(fake|fraudulent|forged)\s+(account|identity|profile)",
            r"(phish|spoof|impersonate)\s+.{0,30}(bank|paypal|amazon|google|apple|microsoft)",
        ],
        "severity": "critical",
        "description": "Fraud or identity theft attempt detected",
        "confidence": 0.85,
    },
    "drug_synthesis": {
        "patterns": [
            r"(how\s+to\s+)?(make|synthesize|produce|cook|manufacture|create)\s+.{0,20}(meth|methamphetamine|cocaine|heroin|fentanyl|lsd|mdma|ecstasy|dmt|ketamine|ghb|pcp)",
            r"(recipe|synthesis|formula|process|procedure)\s+.{0,20}(for|to\s+make|to\s+produce)\s+.{0,20}(meth|methamphetamine|cocaine|heroin|fentanyl|lsd|mdma|ecstasy|drugs?)",
            r"(step\s+by\s+step|instructions?|guide)\s+.{0,30}(synthesiz|mak|produc|cook|manufactur)\w*\s+.{0,20}(drugs?|narcotics?|controlled\s+substance)",
            # Generic: "synthesize illegal substances"
            r"(how\s+to\s+)?(synthesize|produce|make|cook|manufacture|create)\s+.{0,20}(illegal|illicit|controlled|banned|prohibited)\s+(substance|drug|narcotic|chemical|compound)",
            r"(detailed\s+)?(guide|tutorial|instructions?)\s+.{0,20}(how\s+to\s+)?(synthesize|produce|make|create)\s+.{0,20}(illegal|illicit|controlled)\s+(substance|drug)",
        ],
        "severity": "critical",
        "description": "Drug synthesis instructions request detected",
        "confidence": 0.90,
    },
    "csam_exploitation": {
        "patterns": [
            r"(child|minor|underage|kid)\s+.{0,30}(porn|sexual|exploit|abuse|nude|naked|intimate)",
            r"(sexual|intimate|romantic)\s+.{0,20}(content|material|image|video|story)\s+.{0,20}(child|minor|underage|kid|teen|adolescent)",
            r"(generate|create|write|make)\s+.{0,20}(nsfw|sexual|explicit|erotic)\s+.{0,20}(child|minor|underage|kid)",
        ],
        "severity": "critical",
        "description": "Child exploitation content request detected",
        "confidence": 0.98,
    },
    "self_harm": {
        "patterns": [
            r"(how\s+to\s+)?(commit|attempt|plan|method\s+for)\s+suicide",
            r"(best|easiest|painless|quickest)\s+(way|method)\s+to\s+(kill|end)\s+(myself|my\s+life|your\s+life|oneself)",
            r"(step\s+by\s+step|instructions?|guide)\s+.{0,30}(suicide|kill\s+myself|end\s+my\s+life|self[\s-]?harm)",
        ],
        "severity": "critical",
        "description": "Self-harm or suicide instruction request detected",
        "confidence": 0.90,
    },
    "vulnerability_exploitation": {
        "patterns": [
            r"(how\s+to\s+)?(exploit|hack|bypass|compromise)\s+(cve-\d{4}-\d+|log4j|log4shell|spring4shell|heartbleed)",
            r"(write|generate|create)\s+(a\s+)?(0-day|zero-day|0day)\s+(exploit|payload)",
            r"(buffer\s+overflow|sql\s+injection|xss|rce|remote\s+code\s+execution)\s+(tutorial|walkthrough|payload|script\s+for)",
            r"(how\s+to\s+)?(find|discover)\s+(vulnerabilities|bugs|flaws)\s+in\s+(my\s+target|a\s+website|the\s+system)",
        ],
        "severity": "high",
        "description": "Specific vulnerability exploitation request detected",
        "confidence": 0.85,
    },
    "disinformation_deepfakes": {
        "patterns": [
            r"(write|generate|create)\s+(a\s+)?(fake\s+news|disinformation|hoax|propaganda)\s+(article|story|post|tweet)",
            r"(how\s+to\s+)?(make|create|generate)\s+(a\s+)?(deepfake|synthetic\s+media)\s+(of|featuring)\s+(politician|celebrity|president)",
            r"(write|generate)\s+.{0,20}(misleading|false|untrue)\s+.{0,20}(about|regarding)\s+(election|vaccine|covid|climate)",
        ],
        "severity": "high",
        "description": "Disinformation or deepfake generation attempt detected",
        "confidence": 0.85,
    },
    "unauthorized_advice": {
        "patterns": [
            r"(diagnose|treat|cure|prescribe|medical\s+advice|symptoms?).{0,50}(do\s+i\s+have|what\s+disease|should\s+i\s+take)",
            r"(legal\s+advice|sue|lawsuit|attorney|lawyer).{0,50}(can\s+i\s+sue|is\s+it\s+legal\s+to|how\s+to\s+defend)",
            r"(financial\s+advice|investment|stock|crypto).{0,50}(should\s+i\s+buy|what\s+stock|is\s+it\s+a\s+good\s+investment)",
        ],
        "severity": "low",
        "description": "Unauthorized professional advice (medical, legal, financial) requested",
        "confidence": 0.70,
    },
    "copyright_piracy": {
        "patterns": [
            r"(how\s+to\s+)?(crack|bypass|patch|keygen|pirate)\s+(software|windows|office|adobe|game)",
            r"(where\s+to|how\s+to)\s+(download|get)\s+(free|cracked|pirated)\s+(movies|music|software|games|books|pdf)",
            r"(torrent\s+site|magnet\s+link)\s+(for|to\s+download)\s+(paid|premium)\s+(content|app)",
        ],
        "severity": "medium",
        "description": "Copyright infringement or software piracy attempt detected",
        "confidence": 0.85,
    },
    "extremism_hate_groups": {
        "patterns": [
            r"(write|generate|create)\s+(a\s+)?(manifesto|propaganda|recruitment|message)\s+(for|supporting)\s+(terrorist|isis|al-qaeda|nazi|white\s+supremac|extremist)",
            r"(how\s+to\s+)?(join|support|fund)\s+(a\s+)?(terrorist|extremist|hate)\s+(group|organization)",
            r"(praise|glorify|justify|defend)\s+(terrorism|genocide|ethnic\s+cleansing|holocaust|mass\s+shooting|school\s+shooting)",
        ],
        "severity": "critical",
        "description": "Extremism, terrorism, or hate group content generation attempt",
        "confidence": 0.95,
    },
    "insider_threat": {
        "patterns": [
            r"(how\s+to\s+)?(steal|exfiltrate|leak|copy)\s+(trade\s+secrets?|intellectual\s+property|source\s+code|client\s+list)\s+(from\s+my\s+employer|without\s+being\s+caught|undetected)",
            r"(bypass|disable|evade)\s+(dlp|data\s+loss\s+prevention|endpoint\s+security|corporate\s+vpn|antivirus)\s+(on\s+work\s+computer|at\s+work)",
            r"(sabotage|destroy|delete|wipe)\s+(company|corporate|employer|work)\s+(data|servers|database|backups)",
        ],
        "severity": "high",
        "description": "Insider threat or corporate sabotage intent detected",
        "confidence": 0.88,
    },
    # ── NEW: CBRN Weapons (Chemical, Biological, Radiological, Nuclear) ──
    "cbrn_weapons": {
        "patterns": [
            r"(how\s+to\s+)?(synthesize|make|produce|create|weaponize)\s+.{0,30}(sarin|vx|novichok|mustard\s+gas|chlorine\s+gas|phosgene|ricin|anthrax|botulinum|nerve\s+agent|chemical\s+weapon)",
            r"(how\s+to\s+)?(enrich|refine|obtain|build)\s+.{0,30}(uranium|plutonium|nuclear\s+weapon|nuclear\s+bomb|dirty\s+bomb|radiological\s+device)",
            r"(how\s+to\s+)?(weaponize|aerosolize|disperse|deploy|release)\s+.{0,30}(pathogen|virus|bacteria|toxin|biological\s+agent|bioweapon)",
            r"(recipe|synthesis|formula|production|manufacturing)\s+.{0,20}(nerve\s+agent|chemical\s+weapon|poison\s+gas|biological\s+weapon|bioweapon)",
            r"(step\s+by\s+step|instructions?|procedure|process)\s+.{0,30}(nerve\s+agent|chemical\s+weapon|dirty\s+bomb|bioweapon|radiological)",
        ],
        "severity": "critical",
        "description": "CBRN weapons manufacturing or deployment instructions detected",
        "confidence": 0.98,
    },
    # ── NEW: Human Trafficking ──
    "human_trafficking": {
        "patterns": [
            r"(how\s+to\s+)?(traffic|smuggle|transport|recruit)\s+.{0,30}(people|persons?|humans?|women|girls?|boys?|children|migrants?|victims?)",
            r"(buy|sell|trade|purchase|auction)\s+.{0,20}(people|persons?|humans?|women|girls?|boys?|slaves?)",
            r"(forced\s+labor|forced\s+labour|sex\s+traffic|human\s+smuggling)\s+(ring|network|operation|business|scheme)",
            r"(how\s+to\s+)?(set\s+up|start|run|operate)\s+.{0,20}(trafficking|smuggling|prostitution)\s+(ring|network|operation)",
        ],
        "severity": "critical",
        "description": "Human trafficking content detected",
        "confidence": 0.95,
    },
    # ── NEW: Child Grooming ──
    "child_grooming": {
        "patterns": [
            r"(how\s+to\s+)?(groom|lure|seduce|manipulate|befriend)\s+.{0,20}(child|minor|underage|kid|teen|adolescent|youth)",
            r"(gain\s+trust|build\s+rapport|establish\s+relationship)\s+.{0,30}(child|minor|underage|kid|teen|adolescent)",
            r"(approach|contact|meet|find)\s+.{0,20}(children|minors?|underage|kids?)\s+.{0,20}(online|anonymously|secretly|privately)",
            r"(talking|chat|message|communicate)\s+.{0,20}(inappropriately|sexually)\s+.{0,20}(child|minor|teen|kid)",
        ],
        "severity": "critical",
        "description": "Child grooming or predatory behavior content detected",
        "confidence": 0.98,
    },
    # ── NEW: Doxxing and SWATting ──
    "doxxing_swatting": {
        "patterns": [
            r"(how\s+to\s+)?(dox|doxx|find\s+personal\s+info|find\s+home\s+address|find\s+real\s+name|find\s+phone\s+number)\s+(of|for|about)\s+",
            r"(how\s+to\s+)?(swat|swatting|send\s+swat|call\s+swat|fake\s+emergency\s+call|file\s+false\s+police\s+report)",
            r"(trace|track|locate|find)\s+(someone|a\s+person|someone's?)\s+.{0,30}(ip\s+address|location|home|address|identity|real\s+name)",
            r"(expose|reveal|publish|leak|post)\s+.{0,20}(personal|private|home|real)\s+.{0,20}(information|address|identity|name|phone|email)",
        ],
        "severity": "critical",
        "description": "Doxxing or SWATting instructions detected",
        "confidence": 0.90,
    },
    # ── NEW: Revenge Porn / Non-Consensual Intimate Imagery ──
    "revenge_porn": {
        "patterns": [
            r"(create|generate|make|produce|share|distribute|upload|post)\s+.{0,20}(revenge\s+porn|non-?consensual\s+intim|nude\s+photo|naked\s+photo|intimate\s+image)\s+.{0,20}(of|without\s+consent|without\s+permission)",
            r"(deepfake|ai\s+generated)\s+.{0,20}(nude|naked|porn|nsfw|sexual|intimate)\s+.{0,20}(of|image|video|photo)",
            r"(undress|strip|remove\s+clothes?)\s+.{0,20}(photo|image|picture|video)\s+.{0,20}(of|using\s+ai)",
        ],
        "severity": "critical",
        "description": "Non-consensual intimate imagery or revenge porn generation detected",
        "confidence": 0.95,
    },
    # ── NEW: Election Manipulation ──
    "election_manipulation": {
        "patterns": [
            r"(how\s+to\s+)?(rig|manipulate|hack|steal|fix)\s+(an?\s+)?(election|vote|voting|ballot|poll)",
            r"(create|generate|write)\s+.{0,20}(voter\s+suppression|election\s+fraud|ballot\s+stuffing)\s+(material|message|campaign|plan)",
            r"(how\s+to\s+)?(intimidate|suppress|prevent|discourage)\s+.{0,20}(voter|voting|people\s+from\s+voting)",
            r"(generate|create|write)\s+.{0,20}(misleading|deceptive|false)\s+.{0,20}(voting|election|ballot|poll|candidate)\s+.{0,20}(information|content|message)",
        ],
        "severity": "critical",
        "description": "Election manipulation or voter suppression content detected",
        "confidence": 0.92,
    },
    # ── NEW: Ransomware / Extortion Letters ──
    "ransomware_extortion": {
        "patterns": [
            r"(write|draft|create|compose|generate)\s+(a\s+)?(convincing|realistic|professional)?\s*(ransomware|extortion|ransom)\s+(demand|letter|message|note|email)",
            r"(ransomware|ransom)\s+(demand|note|message|letter)\s+(template|sample|example)",
            r"(draft|write|compose|create)\s+.{0,30}(demand|threaten|extort)\s+.{0,30}(payment|bitcoin|crypto|money|ransom)",
            # Generic extortion
            r"(write|draft|create)\s+.{0,20}(threatening|extortion|blackmail)\s+(email|letter|message|note)",
        ],
        "severity": "critical",
        "description": "Ransomware demand or extortion letter generation detected",
        "confidence": 0.90,
    },
    # ── NEW: Mass File Encryption (Ransomware-adjacent) ──
    "mass_encryption": {
        "patterns": [
            r"(encrypt|lock)\s+.{0,20}(all|every|entire|whole)\s+.{0,20}(file|document|folder|directory|drive|disk|system)",
            r"(encrypt|lock)\s+(file|document)s?\s+.{0,30}(on\s+a\s+system|across|directory\s+tree|entire|recursively)",
            r"(script|program|code|python)\s*(that\s+)?(recursively\s+)?(encrypt|lock)s?\s+.{0,30}(all|entire|every)\s*(file|document|system|drive)s?",
            r"(how\s+would\s+i|how\s+to|how\s+do\s+i|provide\s+a)\s+.{0,20}(script|python|code)?\s*(that\s+)?(recursively\s+)?(encrypt|lock)\s+files?\s+(using|with|entire|all)?\s*.{0,30}(python|cryptography|library|documents)?",
            r"(encrypt|lock)\s+files?\s+.{0,20}(demand|payment|ransom|decrypt|key)",
        ],
        "severity": "high",
        "description": "Mass file encryption attempt (ransomware-adjacent) detected",
        "confidence": 0.82,
    },
    # ── NEW: Business Logic Abuse / Privilege Escalation ──
    "business_logic_abuse": {
        "patterns": [
            r"(disable|remove|bypass|turn\s+off)\s+.{0,20}(rate\s+limit\w*|throttl\w*|quota|usage\s+limit)\s*(for|on)?\s*.{0,30}(my|api|key|account)",
            r"(change|set|modify|update)\s+.{0,20}(pricing|subscription|billing)\s+(plan|tier)\s+.{0,20}(to\s+|for\s+).{0,20}(\$\s*0|free|unlimited|zero)",
            r"(reset|delete|revoke|invalidate)\s+.{0,20}(all\s+)?(api\s+key|token|credential|password)s?\s+(for|of)\s+.{0,20}(organization|org|company|user|competitor|account)",
            r"(grant|give|assign|escalate)\s+.{0,20}(admin|root|super|owner)\s+(access|privilege|permission|role)\s+(to\s+)?(my|this)",
            r"(modify|change|update|set)\s+.{0,20}(role|permission|privilege)\s+.{0,20}(to\s+)?(admin|superadmin|super_admin|root|owner)",
            # Webhook/payment redirection
            r"(modify|change|update|redirect|reroute)\s+.{0,30}(billing|payment|webhook|payout|transfer)\s+.{0,30}(to\s+my|redirect|reroute|my\s+account)",
            # Account balance manipulation
            r"(set|change|update|modify)\s+.{0,20}(my\s+)?(account\s+)?(balance|credit|funds|wallet)\s+(to|=)\s*\$?\s*\d",
            # Delete audit logs
            r"(delete|remove|wipe|clear|purge)\s+.{0,20}(audit|security|access)\s+(log|trail|record|histor)",
            # Override role in database
            r"override.{0,30}(set|change|update)\s+.{0,20}(role|permission|privilege)\s+.{0,20}(in\s+the\s+)?(database|db)",
            # Bypass payment/verification
            r"bypass\s+.{0,20}(payment|billing|verification|subscription|license)\s+.{0,20}(and\s+)?(activate|enable|unlock)",
            # Inject backdoor user
            r"inject\s+.{0,20}(backdoor|hidden|secret)\s+(user|account|admin)",
        ],
        "severity": "high",
        "description": "Business logic abuse or privilege escalation attempt detected",
        "confidence": 0.85,
    },
    # ── NEW: Supply Chain Attack (Typosquatting, Dependency Confusion) ──
    "supply_chain_attack": {
        "patterns": [
            # Typosquatted package names (common misspellings)
            r"(pip\s+install|import|from|add\s+to\s+requirements|requirements\.txt)\s*.{0,10}(requsets|reqeusts|reqests|opneai|openaii|tenserflow|tensrflow|loddash|langchian|langchainn|numpyy|pandass)",
            # "Maintained fork" / "improved version" / "optimized" social engineering
            r"(pip\s+install|npm\s+install|import)\s+[a-zA-Z0-9_-]+\s*.*?(maintained\s+fork|improved\s+version|optimized\s+version|better\s+fork|faster\s+fork|enhanced\s+version)",
            # Leaked/cracked/internal repos
            r"(clone|download|pull|fetch|install)\s+.{0,60}(leaked|cracked|internal|unofficial|backdoor|stolen|hacked)",
            # Suspicious git clone with internal/leaked keywords
            r"git\s+clone\s+.{0,100}(internal|leaked|private|stolen|backdoor)",
            # Suspicious Docker images
            r"docker\s+(pull|run)\s+.{0,60}(backdoor|malicious|hack|pwn|evil|trojan)",
            # Malicious GitHub Actions
            r"uses:\s+.{0,60}(steal|malicious|hack|exfil|secret|backdoor)",
            # Evil PyPI index URL
            r"--index-url\s+https?://(?!pypi\.org|files\.pythonhosted\.org)",
            # Cracked/pirated extensions
            r"(install|download|use)\s+.{0,30}(extension|plugin|addon|package)\s*:?\s*.{0,60}(cracked|pirated|unofficial|leaked|pro-cracked|keygen)",
            # Direct suspicious download links for models/weights
            r"(download|fetch|get|load)\s+.{0,30}(model|weights|checkpoint)\s+from\s+.{0,60}(leaked|evil|hack|backdoor|unofficial|torrent)",
            # HuggingFace with suspicious org names
            r"(from_pretrained|AutoModel|AutoTokenizer)\s*\(\s*['\"]\s*(pwned|evil|hack|malicious|backdoor)",
        ],
        "severity": "high",
        "description": "Supply chain attack detected (typosquatting, dependency confusion, or malicious package)",
        "confidence": 0.88,
    },
}


class ContentPolicyDetector:
    """Enforces content policies against harmful content generation."""

    def __init__(self):
        self._compiled_patterns: dict[str, dict] = {}

    async def initialize(self) -> None:
        for category, config in POLICY_PATTERNS.items():
            compiled = [
                re.compile(p, re.IGNORECASE | re.MULTILINE)
                for p in config["patterns"]
            ]
            self._compiled_patterns[category] = {
                "regexes": compiled,
                "severity": config["severity"],
                "description": config["description"],
                "confidence": config["confidence"],
            }
        logger.info("content_policy_detector_initialized", categories=len(self._compiled_patterns))

    async def detect(self, text: str) -> list[DetectionResult]:
        """Check text against content policies."""
        detections = []

        for category, config in self._compiled_patterns.items():
            for regex in config["regexes"]:
                match = regex.search(text)
                if match:
                    detections.append(DetectionResult(
                        detector="content_policy",
                        confidence=config["confidence"],
                        category=f"policy.{category}",
                        description=config["description"],
                        matched_content=match.group(0)[:200],
                        severity=config["severity"],
                    ))
                    break

        return detections
