"""
Rules Engine - Loads and manages security detection rules.
Similar to Wazuh rules engine functionality.
"""
import json
import uuid
from pathlib import Path
from typing import List, Dict, Any, Optional
from datetime import datetime

from .models import Rule, RuleCondition, RuleMatch, RuleGroup


class RulesEngine:
    """
    Security rules engine for detecting threats in processed logs.
    """
    
    def __init__(self, rules_directory: str = None):
        """
        Initialize the rules engine.
        
        Args:
            rules_directory: Path to directory containing rule files
        """
        if rules_directory is None:
            rules_directory = str(Path(__file__).parent / "rule_sets")
        
        self.rules_directory = Path(rules_directory)
        self.rules: List[Rule] = []
        self.rule_groups: Dict[str, RuleGroup] = {}
        self.matches: List[RuleMatch] = []
        
        # Statistics
        self.stats = {
            'rules_loaded': 0,
            'rules_enabled': 0,
            'total_matches': 0,
            'matches_by_severity': {
                'CRITICAL': 0,
                'HIGH': 0,
                'MEDIUM': 0,
                'LOW': 0
            }
        }
    
    def load_rules(self):
        """Load all rules from the rules directory"""
        self.rules.clear()
        self.rule_groups.clear()
        
        # Create rules directory if it doesn't exist
        self.rules_directory.mkdir(parents=True, exist_ok=True)
        
        # Load rule files
        rule_files = list(self.rules_directory.glob("*.json"))
        
        if not rule_files:
            print(f"⚠️  No rule files found in {self.rules_directory}")
            print("   Loading default rules...")
            self._create_default_rules()
            return
        
        print(f"📋 Loading rules from {self.rules_directory}")
        
        for rule_file in rule_files:
            try:
                self._load_rule_file(rule_file)
            except Exception as e:
                print(f"  ✗ Error loading {rule_file.name}: {str(e)}")
        
        self.stats['rules_loaded'] = len(self.rules)
        self.stats['rules_enabled'] = sum(1 for r in self.rules if r.enabled)
        
        print(f"✓ Loaded {self.stats['rules_loaded']} rules ({self.stats['rules_enabled']} enabled)")
    
    def _load_rule_file(self, file_path: Path):
        """Load rules from a single JSON file"""
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
        
        # Handle both single rule and rule group formats
        if 'rules' in data:  # Rule group format
            group = RuleGroup(
                group_name=data.get('group_name', file_path.stem),
                description=data.get('description', ''),
                enabled=data.get('enabled', True)
            )
            
            for rule_data in data['rules']:
                rule = self._parse_rule(rule_data)
                if rule:
                    group.add_rule(rule)
                    self.rules.append(rule)
            
            self.rule_groups[group.group_name] = group
            print(f"  ✓ Loaded group '{group.group_name}': {len(group.rules)} rules")
        else:  # Single rule format
            rule = self._parse_rule(data)
            if rule:
                self.rules.append(rule)
                print(f"  ✓ Loaded rule {rule.rule_id}: {rule.name}")
    
    def _parse_rule(self, rule_data: Dict[str, Any]) -> Optional[Rule]:
        """Parse a rule from dictionary data"""
        try:
            # Parse conditions
            conditions = []
            for cond_data in rule_data.get('conditions', []):
                condition = RuleCondition(
                    field=cond_data['field'],
                    operator=cond_data['operator'],
                    value=cond_data['value'],
                    case_sensitive=cond_data.get('case_sensitive', False)
                )
                conditions.append(condition)
            
            # Create rule
            rule = Rule(
                rule_id=rule_data['rule_id'],
                name=rule_data['name'],
                description=rule_data['description'],
                level=rule_data.get('level', 5),
                conditions=conditions,
                mitre_technique=rule_data.get('mitre_technique'),
                mitre_tactic=rule_data.get('mitre_tactic'),
                category=rule_data.get('category', 'generic'),
                tags=rule_data.get('tags', []),
                enabled=rule_data.get('enabled', True),
                match_all=rule_data.get('match_all', True),
                alert_threshold=rule_data.get('alert_threshold', 1),
                frequency=rule_data.get('frequency', 0),
                metadata=rule_data.get('metadata', {})
            )
            
            return rule
            
        except Exception as e:
            print(f"  ✗ Error parsing rule: {str(e)}")
            return None
    
    def evaluate_log(self, log_data: Dict[str, Any]) -> List[RuleMatch]:
        """
        Evaluate a single log against all rules.
        
        Args:
            log_data: Decoded log data
            
        Returns:
            List of rule matches
        """
        matches = []
        
        for rule in self.rules:
            if not rule.enabled:
                continue
            
            if rule.evaluate(log_data):
                # Create match
                matched_conditions = [
                    f"{cond.field} {cond.operator} {cond.value}"
                    for cond in rule.conditions
                    if cond.matches(log_data)
                ]
                
                match = RuleMatch(
                    rule=rule,
                    matched_log=log_data,
                    timestamp=datetime.now().isoformat(),
                    matched_conditions=matched_conditions,
                    alert_id=str(uuid.uuid4())
                )
                
                matches.append(match)
                self.matches.append(match)
                
                # Update statistics
                self.stats['total_matches'] += 1
                self.stats['matches_by_severity'][rule.severity] += 1
        
        return matches
    
    def evaluate_context(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Evaluate entire context (all decoded logs) against rules.
        
        Args:
            context: Processing context with decoded logs
            
        Returns:
            Alert report with all matches
        """
        print(f"\n🔍 Evaluating logs against {len(self.rules)} rules...")
        
        decoded_logs = context.get('decoded_logs', [])
        all_matches = []
        
        for idx, log in enumerate(decoded_logs):
            if (idx + 1) % 100 == 0:
                print(f"  Evaluated {idx + 1}/{len(decoded_logs)} logs...", end='\r')
            
            matches = self.evaluate_log(log)
            all_matches.extend(matches)
        
        print(f"\n✓ Evaluation complete: {len(all_matches)} alerts generated")
        
        # Build alert report
        report = self._build_alert_report(all_matches, context)
        
        return report
    
    def _build_alert_report(self, matches: List[RuleMatch], context: Dict[str, Any]) -> Dict[str, Any]:
        """Build comprehensive alert report"""
        
        # Group alerts by rule
        alerts_by_rule = {}
        for match in matches:
            rule_id = match.rule.rule_id
            if rule_id not in alerts_by_rule:
                alerts_by_rule[rule_id] = []
            alerts_by_rule[rule_id].append(match.to_dict())
        
        # Group alerts by severity
        alerts_by_severity = {
            'CRITICAL': [],
            'HIGH': [],
            'MEDIUM': [],
            'LOW': []
        }
        
        for match in matches:
            alerts_by_severity[match.rule.severity].append(match.to_dict())
        
        # Group by MITRE technique
        alerts_by_mitre = {}
        for match in matches:
            if match.rule.mitre_technique:
                tech = match.rule.mitre_technique
                if tech not in alerts_by_mitre:
                    alerts_by_mitre[tech] = []
                alerts_by_mitre[tech].append(match.to_dict())
        
        # Calculate statistics
        severity_counts = {
            severity: len(alerts)
            for severity, alerts in alerts_by_severity.items()
        }
        
        # Build report
        report = {
            'analysis_metadata': {
                'timestamp': datetime.now().isoformat(),
                'total_logs_analyzed': len(context.get('decoded_logs', [])),
                'total_alerts': len(matches),
                'rules_evaluated': len(self.rules),
                'rules_triggered': len(alerts_by_rule)
            },
            'alerts': {
                'all_alerts': [match.to_dict() for match in matches],
                'by_severity': alerts_by_severity,
                'by_rule': alerts_by_rule,
                'by_mitre_technique': alerts_by_mitre
            },
            'statistics': {
                'severity_distribution': severity_counts,
                'top_triggered_rules': self._get_top_rules(alerts_by_rule, 10),
                'mitre_coverage': list(alerts_by_mitre.keys())
            },
            'risk_summary': self._calculate_risk_summary(severity_counts),
            'engine_stats': self.stats
        }
        
        return report
    
    def _get_top_rules(self, alerts_by_rule: Dict[int, List], limit: int) -> List[Dict]:
        """Get top triggered rules"""
        rule_counts = [
            {
                'rule_id': rule_id,
                'count': len(alerts),
                'rule_name': alerts[0]['rule_name'] if alerts else 'Unknown'
            }
            for rule_id, alerts in alerts_by_rule.items()
        ]
        
        return sorted(rule_counts, key=lambda x: x['count'], reverse=True)[:limit]
    
    def _calculate_risk_summary(self, severity_counts: Dict[str, int]) -> Dict[str, Any]:
        """Calculate overall risk based on alert severities"""
        # Simple risk scoring
        risk_score = (
            severity_counts.get('CRITICAL', 0) * 15 +
            severity_counts.get('HIGH', 0) * 10 +
            severity_counts.get('MEDIUM', 0) * 5 +
            severity_counts.get('LOW', 0) * 1
        )
        
        # Determine risk level
        if risk_score >= 50:
            risk_level = "CRITICAL"
        elif risk_score >= 30:
            risk_level = "HIGH"
        elif risk_score >= 10:
            risk_level = "MEDIUM"
        else:
            risk_level = "LOW"
        
        return {
            'risk_score': risk_score,
            'risk_level': risk_level,
            'critical_alerts': severity_counts.get('CRITICAL', 0),
            'high_alerts': severity_counts.get('HIGH', 0),
            'total_high_priority': severity_counts.get('CRITICAL', 0) + severity_counts.get('HIGH', 0)
        }
    
    def _create_default_rules(self):
        """Create default rule sets"""
        default_rules_dir = self.rules_directory
        default_rules_dir.mkdir(parents=True, exist_ok=True)
        
        # Authentication rules
        auth_rules = {
            "group_name": "authentication",
            "description": "Authentication and access control rules",
            "enabled": True,
            "rules": [
                {
                    "rule_id": 1001,
                    "name": "Failed Login Attempt",
                    "description": "Detects failed authentication attempts",
                    "level": 5,
                    "category": "authentication",
                    "mitre_tactic": "Initial Access",
                    "mitre_technique": "T1078",
                    "tags": ["authentication", "failed_login"],
                    "match_all": False,
                    "conditions": [
                        {"field": "event_type", "operator": "contains", "value": "logon", "case_sensitive": False},
                        {"field": "event_type", "operator": "contains", "value": "login", "case_sensitive": False},
                        {"field": "status", "operator": "contains", "value": "fail", "case_sensitive": False},
                        {"field": "result", "operator": "contains", "value": "fail", "case_sensitive": False}
                    ]
                },
                {
                    "rule_id": 1002,
                    "name": "Successful Privileged Login",
                    "description": "Successful login with administrative privileges",
                    "level": 3,
                    "category": "authentication",
                    "tags": ["authentication", "privileged_access"],
                    "match_all": True,
                    "conditions": [
                        {"field": "event_type", "operator": "contains", "value": "logon", "case_sensitive": False},
                        {"field": "status", "operator": "contains", "value": "success", "case_sensitive": False},
                        {"field": "user", "operator": "contains", "value": "admin", "case_sensitive": False}
                    ]
                }
            ]
        }
        
        # Windows Defender rules
        defender_rules = {
            "group_name": "windows_defender",
            "description": "Windows Defender antivirus detections",
            "enabled": True,
            "rules": [
                {
                    "rule_id": 2001,
                    "name": "Windows Defender Malware Detection",
                    "description": "Windows Defender detected malware",
                    "level": 12,
                    "category": "malware",
                    "mitre_tactic": "Execution",
                    "mitre_technique": "T1204",
                    "tags": ["defender", "malware", "threat"],
                    "match_all": True,
                    "conditions": [
                        {"field": "source", "operator": "contains", "value": "defender", "case_sensitive": False},
                        {"field": "event_type", "operator": "contains", "value": "threat", "case_sensitive": False}
                    ]
                },
                {
                    "rule_id": 2002,
                    "name": "Suspicious File Quarantined",
                    "description": "File was quarantined by Windows Defender",
                    "level": 8,
                    "category": "malware",
                    "tags": ["defender", "quarantine"],
                    "match_all": True,
                    "conditions": [
                        {"field": "action", "operator": "contains", "value": "quarantine", "case_sensitive": False}
                    ]
                }
            ]
        }
        
        # Process execution rules
        process_rules = {
            "group_name": "process_execution",
            "description": "Process creation and execution monitoring",
            "enabled": True,
            "rules": [
                {
                    "rule_id": 3001,
                    "name": "PowerShell Execution",
                    "description": "PowerShell process started",
                    "level": 4,
                    "category": "process",
                    "mitre_tactic": "Execution",
                    "mitre_technique": "T1059.001",
                    "tags": ["powershell", "execution"],
                    "match_all": False,
                    "conditions": [
                        {"field": "process_name", "operator": "contains", "value": "powershell", "case_sensitive": False},
                        {"field": "event_type", "operator": "contains", "value": "process", "case_sensitive": False}
                    ]
                },
                {
                    "rule_id": 3002,
                    "name": "Suspicious Command Line",
                    "description": "Detected suspicious command line execution",
                    "level": 8,
                    "category": "process",
                    "mitre_tactic": "Execution",
                    "mitre_technique": "T1059",
                    "tags": ["command_line", "suspicious"],
                    "match_all": False,
                    "conditions": [
                        {"field": "command_line", "operator": "contains", "value": "whoami", "case_sensitive": False},
                        {"field": "command_line", "operator": "contains", "value": "net user", "case_sensitive": False},
                        {"field": "command_line", "operator": "contains", "value": "tasklist", "case_sensitive": False}
                    ]
                }
            ]
        }
        
        # Network rules
        network_rules = {
            "group_name": "network",
            "description": "Network activity monitoring",
            "enabled": True,
            "rules": [
                {
                    "rule_id": 4001,
                    "name": "Firewall Block Event",
                    "description": "Firewall blocked a connection",
                    "level": 6,
                    "category": "network",
                    "tags": ["firewall", "blocked"],
                    "match_all": True,
                    "conditions": [
                        {"field": "event_type", "operator": "contains", "value": "firewall", "case_sensitive": False},
                        {"field": "action", "operator": "contains", "value": "block", "case_sensitive": False}
                    ]
                },
                {
                    "rule_id": 4002,
                    "name": "Outbound Connection to Suspicious Port",
                    "description": "Connection attempt to commonly malicious port",
                    "level": 7,
                    "category": "network",
                    "mitre_tactic": "Command and Control",
                    "mitre_technique": "T1071",
                    "tags": ["network", "suspicious_port"],
                    "match_all": True,
                    "conditions": [
                        {"field": "direction", "operator": "equals", "value": "outbound", "case_sensitive": False},
                        {"field": "dest_port", "operator": "in_list", "value": [4444, 1337, 31337]}
                    ]
                }
            ]
        }
        
        # Save default rules
        rule_sets = [
            ("authentication_rules.json", auth_rules),
            ("windows_defender_rules.json", defender_rules),
            ("process_execution_rules.json", process_rules),
            ("network_rules.json", network_rules)
        ]
        
        for filename, rules in rule_sets:
            filepath = default_rules_dir / filename
            with open(filepath, 'w', encoding='utf-8') as f:
                json.dump(rules, f, indent=2)
            print(f"  ✓ Created {filename}")
        
        # Reload rules
        self.load_rules()
    
    def get_statistics(self) -> Dict[str, Any]:
        """Get engine statistics"""
        return self.stats.copy()
