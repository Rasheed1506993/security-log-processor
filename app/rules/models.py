"""
Rule models and schemas for the EDR security rules engine.
Similar to Wazuh rules structure.
"""
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional
from enum import Enum


class Severity(Enum):
    """Rule severity levels"""
    LOW = 1
    MEDIUM = 5
    HIGH = 10
    CRITICAL = 15


class RuleLevel(Enum):
    """Wazuh-style rule levels"""
    INFORMATIONAL = 0
    LOW = 3
    MEDIUM = 6
    HIGH = 10
    CRITICAL = 15


@dataclass
class RuleCondition:
    """Represents a single condition in a rule"""
    field: str
    operator: str  # equals, contains, regex, greater_than, less_than, etc.
    value: Any
    case_sensitive: bool = False
    
    def matches(self, log_data: Dict[str, Any]) -> bool:
        """Check if this condition matches the log data"""
        # Get the field value from log data
        field_value = self._get_nested_value(log_data, self.field)
        
        if field_value is None:
            return False
            
        # Convert to string for string operations if needed
        if self.operator in ['contains', 'regex', 'equals']:
            field_value = str(field_value)
            compare_value = str(self.value)
            
            if not self.case_sensitive:
                field_value = field_value.lower()
                compare_value = compare_value.lower()
        
        # Apply operator
        if self.operator == 'equals':
            return field_value == compare_value
        elif self.operator == 'contains':
            return compare_value in field_value
        elif self.operator == 'regex':
            import re
            pattern = re.compile(self.value)
            return bool(pattern.search(str(field_value)))
        elif self.operator == 'greater_than':
            return float(field_value) > float(self.value)
        elif self.operator == 'less_than':
            return float(field_value) < float(self.value)
        elif self.operator == 'in_list':
            return field_value in self.value
        elif self.operator == 'not_equals':
            return field_value != compare_value
        
        return False
    
    def _get_nested_value(self, data: Dict[str, Any], field_path: str) -> Any:
        """Get value from nested dictionary using dot notation"""
        keys = field_path.split('.')
        value = data
        
        for key in keys:
            if isinstance(value, dict):
                value = value.get(key)
                if value is None:
                    return None
            else:
                return None
        
        return value


@dataclass
class Rule:
    """Represents a security detection rule"""
    rule_id: int
    name: str
    description: str
    level: int  # Wazuh-style level (0-15)
    conditions: List[RuleCondition]
    mitre_technique: Optional[str] = None
    mitre_tactic: Optional[str] = None
    category: str = "generic"
    tags: List[str] = field(default_factory=list)
    enabled: bool = True
    metadata: Dict[str, Any] = field(default_factory=dict)
    
    # Rule logic
    match_all: bool = True  # True = AND, False = OR
    
    # Response actions
    alert_threshold: int = 1  # Number of matches before alerting
    frequency: int = 0  # Time window in seconds (0 = no frequency check)
    
    def evaluate(self, log_data: Dict[str, Any]) -> bool:
        """Evaluate if this rule matches the given log data"""
        if not self.enabled:
            return False
            
        if not self.conditions:
            return False
        
        # Evaluate all conditions
        matches = [condition.matches(log_data) for condition in self.conditions]
        
        # Apply match logic (AND/OR)
        if self.match_all:
            return all(matches)
        else:
            return any(matches)
    
    @property
    def severity(self) -> str:
        """Get severity based on level"""
        if self.level >= 12:
            return "CRITICAL"
        elif self.level >= 8:
            return "HIGH"
        elif self.level >= 4:
            return "MEDIUM"
        else:
            return "LOW"


@dataclass
class RuleMatch:
    """Represents a rule match/detection"""
    rule: Rule
    matched_log: Dict[str, Any]
    timestamp: str
    matched_conditions: List[str]
    alert_id: str
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert to dictionary for JSON serialization"""
        return {
            'alert_id': self.alert_id,
            'rule_id': self.rule.rule_id,
            'rule_name': self.rule.name,
            'description': self.rule.description,
            'severity': self.rule.severity,
            'level': self.rule.level,
            'category': self.rule.category,
            'mitre_technique': self.rule.mitre_technique,
            'mitre_tactic': self.rule.mitre_tactic,
            'timestamp': self.timestamp,
            'matched_conditions': self.matched_conditions,
            'matched_log': self.matched_log,
            'tags': self.rule.tags
        }


@dataclass
class RuleGroup:
    """Group of related rules"""
    group_name: str
    description: str
    rules: List[Rule] = field(default_factory=list)
    enabled: bool = True
    
    def add_rule(self, rule: Rule):
        """Add a rule to this group"""
        self.rules.append(rule)
    
    def get_rule_by_id(self, rule_id: int) -> Optional[Rule]:
        """Get a specific rule by ID"""
        for rule in self.rules:
            if rule.rule_id == rule_id:
                return rule
        return None
