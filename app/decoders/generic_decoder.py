import json
import re
import xml.etree.ElementTree as ET
from typing import Dict, Any, Optional


class GenericDecoder:
    """
    Generic decoder for unknown log formats.
    Attempts to parse JSON, key-value pairs, and XML structures.
    Extracts as many fields as possible from unrecognized formats.
    """

    def __init__(self):
        self.stats = {
            'json_decoded': 0,
            'kv_decoded': 0,
            'xml_decoded': 0,
            'failed': 0
        }

    def decode_generic(self, log_line: str) -> Optional[Dict[str, Any]]:
        """
        Attempt to decode unknown log format.
        Tries JSON, then key-value, then XML parsing.
        """
        result = None

        # Try JSON format first
        result = self._try_json(log_line)
        if result:
            self.stats['json_decoded'] += 1
            return result

        # Try key-value format
        result = self._try_key_value(log_line)
        if result:
            self.stats['kv_decoded'] += 1
            return result

        # Try XML format
        result = self._try_xml(log_line)
        if result:
            self.stats['xml_decoded'] += 1
            return result

        self.stats['failed'] += 1
        return None

    def _try_json(self, log_line: str) -> Optional[Dict[str, Any]]:
        """Attempt to parse as JSON."""
        try:
            data = json.loads(log_line.strip())

            if not isinstance(data, dict):
                return None

            decoded = {
                'log_type': 'generic_json',
                'raw_data': data,
                'extracted_fields': self._extract_common_fields(data),
                'severity': self._assess_generic_severity(data),
                'field_count': len(data)
            }

            # Try to extract timestamp
            timestamp = self._find_timestamp(data)
            if timestamp:
                decoded['timestamp'] = timestamp

            return decoded

        except json.JSONDecodeError:
            return None

    def _try_key_value(self, log_line: str) -> Optional[Dict[str, Any]]:
        """Attempt to parse as key-value pairs."""
        try:
            # Look for key-value patterns: key=value, key:value, key="value"
            kv_patterns = [
                r'(\w+)="([^"]*)"',  # key="value"
                r'(\w+)=\'([^\']*)\'',  # key='value'
                r'(\w+)=([^,;\s]+)',  # key=value
                r'(\w+):\s*([^,;\n]+)',  # key: value
            ]

            fields = {}
            for pattern in kv_patterns:
                matches = re.findall(pattern, log_line)
                for key, value in matches:
                    if key and value:
                        fields[key] = value.strip()

            if len(fields) < 2:  # Need at least 2 fields to be valid
                return None

            decoded = {
                'log_type': 'generic_key_value',
                'raw_data': fields,
                'extracted_fields': self._extract_common_fields(fields),
                'severity': self._assess_generic_severity(fields),
                'field_count': len(fields)
            }

            # Try to extract timestamp
            timestamp = self._find_timestamp(fields)
            if timestamp:
                decoded['timestamp'] = timestamp

            return decoded

        except Exception:
            return None

    def _try_xml(self, log_line: str) -> Optional[Dict[str, Any]]:
        """Attempt to parse as XML."""
        try:
            root = ET.fromstring(log_line.strip())

            # Extract all elements into a dictionary
            xml_data = self._xml_to_dict(root)

            decoded = {
                'log_type': 'generic_xml',
                'raw_data': xml_data,
                'extracted_fields': self._extract_common_fields(xml_data),
                'severity': self._assess_generic_severity(xml_data),
                'field_count': len(xml_data)
            }

            # Try to extract timestamp

            timestamp = self._find_timestamp(xml_data)
            if timestamp:
                decoded['timestamp'] = timestamp

            return decoded

        except ET.ParseError:
            return None

    def _xml_to_dict(self, element) -> Dict[str, Any]:
        """Convert XML element to dictionary recursively."""
        result = {}

        # Add attributes
        if element.attrib:
            result.update(element.attrib)

        # Add text content
        if element.text and element.text.strip():
            result['_text'] = element.text.strip()

        # Add child elements
        for child in element:
            child_data = self._xml_to_dict(child)
            tag = child.tag.split('}')[-1]  # Remove namespace

            if tag in result:
                # If key exists, convert to list
                if not isinstance(result[tag], list):
                    result[tag] = [result[tag]]
                result[tag].append(child_data)
            else:
                result[tag] = child_data

        return result

    def _extract_common_fields(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Extract commonly used fields from generic data."""
        common_fields = {}

        # Common field name variations
        field_mappings = {
            'timestamp': ['timestamp', 'time', 'datetime', 'date', 'eventtime', 'logtime', '@timestamp'],
            'user': ['user', 'username', 'account', 'userid', 'accountname', 'subject'],
            'source_ip': ['sourceip', 'source_ip', 'src_ip', 'srcip', 'clientip', 'remote_addr'],
            'destination_ip': ['destip', 'destination_ip', 'dest_ip', 'dstip', 'targetip'],
            'host': ['host', 'hostname', 'computer', 'computername', 'machine'],
            'process': ['process', 'processname', 'image', 'application', 'program'],
            'action': ['action', 'event', 'eventtype', 'activity', 'operation'],
            'status': ['status', 'result', 'outcome', 'state'],
            'message': ['message', 'msg', 'description', 'details', 'text'],
            'severity': ['severity', 'level', 'priority', 'importance'],
            'event_id': ['eventid', 'event_id', 'id', 'code', 'event_code']
        }

        # Flatten nested dictionaries for searching
        flat_data = self._flatten_dict(data)

        for common_field, variations in field_mappings.items():
            for variation in variations:
                # Case-insensitive search
                for key, value in flat_data.items():
                    if key.lower() == variation.lower():
                        common_fields[common_field] = value
                        break
                if common_field in common_fields:
                    break

        return common_fields

    def _flatten_dict(self, d: Dict[str, Any], parent_key: str = '', sep: str = '.') -> Dict[str, Any]:
        """Flatten nested dictionary."""
        items = []
        for k, v in d.items():
            new_key = f"{parent_key}{sep}{k}" if parent_key else k
            if isinstance(v, dict):
                items.extend(self._flatten_dict(v, new_key, sep=sep).items())
            else:
                items.append((new_key, v))
        return dict(items)

    def _find_timestamp(self, data: Dict[str, Any]) -> Optional[str]:
        """Try to find timestamp in various formats."""
        timestamp_keys = ['timestamp', 'time', 'datetime', 'date', 'eventtime', '@timestamp']

        flat_data = self._flatten_dict(data) if isinstance(data, dict) else {}

        for key, value in flat_data.items():
            if any(ts_key in key.lower() for ts_key in timestamp_keys):
                return str(value)

        return None

    def _assess_generic_severity(self, data: Dict[str, Any]) -> str:
        """Assess severity from generic log data."""
        # Look for explicit severity indicators
        severity_keys = ['severity', 'level', 'priority', 'importance']

        flat_data = self._flatten_dict(data) if isinstance(data, dict) else {}

        for key, value in flat_data.items():
            if any(sev_key in key.lower() for sev_key in severity_keys):
                value_lower = str(value).lower()
                if any(word in value_lower for word in ['critical', 'high', 'error', 'alert', 'fatal']):
                    return 'high'
                elif any(word in value_lower for word in ['warning', 'warn', 'medium', 'moderate']):
                    return 'medium'
                elif any(word in value_lower for word in ['info', 'low', 'debug', 'trace']):
                    return 'low'

        # Look for threat/security indicators
        threat_indicators = ['threat', 'malware', 'virus', 'attack', 'breach', 'exploit', 'failed', 'denied', 'blocked']
        for key, value in flat_data.items():
            value_str = str(value).lower()
            if any(indicator in value_str for indicator in threat_indicators):
                return 'high'

        return 'medium'  # Default for unknown generic logs

    def get_statistics(self) -> Dict[str, int]:
        return self.stats.copy()

    def _try_json(self, log_line: str) -> Optional[Dict[str, Any]]:
        """Attempt to parse as JSON (handles multi-line JSON)."""
        try:
            # Remove any leading/trailing whitespace and newlines
            cleaned_line = log_line.strip()

            # Try to parse the JSON
            data = json.loads(cleaned_line)

            if not isinstance(data, dict):
                # If it's a list, try to extract the first dict
                if isinstance(data, list) and len(data) > 0 and isinstance(data[0], dict):
                    data = data[0]
                else:
                    return None

            decoded = {
                'log_type': 'generic_json',
                'raw_data': data,
                'extracted_fields': self._extract_common_fields(data),
                'severity': self._assess_generic_severity(data),
                'field_count': len(data)
            }

            # Try to extract timestamp
            timestamp = self._find_timestamp(data)
            if timestamp:
                decoded['timestamp'] = timestamp

            return decoded

        except json.JSONDecodeError as e:
            # If JSON parsing fails, return None
            return None
        except Exception as e:
            return None