import json
from typing import List, Iterator, Optional
from pathlib import Path


class MultiLineLogReader:
    """
    Advanced log reader that handles multi-line log entries.
    Supports JSON objects spanning multiple lines, XML blocks, and single-line formats.
    """

    def __init__(self, file_path: str):
        self.file_path = file_path
        self.current_buffer = []
        self.in_json_object = False
        self.in_xml_object = False
        self.brace_count = 0
        self.bracket_count = 0

    def read_logs(self) -> Iterator[tuple[int, str]]:
        """
        Read logs from file, yielding complete log entries.
        Returns: Iterator of (line_number, complete_log_entry) tuples
        """
        with open(self.file_path, 'r', encoding='utf-8') as f:
            start_line = 1

            for line_num, line in enumerate(f, 1):
                stripped_line = line.strip()

                # Skip empty lines and comments when not inside an object
                if not self.current_buffer and (not stripped_line or stripped_line.startswith('#')):
                    continue

                # Detect start of JSON object
                if self._is_json_start(stripped_line):
                    if self.current_buffer:
                        # Yield previous complete entry
                        complete_entry = '\n'.join(self.current_buffer)
                        yield (start_line, complete_entry)
                        self.current_buffer = []

                    start_line = line_num
                    self.in_json_object = True
                    self.brace_count = stripped_line.count('{') - stripped_line.count('}')
                    self.bracket_count = stripped_line.count('[') - stripped_line.count(']')
                    self.current_buffer.append(line.rstrip())

                    # Check if JSON completes on same line
                    if self.brace_count == 0 and self.bracket_count == 0:
                        complete_entry = '\n'.join(self.current_buffer)
                        yield (start_line, complete_entry)
                        self.current_buffer = []
                        self.in_json_object = False

                    continue

                # Detect start of XML object
                if self._is_xml_start(stripped_line):
                    if self.current_buffer:
                        complete_entry = '\n'.join(self.current_buffer)
                        yield (start_line, complete_entry)
                        self.current_buffer = []

                    start_line = line_num
                    self.in_xml_object = True
                    self.current_buffer.append(line.rstrip())

                    # Check if XML completes on same line
                    if self._is_xml_complete('\n'.join(self.current_buffer)):
                        complete_entry = '\n'.join(self.current_buffer)
                        yield (start_line, complete_entry)
                        self.current_buffer = []
                        self.in_xml_object = False

                    continue

                # Continue building current object
                if self.in_json_object:
                    self.current_buffer.append(line.rstrip())
                    self.brace_count += stripped_line.count('{') - stripped_line.count('}')
                    self.bracket_count += stripped_line.count('[') - stripped_line.count(']')

                    # Check if JSON object is complete
                    if self.brace_count == 0 and self.bracket_count == 0:
                        complete_entry = '\n'.join(self.current_buffer)
                        yield (start_line, complete_entry)
                        self.current_buffer = []
                        self.in_json_object = False

                elif self.in_xml_object:
                    self.current_buffer.append(line.rstrip())

                    # Check if XML is complete
                    if self._is_xml_complete('\n'.join(self.current_buffer)):
                        complete_entry = '\n'.join(self.current_buffer)
                        yield (start_line, complete_entry)
                        self.current_buffer = []
                        self.in_xml_object = False

                else:
                    # Single-line log entry (standard formats)
                    if stripped_line:
                        yield (line_num, stripped_line)

            # Yield any remaining buffered content
            if self.current_buffer:
                complete_entry = '\n'.join(self.current_buffer)
                yield (start_line, complete_entry)

    def _is_json_start(self, line: str) -> bool:
        """Check if line starts a JSON object or array."""
        return line.startswith('{') or line.startswith('[')

    def _is_xml_start(self, line: str) -> bool:
        """Check if line starts an XML element."""
        return line.startswith('<') and not line.startswith('<!--')

    def _is_xml_complete(self, content: str) -> bool:
        """Check if XML content is complete by matching opening and closing tags."""
        try:
            # Simple check: count < and > characters
            open_tags = content.count('<')
            close_tags = content.count('>')

            # If they match and content ends with >, likely complete
            if open_tags == close_tags and content.strip().endswith('>'):
                # Additional check: look for self-closing or proper closing tag
                lines = content.strip().split('\n')
                if len(lines) == 1:
                    # Single line XML
                    return lines[0].endswith('/>') or '</' in lines[0]
                else:
                    # Multi-line XML
                    return '</' in content or content.strip().endswith('/>')

            return False
        except:
            return False


class LogEntryDetector:
    """
    Detects boundaries between different log entries in various formats.
    """

    @staticmethod
    def is_new_entry(line: str, previous_line: Optional[str] = None) -> bool:
        """
        Determine if a line starts a new log entry.
        """
        stripped = line.strip()

        if not stripped or stripped.startswith('#'):
            return False

        # JSON object start
        if stripped.startswith('{') or stripped.startswith('['):
            return True

        # XML start
        if stripped.startswith('<') and not stripped.startswith('<!--'):
            return True

        # Standard log formats with timestamp or prefix
        prefixes = ['FIM ', 'PROC ', 'NET ', 'AUTH ', 'REG ', 'SVC ', 'Event ID:', 'EventID:']
        if any(stripped.startswith(prefix) for prefix in prefixes):
            return True

        # If line starts with timestamp pattern
        if LogEntryDetector._has_timestamp_start(stripped):
            return True

        return False

    @staticmethod
    def _has_timestamp_start(line: str) -> bool:
        """Check if line starts with a timestamp pattern."""
        import re
        timestamp_patterns = [
            r'^\d{4}-\d{2}-\d{2}',  # YYYY-MM-DD
            r'^\d{2}/\d{2}/\d{4}',  # MM/DD/YYYY
            r'^\[\d{4}-\d{2}-\d{2}',  # [YYYY-MM-DD
        ]
        return any(re.match(pattern, line) for pattern in timestamp_patterns)