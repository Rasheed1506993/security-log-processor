import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Dict, Any, Optional, List

# Since app is the sources root, use relative imports
from decoders.log_decoder import LogDecoder
from decoders.windows_decoder import WindowsDecoder
from decoders.generic_decoder import GenericDecoder
from context.context_builder import ContextBuilder
from rules.rules_engine import RulesEngine


class EnhancedLogProcessingServer:
    """
    Enhanced main server for processing security agent logs with rules engine integration.
    """

    def __init__(self, config_path: str = None):
        # If no config path provided, look in app/config/settings.json
        if config_path is None:
            # Get the app directory (parent of server directory)
            app_dir = Path(__file__).parent.parent
            config_path = str(app_dir / "config" / "settings.json")

        self.config = self._load_config(config_path)

        # Initialize all decoders
        self.basic_decoder = LogDecoder()
        self.windows_decoder = WindowsDecoder()
        self.generic_decoder = GenericDecoder()
        self.context_builder = ContextBuilder()
        
        # Initialize rules engine
        self.rules_engine = RulesEngine()
        self.rules_engine.load_rules()

        # Get app directory for resolving relative paths
        self.app_dir = Path(__file__).parent.parent

        # File paths (resolve relative to app directory)
        self.input_log_file = str(self.app_dir / self.config['paths']['input_logs'])
        self.output_context_file = str(self.app_dir / self.config['paths']['output_context'])
        self.output_alerts_file = str(self.app_dir / self.config['paths'].get('output_alerts', 'data/output/alerts.json'))
        self.unknown_logs_file = str(self.app_dir / self.config['paths']['unknown_logs'])

        # Unknown logs storage
        self.unknown_logs = []

    def _load_config(self, config_path: str) -> Dict[str, Any]:
        """Load configuration from JSON file."""
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                return json.load(f)
        except FileNotFoundError:
            print(f"Warning: Config file not found at {config_path}. Using defaults.")
            return {
                'paths': {
                    'input_logs': 'data/input/agent_logs.txt',
                    'output_context': 'data/output/processed_context.json',
                    'output_alerts': 'data/output/alerts.json',
                    'unknown_logs': 'data/output/unknown_logs.txt'
                },
                'processing': {
                    'batch_size': 1000,
                    'log_level': 'INFO',
                    'save_unknown_logs': True,
                    'enable_rules_engine': True
                }
            }

    def decode_single_log(self, log_line: str) -> Optional[Dict[str, Any]]:
        """
        Attempt to decode a single log line using all available decoders.
        Priority: Basic -> Windows -> Generic
        """
        # Try basic security event formats first
        result = self.basic_decoder.decode_log(log_line)
        if result:
            result['decoder_used'] = 'basic'
            return result

        # Try Windows-specific formats
        result = self.windows_decoder.decode_windows_event(log_line)
        if result:
            result['decoder_used'] = 'windows'
            return result

        # Try generic formats (JSON, KV, XML)
        result = self.generic_decoder.decode_generic(log_line)
        if result:
            result['decoder_used'] = 'generic'
            return result

        # Could not decode - will be saved as unknown
        return None

    def process_logs(self) -> Optional[Dict[str, Any]]:
        """Process logs from input file and generate context"""
        print(f"\n📖 Reading logs from: {self.input_log_file}")
        print("Processing multi-line logs...\n")

        try:
            from utils.log_reader import MultiLineLogReader

            decoded_logs = []
            self.unknown_logs = []

            reader = MultiLineLogReader(self.input_log_file)
            total_entries = 0

            for line_num, complete_log in reader.read_logs():
                total_entries += 1

                if total_entries % 100 == 0:
                    print(f"  Processing log #{total_entries}...", end='\r')

                decoded = self.decode_single_log(complete_log)

                if decoded:
                    decoded['line_number'] = line_num
                    decoded['raw_log'] = complete_log[:500] if len(complete_log) > 500 else complete_log
                    decoded_logs.append(decoded)
                else:
                    self.unknown_logs.append({
                        'line_number': line_num,
                        'raw_log': complete_log
                    })

                    if self.config['processing']['log_level'] == 'DEBUG':
                        print(f"\n  [Unknown] Log starting at line {line_num}: Could not decode")

            print(f"\n✓ Successfully decoded: {len(decoded_logs)} logs")
            print(f"✗ Unknown format logs: {len(self.unknown_logs)} logs")
            print(f"Total logs processed: {total_entries}")

            # Save decoded logs to separate file before building context
            if decoded_logs:
                self._save_decoded_logs(decoded_logs)

            # Save unknown logs
            if self.config['processing'].get('save_unknown_logs', True):
                self._save_unknown_logs()

            # Build context
            print(f"\n🔨 Building context...")
            context = self.context_builder.build_context(decoded_logs)
            context['decoded_logs'] = decoded_logs

            context['metadata'] = {
                'processed_at': datetime.now().isoformat(),
                'source_file': self.input_log_file,
                'total_entries_processed': total_entries,
                'successfully_decoded': len(decoded_logs),
                'unknown_logs_count': len(self.unknown_logs),
                'decoder_statistics': {
                    'basic_decoder': self.basic_decoder.get_statistics(),
                    'windows_decoder': self.windows_decoder.get_statistics(),
                    'generic_decoder': self.generic_decoder.get_statistics()
                },
                'configuration': self.config
            }

            print(f"✓ Context built successfully")

            return context

        except FileNotFoundError:
            print(f"✗ Error: Input file '{self.input_log_file}' not found")
            return None
        except Exception as e:
            print(f"✗ Error processing logs: {str(e)}")
            import traceback
            traceback.print_exc()
            return None

    def analyze_with_rules(self, context: Dict[str, Any]) -> Dict[str, Any]:
        """
        Analyze context with rules engine and generate alerts.
        
        Args:
            context: Processing context with decoded logs
            
        Returns:
            Alert report
        """
        if not self.config['processing'].get('enable_rules_engine', True):
            print("\n⚠️  Rules engine is disabled in configuration")
            return None
        
        print("\n" + "=" * 80)
        print(" " * 25 + "RULES ENGINE ANALYSIS")
        print("=" * 80)
        
        # Evaluate context against rules
        alert_report = self.rules_engine.evaluate_context(context)
        
        # Save alerts
        self._save_alerts(alert_report)
        
        return alert_report

    def _save_alerts(self, alert_report: Dict[str, Any]):
        """Save alert report to file"""
        try:
            output_path = Path(self.output_alerts_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)

            print(f"\n💾 Saving alerts to: {self.output_alerts_file}")

            with open(self.output_alerts_file, 'w', encoding='utf-8') as f:
                json.dump(alert_report, f, indent=2, ensure_ascii=False)

            file_size = output_path.stat().st_size
            print(f"✓ Alerts saved successfully")
            print(f"  File size: {file_size:,} bytes ({file_size / 1024:.2f} KB)")

        except Exception as e:
            print(f"✗ Error saving alerts: {str(e)}")

    def _save_unknown_logs(self):
        """Save unknown logs to separate file for manual review."""
        if not self.unknown_logs:
            return

        try:
            output_path = Path(self.unknown_logs_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)

            with open(self.unknown_logs_file, 'w', encoding='utf-8') as f:
                f.write(f"# Unknown Log Entries\n")
                f.write(f"# Generated: {datetime.now().isoformat()}\n")
                f.write(f"# Total unknown entries: {len(self.unknown_logs)}\n")
                f.write(f"# These logs could not be decoded by any parser\n")
                f.write(f"# Please review and update decoders if needed\n\n")

                for entry in self.unknown_logs:
                    f.write(f"[Line {entry['line_number']}]\n")
                    f.write(f"{entry['raw_log']}\n\n")

            print(f"✓ Unknown logs saved to: {self.unknown_logs_file}")

        except Exception as e:
            print(f"✗ Warning: Could not save unknown logs: {str(e)}")

    def save_context(self, context: Dict[str, Any]) -> bool:
        """Save context to output file."""
        try:
            output_path = Path(self.output_context_file)
            output_path.parent.mkdir(parents=True, exist_ok=True)

            print(f"\n💾 Saving context to: {self.output_context_file}")

            with open(self.output_context_file, 'w', encoding='utf-8') as f:
                json.dump(context, f, indent=2, ensure_ascii=False)

            file_size = output_path.stat().st_size
            print(f"✓ Context saved successfully")
            print(f"  File size: {file_size:,} bytes ({file_size / 1024:.2f} KB)")
            return True

        except Exception as e:
            print(f"✗ Error saving context: {str(e)}")
            return False

    def run(self) -> Optional[Dict[str, Any]]:
        """Run the complete log processing workflow with rules analysis."""
        print("=" * 80)
        print(" " * 20 + "Security Agent Log Processing Server")
        print(" " * 28 + "with Rules Engine")
        print("=" * 80)

        # Step 1: Process logs and build context
        context = self.process_logs()

        if not context:
            print("\n✗ Processing failed. Please check the error messages above.")
            return None

        # Step 2: Save context
        if not self.save_context(context):
            return None

        # Step 3: Analyze with rules engine
        alert_report = self.analyze_with_rules(context)

        # Step 4: Print summary
        self._print_summary(context, alert_report)

        return {
            'context': context,
            'alerts': alert_report
        }

    def _save_decoded_logs(self, decoded_logs: List[Dict[str, Any]]):
        """Save decoded logs to separate file before building context"""
        try:
            # Create decoded logs file path
            app_dir = Path(__file__).parent.parent
            decoded_output_file = str(app_dir / "data" / "output" / "decoded_logs.json")

            # Ensure directory exists
            Path(decoded_output_file).parent.mkdir(parents=True, exist_ok=True)

            print(f"\n💾 Saving decoded logs to: {decoded_output_file}")

            # Prepare data for saving
            decoded_output = {
                "decoding_completed_at": datetime.now().isoformat(),
                "source_file": self.input_log_file,
                "total_decoded_logs": len(decoded_logs),
                "decoder_statistics": {
                    "basic_decoder": self.basic_decoder.get_statistics(),
                    "windows_decoder": self.windows_decoder.get_statistics(),
                    "generic_decoder": self.generic_decoder.get_statistics()
                },
                "decoded_logs": decoded_logs
            }

            with open(decoded_output_file, 'w', encoding='utf-8') as f:
                json.dump(decoded_output, f, indent=2, ensure_ascii=False)

            file_size = Path(decoded_output_file).stat().st_size
            print(f"✓ Successfully saved {len(decoded_logs)} decoded logs")
            print(f"  File size: {file_size:,} bytes ({file_size / 1024:.2f} KB)")

        except Exception as e:
            print(f"✗ Error saving decoded logs: {str(e)}")

    def _print_summary(self, context: Dict[str, Any], alert_report: Optional[Dict[str, Any]] = None):
        """Print comprehensive processing summary including alerts."""
        print("\n" + "=" * 80)
        print(" " * 30 + "PROCESSING SUMMARY")
        print("=" * 80)

        summary = context['summary']
        risk = context['risk_assessment']
        metadata = context['metadata']

        print(f"\n📊 Event Statistics:")
        print(f"  Total Events Decoded    : {summary['total_events']}")
        print(f"  Unknown Logs            : {metadata['unknown_logs_count']}")
        print(f"  Unique Users            : {summary['unique_users']}")

        print(f"\n📋 Event Types:")
        for event_type, count in sorted(summary['event_types'].items())[:10]:
            print(f"  {event_type:.<25} {count:>4}")

        print(f"\n⚠️  Severity Distribution:")
        sev_dist = summary['severity_distribution']
        print(f"  High   : {sev_dist.get('high', 0):>4} events")
        print(f"  Medium : {sev_dist.get('medium', 0):>4} events")
        print(f"  Low    : {sev_dist.get('low', 0):>4} events")

        # Print alerts summary if available
        if alert_report:
            print("\n" + "=" * 80)
            print(" " * 32 + "ALERTS SUMMARY")
            print("=" * 80)
            
            analysis = alert_report['analysis_metadata']
            stats = alert_report['statistics']
            risk_summary = alert_report['risk_summary']
            
            print(f"\n🚨 Alert Statistics:")
            print(f"  Total Alerts Generated  : {analysis['total_alerts']}")
            print(f"  Rules Triggered         : {analysis['rules_triggered']}/{analysis['rules_evaluated']}")
            
            print(f"\n⚠️  Alert Severity Distribution:")
            severity_dist = stats['severity_distribution']
            print(f"  CRITICAL : {severity_dist.get('CRITICAL', 0):>4} alerts")
            print(f"  HIGH     : {severity_dist.get('HIGH', 0):>4} alerts")
            print(f"  MEDIUM   : {severity_dist.get('MEDIUM', 0):>4} alerts")
            print(f"  LOW      : {severity_dist.get('LOW', 0):>4} alerts")
            
            print(f"\n🎯 Risk Assessment (Rules-Based):")
            risk_level = risk_summary['risk_level']
            risk_symbol = "🔴" if risk_level == "CRITICAL" else "🟡" if risk_level == "HIGH" else "🟢"
            print(f"  Risk Level              : {risk_symbol} {risk_level}")
            print(f"  Risk Score              : {risk_summary['risk_score']}")
            print(f"  Critical Alerts         : {risk_summary['critical_alerts']}")
            print(f"  High Priority Alerts    : {risk_summary['total_high_priority']}")
            
            # Top triggered rules
            if stats['top_triggered_rules']:
                print(f"\n📌 Top Triggered Rules:")
                for idx, rule_info in enumerate(stats['top_triggered_rules'][:5], 1):
                    print(f"  {idx}. Rule {rule_info['rule_id']}: {rule_info['rule_name']}")
                    print(f"     Triggered {rule_info['count']} times")
            
            # MITRE coverage
            if stats['mitre_coverage']:
                print(f"\n🔍 MITRE ATT&CK Coverage:")
                print(f"  Techniques Detected: {', '.join(stats['mitre_coverage'][:5])}")

        print(f"\n🔧 Decoder Performance:")
        stats_decoder = metadata['decoder_statistics']
        print(f"  Basic Decoder           : {stats_decoder['basic_decoder']['successful_decodes']} decoded")
        print(f"  Windows Decoder         : {stats_decoder['windows_decoder']['windows_events_decoded']} decoded")
        print(f"    ├─ Defender           : {stats_decoder['windows_decoder']['defender_events']}")
        print(f"    ├─ Security           : {stats_decoder['windows_decoder']['security_events']}")
        print(f"    ├─ Sysmon             : {stats_decoder['windows_decoder']['sysmon_events']}")
        print(f"    ├─ PowerShell         : {stats_decoder['windows_decoder']['powershell_events']}")
        print(f"    ├─ Firewall           : {stats_decoder['windows_decoder']['firewall_events']}")
        print(f"    └─ AppLocker          : {stats_decoder['windows_decoder']['applocker_events']}")
        generic_total = sum(stats_decoder['generic_decoder'].values()) - stats_decoder['generic_decoder']['failed']
        print(f"  Generic Decoder         : {generic_total} decoded")
        print(f"    ├─ JSON               : {stats_decoder['generic_decoder']['json_decoded']}")
        print(f"    ├─ Key-Value          : {stats_decoder['generic_decoder']['kv_decoded']}")
        print(f"    └─ XML                : {stats_decoder['generic_decoder']['xml_decoded']}")

        if summary['time_range']['start']:
            print(f"\n📅 Time Range:")
            print(f"  Start: {summary['time_range']['start']}")
            print(f"  End  : {summary['time_range']['end']}")

        print(f"\n✅ Output Files:")
        print(f"  Context     : {self.output_context_file}")
        if alert_report:
            print(f"  Alerts      : {self.output_alerts_file}")
        if metadata['unknown_logs_count'] > 0:
            print(f"  Unknown Logs: {self.unknown_logs_file}")

        print("\n" + "=" * 80)
        print("✓ Log processing and analysis completed successfully!")
        print("  All files are ready for API serving and frontend display")
        print("=" * 80 + "\n")


if __name__ == "__main__":
    server = EnhancedLogProcessingServer()
    result = server.run()
