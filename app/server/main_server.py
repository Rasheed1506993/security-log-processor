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


class LogProcessingServer:
    """
    Enhanced main server for processing security agent logs.
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

        # Get app directory for resolving relative paths
        self.app_dir = Path(__file__).parent.parent

        # File paths (resolve relative to app directory)
        self.input_log_file = str(self.app_dir / self.config['paths']['input_logs'])
        self.output_context_file = str(self.app_dir / self.config['paths']['output_context'])
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
                    'unknown_logs': 'data/output/unknown_logs.txt'
                },
                'processing': {
                    'batch_size': 1000,
                    'log_level': 'INFO',
                    'save_unknown_logs': True
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
        """معالجة السجلات من الملف المدخل وتوليد السياق"""
        print(f"\\n📖 قراءة السجلات من: {self.input_log_file}")
        print("معالجة سجلات متعددة الأسطر...\\n")

        try:
            from utils.log_reader import MultiLineLogReader

            decoded_logs = []
            self.unknown_logs = []

            reader = MultiLineLogReader(self.input_log_file)
            total_entries = 0

            for line_num, complete_log in reader.read_logs():
                total_entries += 1

                if total_entries % 100 == 0:
                    print(f"  معالجة السجل رقم {total_entries}...", end='\\r')

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
                        print(f"\\n  [غير معروف] السجل الذي يبدأ في السطر {line_num}: لم يتم فك التشفير")

            print(f"\\n✓ تم فك تشفير: {len(decoded_logs)} سجل بنجاح")
            print(f"✗ سجلات بصيغة غير معروفة: {len(self.unknown_logs)} سجل")
            print(f"إجمالي السجلات المعالجة: {total_entries}")

            # حفظ السجلات المفككة في ملف منفصل قبل بناء السياق
            if decoded_logs:
                self._save_decoded_logs(decoded_logs)

            # حفظ السجلات غير المعروفة
            if self.config['processing'].get('save_unknown_logs', True):
                self._save_unknown_logs()

            # بناء السياق
            print(f"\\n🔨 بناء السياق...")
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

            print(f"✓ تم بناء السياق بنجاح")

            return context

        except FileNotFoundError:
            print(f"✗ خطأ: ملف الإدخال '{self.input_log_file}' غير موجود")
            return None
        except Exception as e:
            print(f"✗ خطأ في معالجة السجلات: {str(e)}")
            import traceback
            traceback.print_exc()
            return None

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

            print(f"\nSaving context to: {self.output_context_file}")

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
        """Run the complete log processing workflow."""
        print("=" * 80)
        print(" " * 20 + "Security Agent Log Processing Server")
        print("=" * 80)

        context = self.process_logs()

        if context:
            if self.save_context(context):
                self._print_summary(context)
                return context
        else:
            print("\n✗ Processing failed. Please check the error messages above.")

        return None

    def _save_decoded_logs(self, decoded_logs: List[Dict[str, Any]]):
        """حفظ السجلات المفككة في ملف منفصل قبل بناء السياق"""
        try:
            # إنشاء مسار ملف السجلات المفككة
            app_dir = Path(__file__).parent.parent
            decoded_output_file = str(app_dir / "data" / "output" / "decoded_logs.json")

            # التأكد من وجود المجلد
            Path(decoded_output_file).parent.mkdir(parents=True, exist_ok=True)

            print(f"\\n💾 حفظ السجلات المفككة في: {decoded_output_file}")

            # إعداد البيانات للحفظ
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
            print(f"✓ تم حفظ {len(decoded_logs)} سجل مفكك بنجاح")
            print(f"  حجم الملف: {file_size:,} بايت ({file_size / 1024:.2f} كيلوبايت)")

        except Exception as e:
            print(f"✗ خطأ في حفظ السجلات المفككة: {str(e)}")


    def _print_summary(self, context: Dict[str, Any]):
        """Print processing summary."""
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
        for event_type, count in sorted(summary['event_types'].items()):
            print(f"  {event_type:.<25} {count:>4}")

        print(f"\n⚠️  Severity Distribution:")
        sev_dist = summary['severity_distribution']
        print(f"  High   : {sev_dist.get('high', 0):>4} events")
        print(f"  Medium : {sev_dist.get('medium', 0):>4} events")
        print(f"  Low    : {sev_dist.get('low', 0):>4} events")

        print(f"\n🎯 Risk Assessment:")
        risk_level = risk['risk_level'].upper()
        risk_symbol = "🔴" if risk_level == "HIGH" else "🟡" if risk_level == "MEDIUM" else "🟢"
        print(f"  Risk Level              : {risk_symbol} {risk_level}")
        print(f"  Risk Score              : {risk['risk_score']:.2f}%")
        print(f"  High Severity Events    : {risk['high_severity_events']}")

        if risk['indicators']:
            print(f"\n🚨 Risk Indicators:")
            for indicator in risk['indicators'][:5]:
                print(f"  • {indicator}")

        print(f"\n🔧 Decoder Performance:")


        stats = metadata['decoder_statistics']
        print(f"  Basic Decoder           : {stats['basic_decoder']['successful_decodes']} decoded")
        print(f"  Windows Decoder         : {stats['windows_decoder']['windows_events_decoded']} decoded")
        print(f"    ├─ Defender           : {stats['windows_decoder']['defender_events']}")
        print(f"    ├─ Security           : {stats['windows_decoder']['security_events']}")
        print(f"    ├─ Sysmon             : {stats['windows_decoder']['sysmon_events']}")
        print(f"    ├─ PowerShell         : {stats['windows_decoder']['powershell_events']}")
        print(f"    ├─ Firewall           : {stats['windows_decoder']['firewall_events']}")
        print(f"    └─ AppLocker          : {stats['windows_decoder']['applocker_events']}")
        generic_total = sum(stats['generic_decoder'].values()) - stats['generic_decoder']['failed']
        print(f"  Generic Decoder         : {generic_total} decoded")
        print(f"    ├─ JSON               : {stats['generic_decoder']['json_decoded']}")
        print(f"    ├─ Key-Value          : {stats['generic_decoder']['kv_decoded']}")
        print(f"    └─ XML                : {stats['generic_decoder']['xml_decoded']}")

        if summary['time_range']['start']:
            print(f"\n📅 Time Range:")
            print(f"  Start: {summary['time_range']['start']}")
            print(f"  End  : {summary['time_range']['end']}")

        print(f"\n✅ Output Files:")
        print(f"  Context     : {self.output_context_file}")
        if metadata['unknown_logs_count'] > 0:
            print(f"  Unknown Logs: {self.unknown_logs_file}")

        print("\n" + "=" * 80)
        print("✓ Log processing completed successfully!")
        print("  Context file is ready for rule comparison and analysis")
        print("=" * 80 + "\n")

if __name__ == "__main__":
    server = LogProcessingServer()
    server.run()