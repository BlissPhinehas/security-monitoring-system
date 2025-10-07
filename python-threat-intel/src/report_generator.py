"""
Report Generator Module
Generates security reports in multiple formats
"""

import json
from datetime import datetime
from pathlib import Path
from typing import Dict, List
from .config import Config


class ReportGenerator:
    """Generates threat intelligence reports"""
    
    def __init__(self):
        self.config = Config()
    
    def generate_report(self, data: Dict, report_type: str = "json") -> str:
        """
        Generate a report from analysis data
        
        Args:
            data: Analysis data to include in report
            report_type: Format (json, html, txt)
            
        Returns:
            Path to generated report file
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        if report_type == "json":
            return self._generate_json_report(data, timestamp)
        elif report_type == "html":
            return self._generate_html_report(data, timestamp)
        elif report_type == "txt":
            return self._generate_text_report(data, timestamp)
        else:
            raise ValueError(f"Unknown report type: {report_type}")
    
    def _generate_json_report(self, data: Dict, timestamp: str) -> str:
        """Generate JSON report"""
        report_file = self.config.REPORTS_DIR / f"threat_report_{timestamp}.json"
        
        report = {
            "report_metadata": {
                "generated_at": datetime.now().isoformat(),
                "report_type": "Threat Intelligence Analysis",
                "version": "1.0.0"
            },
            "analysis_data": data
        }
        
        with open(report_file, 'w', encoding='utf-8') as f:
            json.dump(report, f, indent=2, ensure_ascii=False)
        
        return str(report_file)
    
    def _generate_html_report(self, data: Dict, timestamp: str) -> str:
        """Generate HTML report"""
        report_file = self.config.REPORTS_DIR / f"threat_report_{timestamp}.html"
        
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Threat Intelligence Report - {timestamp}</title>
    <style>
        body {{
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
            background: #f5f5f5;
        }}
        .header {{
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            padding: 30px;
            border-radius: 10px;
            margin-bottom: 20px;
        }}
        .header h1 {{
            margin: 0;
            font-size: 2em;
        }}
        .card {{
            background: white;
            padding: 20px;
            margin: 20px 0;
            border-radius: 8px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }}
        .threat-level {{
            display: inline-block;
            padding: 5px 15px;
            border-radius: 20px;
            font-weight: bold;
            color: white;
        }}
        .critical {{ background: #dc3545; }}
        .high {{ background: #fd7e14; }}
        .medium {{ background: #ffc107; color: #000; }}
        .low {{ background: #28a745; }}
        .minimal {{ background: #17a2b8; }}
        .clean {{ background: #6c757d; }}
        table {{
            width: 100%;
            border-collapse: collapse;
            margin: 10px 0;
        }}
        th, td {{
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }}
        th {{
            background: #f8f9fa;
            font-weight: bold;
        }}
        .footer {{
            text-align: center;
            color: #6c757d;
            margin-top: 40px;
            padding: 20px;
        }}
        pre {{
            background: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            overflow-x: auto;
        }}
    </style>
</head>
<body>
    <div class="header">
        <h1>🔒 Threat Intelligence Report</h1>
        <p>Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
    </div>
    
    <div class="card">
        <h2>Analysis Results</h2>
        <pre>{json.dumps(data, indent=2)}</pre>
    </div>
    
    <div class="footer">
        <p>Security Monitoring System v1.0.0</p>
        <p>For authorized security analysis only</p>
    </div>
</body>
</html>
"""
        
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(html)
        
        return str(report_file)
    
    def _generate_text_report(self, data: Dict, timestamp: str) -> str:
        """Generate plain text report"""
        report_file = self.config.REPORTS_DIR / f"threat_report_{timestamp}.txt"
        
        lines = [
            "=" * 70,
            "THREAT INTELLIGENCE REPORT",
            "=" * 70,
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            "ANALYSIS DATA:",
            "-" * 70,
        ]
        
        lines.extend(self._format_dict_to_text(data))
        
        lines.extend([
            "",
            "=" * 70,
            "End of Report",
            "=" * 70
        ])
        
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write('\n'.join(lines))
        
        return str(report_file)
    
    def _format_dict_to_text(self, data: Dict, indent: int = 0) -> List[str]:
        """Recursively format dictionary to text lines"""
        lines = []
        prefix = "  " * indent
        
        for key, value in data.items():
            if isinstance(value, dict):
                lines.append(f"{prefix}{key}:")
                lines.extend(self._format_dict_to_text(value, indent + 1))
            elif isinstance(value, list):
                lines.append(f"{prefix}{key}:")
                for item in value:
                    if isinstance(item, dict):
                        lines.extend(self._format_dict_to_text(item, indent + 1))
                    else:
                        lines.append(f"{prefix}  - {item}")
            else:
                lines.append(f"{prefix}{key}: {value}")
        
        return lines