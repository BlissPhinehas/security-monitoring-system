"""
IP Address Analysis Module
Checks IP addresses against threat intelligence databases
"""

import requests
import json
import ipaddress
from datetime import datetime
from typing import Dict, List, Optional
from .config import Config

class IPAnalyzer:
    """Analyzes IP addresses for malicious activity"""
    
    def __init__(self):
        self.config = Config()
        self.cache = {}
    
    def is_valid_ip(self, ip: str) -> bool:
        """
        Check if string is a valid IP address
        
        Args:
            ip: IP address string to validate
            
        Returns:
            True if valid IP, False otherwise
        """
        try:
            ipaddress.ip_address(ip)
            return True
        except ValueError:
            return False
    
    def check_abuseipdb(self, ip: str) -> Dict:
        """
        Check IP reputation using AbuseIPDB
        
        AbuseIPDB is a database of reported malicious IPs.
        Abuse confidence score: 0-100 (higher = more malicious)
        
        Args:
            ip: IP address to check
            
        Returns:
            Dictionary with reputation data
        """
        if not self.config.ABUSEIPDB_API_KEY:
            return {
                "error": "AbuseIPDB API key not configured",
                "ip": ip,
                "available": False
            }
        
        try:
            headers = {
                "Key": self.config.ABUSEIPDB_API_KEY,
                "Accept": "application/json"
            }
            
            params = {
                "ipAddress": ip,
                "maxAgeInDays": 90,
                "verbose": ""
            }
            
            response = requests.get(
                self.config.ABUSEIPDB_URL,
                headers=headers,
                params=params,
                timeout=10
            )
            
            if response.status_code == 200:
                data = response.json()
                result = data.get("data", {})
                
                return {
                    "source": "AbuseIPDB",
                    "ip": ip,
                    "abuse_confidence_score": result.get("abuseConfidenceScore", 0),
                    "country": result.get("countryCode", "Unknown"),
                    "usage_type": result.get("usageType", "Unknown"),
                    "isp": result.get("isp", "Unknown"),
                    "domain": result.get("domain", "Unknown"),
                    "total_reports": result.get("totalReports", 0),
                    "is_whitelisted": result.get("isWhitelisted", False),
                    "is_malicious": result.get("abuseConfidenceScore", 0) >= self.config.IP_REPUTATION_THRESHOLD,
                    "timestamp": datetime.now().isoformat()
                }
            else:
                return {
                    "error": f"API returned status {response.status_code}",
                    "ip": ip,
                    "available": False
                }
                
        except requests.RequestException as e:
            return {
                "error": f"Request failed: {str(e)}",
                "ip": ip,
                "available": False
            }
    
    def check_virustotal(self, ip: str) -> Dict:
        """
        Check IP reputation using VirusTotal
        
        VirusTotal aggregates data from 70+ antivirus engines
        
        Args:
            ip: IP address to check
            
        Returns:
            Dictionary with reputation data
        """
        if not self.config.VIRUSTOTAL_API_KEY:
            return {
                "error": "VirusTotal API key not configured",
                "ip": ip,
                "available": False
            }
        
        try:
            headers = {
                "x-apikey": self.config.VIRUSTOTAL_API_KEY
            }
            
            url = f"{self.config.VIRUSTOTAL_IP_URL}/{ip}"
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                attributes = data.get("data", {}).get("attributes", {})
                stats = attributes.get("last_analysis_stats", {})
                
                total_scanners = sum(stats.values())
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                
                return {
                    "source": "VirusTotal",
                    "ip": ip,
                    "malicious_votes": malicious,
                    "suspicious_votes": suspicious,
                    "harmless_votes": stats.get("harmless", 0),
                    "undetected_votes": stats.get("undetected", 0),
                    "total_scanners": total_scanners,
                    "malicious_percentage": (malicious / total_scanners * 100) if total_scanners > 0 else 0,
                    "is_malicious": malicious > 0,
                    "country": attributes.get("country", "Unknown"),
                    "as_owner": attributes.get("as_owner", "Unknown"),
                    "timestamp": datetime.now().isoformat()
                }
            else:
                return {
                    "error": f"API returned status {response.status_code}",
                    "ip": ip,
                    "available": False
                }
                
        except requests.RequestException as e:
            return {
                "error": f"Request failed: {str(e)}",
                "ip": ip,
                "available": False
            }
    
    def analyze_ip(self, ip: str) -> Dict:
        """
        Comprehensive IP analysis using multiple sources
        
        Args:
            ip: IP address to analyze
            
        Returns:
            Combined analysis from all sources
        """
        if not self.is_valid_ip(ip):
            return {
                "error": "Invalid IP address format",
                "ip": ip,
                "is_valid": False
            }
        
        # Check multiple sources
        abuseipdb_result = self.check_abuseipdb(ip)
        virustotal_result = self.check_virustotal(ip)
        
        # Combine results
        combined = {
            "ip": ip,
            "analysis_timestamp": datetime.now().isoformat(),
            "sources": {
                "abuseipdb": abuseipdb_result,
                "virustotal": virustotal_result
            },
            "summary": self._generate_summary(abuseipdb_result, virustotal_result)
        }
        
        return combined
    
    def _generate_summary(self, abuseipdb: Dict, virustotal: Dict) -> Dict:
        """
        Generate overall threat summary from multiple sources
        
        Args:
            abuseipdb: Results from AbuseIPDB
            virustotal: Results from VirusTotal
            
        Returns:
            Summary dictionary with overall threat assessment
        """
        threats = []
        confidence = 0
        
        # Check AbuseIPDB results
        if not abuseipdb.get("error"):
            if abuseipdb.get("is_malicious"):
                threats.append(f"AbuseIPDB: High abuse confidence ({abuseipdb.get('abuse_confidence_score')}%)")
                confidence += abuseipdb.get("abuse_confidence_score", 0) / 100
        
        # Check VirusTotal results
        if not virustotal.get("error"):
            if virustotal.get("is_malicious"):
                threats.append(f"VirusTotal: Flagged by {virustotal.get('malicious_votes')} scanners")
                confidence += virustotal.get("malicious_percentage", 0) / 100
        
        # Calculate average confidence
        sources_checked = sum([1 for r in [abuseipdb, virustotal] if not r.get("error")])
        if sources_checked > 0:
            confidence = confidence / sources_checked
        
        return {
            "is_threat": len(threats) > 0,
            "threat_level": self._calculate_threat_level(confidence),
            "confidence_score": round(confidence * 100, 2),
            "threats_found": threats,
            "recommendation": self._get_recommendation(confidence)
        }
    
    def _calculate_threat_level(self, confidence: float) -> str:
        """Calculate threat level based on confidence score"""
        if confidence >= 0.8:
            return "CRITICAL"
        elif confidence >= 0.6:
            return "HIGH"
        elif confidence >= 0.4:
            return "MEDIUM"
        elif confidence >= 0.2:
            return "LOW"
        else:
            return "MINIMAL"
    
    def _get_recommendation(self, confidence: float) -> str:
        """Get security recommendation based on confidence"""
        if confidence >= 0.8:
            return "BLOCK IMMEDIATELY - High confidence malicious IP"
        elif confidence >= 0.6:
            return "INVESTIGATE - Likely malicious activity"
        elif confidence >= 0.4:
            return "MONITOR - Suspicious activity detected"
        elif confidence >= 0.2:
            return "WATCH - Low threat indicators present"
        else:
            return "ALLOW - No significant threats detected"