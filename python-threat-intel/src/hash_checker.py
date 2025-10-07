"""
File Hash Checker Module
Checks file hashes against malware databases
"""

import requests
import hashlib
from pathlib import Path
from typing import Dict, Optional
from datetime import datetime
from .config import Config


class HashChecker:
    """Checks file hashes against VirusTotal malware database"""
    
    def __init__(self):
        self.config = Config()
    
    def calculate_file_hash(self, file_path: str, algorithm: str = "sha256") -> Optional[str]:
        """
        Calculate hash of a file
        
        Args:
            file_path: Path to file
            algorithm: Hash algorithm (md5, sha1, sha256)
            
        Returns:
            Hex string of file hash, or None if error
        """
        try:
            path = Path(file_path)
            if not path.exists():
                return None
            
            # Select hash algorithm
            if algorithm == "md5":
                hasher = hashlib.md5()
            elif algorithm == "sha1":
                hasher = hashlib.sha1()
            elif algorithm == "sha256":
                hasher = hashlib.sha256()
            else:
                return None
            
            # Read file in chunks to handle large files
            with open(path, 'rb') as f:
                while chunk := f.read(8192):
                    hasher.update(chunk)
            
            return hasher.hexdigest()
            
        except Exception as e:
            print(f"Error calculating hash: {e}")
            return None
    
    def check_hash_virustotal(self, file_hash: str) -> Dict:
        """
        Check file hash against VirusTotal database
        
        VirusTotal maintains a database of known malware hashes.
        This checks if a file hash matches any known malware.
        
        Args:
            file_hash: SHA256, SHA1, or MD5 hash of file
            
        Returns:
            Dictionary with analysis results
        """
        if not self.config.VIRUSTOTAL_API_KEY:
            return {
                "error": "VirusTotal API key not configured",
                "hash": file_hash,
                "available": False
            }
        
        try:
            headers = {
                "x-apikey": self.config.VIRUSTOTAL_API_KEY
            }
            
            url = f"{self.config.VIRUSTOTAL_FILE_URL}/{file_hash}"
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                attributes = data.get("data", {}).get("attributes", {})
                stats = attributes.get("last_analysis_stats", {})
                
                total_scanners = sum(stats.values())
                malicious = stats.get("malicious", 0)
                suspicious = stats.get("suspicious", 0)
                
                # Get file names
                names = attributes.get("names", [])
                file_name = names[0] if names else "Unknown"
                
                return {
                    "source": "VirusTotal",
                    "hash": file_hash,
                    "hash_type": self._detect_hash_type(file_hash),
                    "file_name": file_name,
                    "file_type": attributes.get("type_description", "Unknown"),
                    "file_size": attributes.get("size", 0),
                    "malicious_detections": malicious,
                    "suspicious_detections": suspicious,
                    "harmless_detections": stats.get("harmless", 0),
                    "undetected": stats.get("undetected", 0),
                    "total_scanners": total_scanners,
                    "detection_rate": f"{malicious}/{total_scanners}",
                    "detection_percentage": (malicious / total_scanners * 100) if total_scanners > 0 else 0,
                    "is_malware": malicious > 0,
                    "threat_level": self._calculate_threat_level(malicious, total_scanners),
                    "first_seen": attributes.get("first_submission_date", "Unknown"),
                    "last_seen": attributes.get("last_analysis_date", "Unknown"),
                    "timestamp": datetime.now().isoformat()
                }
                
            elif response.status_code == 404:
                return {
                    "source": "VirusTotal",
                    "hash": file_hash,
                    "is_malware": False,
                    "message": "Hash not found in database (file unknown to VirusTotal)",
                    "timestamp": datetime.now().isoformat()
                }
            else:
                return {
                    "error": f"API returned status {response.status_code}",
                    "hash": file_hash,
                    "available": False
                }
                
        except requests.RequestException as e:
            return {
                "error": f"Request failed: {str(e)}",
                "hash": file_hash,
                "available": False
            }
    
    def analyze_file(self, file_path: str) -> Dict:
        """
        Complete file analysis: calculate hash and check against databases
        
        Args:
            file_path: Path to file to analyze
            
        Returns:
            Complete analysis results
        """
        # Calculate hashes
        sha256 = self.calculate_file_hash(file_path, "sha256")
        md5 = self.calculate_file_hash(file_path, "md5")
        sha1 = self.calculate_file_hash(file_path, "sha1")
        
        if not sha256:
            return {
                "error": "Could not read file or calculate hash",
                "file_path": file_path
            }
        
        # Check against VirusTotal
        vt_result = self.check_hash_virustotal(sha256)
        
        # Compile results
        return {
            "file_path": file_path,
            "hashes": {
                "sha256": sha256,
                "sha1": sha1,
                "md5": md5
            },
            "analysis": vt_result,
            "timestamp": datetime.now().isoformat()
        }
    
    def _detect_hash_type(self, hash_string: str) -> str:
        """Detect hash type based on length"""
        length = len(hash_string)
        if length == 32:
            return "MD5"
        elif length == 40:
            return "SHA1"
        elif length == 64:
            return "SHA256"
        else:
            return "Unknown"
    
    def _calculate_threat_level(self, malicious: int, total: int) -> str:
        """Calculate threat level based on detection rate"""
        if total == 0:
            return "UNKNOWN"
        
        percentage = (malicious / total) * 100
        
        if percentage >= 50:
            return "CRITICAL"
        elif percentage >= 25:
            return "HIGH"
        elif percentage >= 10:
            return "MEDIUM"
        elif percentage > 0:
            return "LOW"
        else:
            return "CLEAN"