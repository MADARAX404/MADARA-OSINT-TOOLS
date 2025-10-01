#!/usr/bin/env python3
"""
MADARA OSINT Information Gathering Tool
A tool for gathering publicly available information from various sources
"""

import os
import json
import requests
from datetime import datetime
from typing import Dict, List, Optional
import re
from urllib.parse import quote_plus

class Colors:
    """Terminal colors for better UI"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    END = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

class OSINTTool:
    def __init__(self):
        self.results = {}
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
    def banner(self):
        """Display tool banner"""
        banner_text = f"""
{Colors.CYAN}╔═══════════════════════════════════════════════════════════╗
║                                                           ║
║     ███╗   ███╗██████╗     ██╗  ██╗ ██████╗ ██╗     ███╗ ║
║     ████╗ ████║██╔══██╗    ██║  ██║██╔═══██╗██║     ████║ ║
║     ██╔████╔██║██████╔╝    ███████║██║   ██║██║     ██║  ║
║     ██║╚██╔╝██║██╔══██╗    ██╔══██║██║   ██║██║     ██║  ║
║     ██║ ╚═╝ ██║██║  ██║    ██║  ██║╚██████╔╝███████╗███╗ ║
║     ╚═╝     ╚═╝╚═╝  ╚═╝    ╚═╝  ╚═╝ ╚═════╝ ╚══════╝╚══╝ ║
║                                                           ║
║            OSINT Information Gathering Tool              ║
║                    Version 1.0                           ║
║                                                           ║
╚═══════════════════════════════════════════════════════════╝{Colors.END}

{Colors.WARNING}⚠️  COPYRIGTH BY MADARACODE ⚠️{Colors.END}
{Colors.WARNING}Only gather information you have permission to collect{Colors.END}
"""
        print(banner_text)

    def print_status(self, message: str, status: str = "info"):
        """Print formatted status messages"""
        symbols = {
            "info": f"{Colors.BLUE}[ℹ]{Colors.END}",
            "success": f"{Colors.GREEN}[✓]{Colors.END}",
            "warning": f"{Colors.WARNING}[⚠]{Colors.END}",
            "error": f"{Colors.FAIL}[✗]{Colors.END}",
            "search": f"{Colors.CYAN}[🔍]{Colors.END}"
        }
        print(f"{symbols.get(status, '')} {message}")

    def username_search(self, username: str) -> Dict:
        """Search for username across multiple platforms"""
        self.print_status(f"Searching for username: {username}", "search")
        
        platforms = {
            "GitHub": f"https://github.com/{username}",
            "Twitter": f"https://twitter.com/{username}",
            "Instagram": f"https://instagram.com/{username}",
            "Reddit": f"https://reddit.com/user/{username}",
            "Medium": f"https://medium.com/@{username}",
            "Dev.to": f"https://dev.to/{username}",
            "LinkedIn": f"https://linkedin.com/in/{username}",
            "Pinterest": f"https://pinterest.com/{username}",
            "YouTube": f"https://youtube.com/@{username}",
            "TikTok": f"https://tiktok.com/@{username}",
            "Twitch": f"https://twitch.tv/{username}",
            "Steam": f"https://steamcommunity.com/id/{username}",
        }
        
        results = {}
        for platform, url in platforms.items():
            try:
                response = self.session.get(url, timeout=5, allow_redirects=True)
                if response.status_code == 200:
                    results[platform] = {
                        "url": url,
                        "status": "Found",
                        "status_code": response.status_code
                    }
                    self.print_status(f"{platform}: {Colors.GREEN}Found{Colors.END}", "success")
                else:
                    results[platform] = {
                        "url": url,
                        "status": "Not Found",
                        "status_code": response.status_code
                    }
            except Exception as e:
                results[platform] = {
                    "url": url,
                    "status": "Error",
                    "error": str(e)
                }
        
        return results

    def email_search(self, email: str) -> Dict:
        """Gather information about email address"""
        self.print_status(f"Analyzing email: {email}", "search")
        
        results = {
            "email": email,
            "valid_format": self.validate_email(email),
            "domain": email.split('@')[1] if '@' in email else None,
            "breach_check_url": f"https://haveibeenpwned.com/account/{email}",
            "gravatar_check": f"https://gravatar.com/{email}"
        }
        
        if results["domain"]:
            self.print_status(f"Domain: {results['domain']}", "info")
            results["whois_lookup"] = f"https://whois.domaintools.com/{results['domain']}"
        
        return results

    def validate_email(self, email: str) -> bool:
        """Validate email format"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return bool(re.match(pattern, email))

    def phone_search(self, phone: str) -> Dict:
        """Analyze phone number"""
        self.print_status(f"Analyzing phone number: {phone}", "search")
        
        # Remove non-numeric characters
        clean_phone = re.sub(r'\D', '', phone)
        
        results = {
            "original": phone,
            "cleaned": clean_phone,
            "length": len(clean_phone),
            "search_urls": {
                "TrueCaller": f"https://www.truecaller.com/search/us/{clean_phone}",
                "WhitePages": f"https://whitepages.com/phone/{clean_phone}",
                "Google": f"https://www.google.com/search?q={quote_plus(phone)}"
            }
        }
        
        return results

    def domain_search(self, domain: str) -> Dict:
        """Gather information about a domain"""
        self.print_status(f"Analyzing domain: {domain}", "search")
        
        results = {
            "domain": domain,
            "tools": {
                "WHOIS": f"https://whois.domaintools.com/{domain}",
                "DNS Lookup": f"https://mxtoolbox.com/SuperTool.aspx?action=mx%3a{domain}",
                "SSL Check": f"https://www.ssllabs.com/ssltest/analyze.html?d={domain}",
                "SecurityTrails": f"https://securitytrails.com/domain/{domain}/dns",
                "VirusTotal": f"https://www.virustotal.com/gui/domain/{domain}",
                "Wayback Machine": f"https://web.archive.org/web/*/{domain}"
            }
        }
        
        # Try to get basic DNS info
        try:
            import socket
            ip = socket.gethostbyname(domain)
            results["ip_address"] = ip
            self.print_status(f"IP Address: {ip}", "success")
        except:
            results["ip_address"] = "Could not resolve"
        
        return results

    def ip_search(self, ip: str) -> Dict:
        """Gather information about an IP address"""
        self.print_status(f"Analyzing IP: {ip}", "search")
        
        results = {
            "ip": ip,
            "tools": {
                "IPInfo": f"https://ipinfo.io/{ip}",
                "AbuseIPDB": f"https://www.abuseipdb.com/check/{ip}",
                "VirusTotal": f"https://www.virustotal.com/gui/ip-address/{ip}",
                "Shodan": f"https://www.shodan.io/host/{ip}",
                "Censys": f"https://search.censys.io/hosts/{ip}"
            }
        }
        
        # Try to get geolocation using free API
        try:
            response = self.session.get(f"https://ipapi.co/{ip}/json/", timeout=5)
            if response.status_code == 200:
                geo_data = response.json()
                results["geolocation"] = {
                    "country": geo_data.get("country_name"),
                    "city": geo_data.get("city"),
                    "region": geo_data.get("region"),
                    "org": geo_data.get("org")
                }
                self.print_status(f"Location: {geo_data.get('city')}, {geo_data.get('country_name')}", "success")
        except:
            results["geolocation"] = "Could not retrieve"
        
        return results

    def save_results(self, filename: Optional[str] = None):
        """Save results to file"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"osint_results_{timestamp}.json"
        
        try:
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(self.results, f, indent=4, ensure_ascii=False)
            self.print_status(f"Results saved to: {filename}", "success")
            
            # Also create a readable text version
            txt_filename = filename.replace('.json', '.txt')
            with open(txt_filename, 'w', encoding='utf-8') as f:
                f.write("="*60 + "\n")
                f.write("OSINT INFORMATION GATHERING REPORT\n")
                f.write("="*60 + "\n\n")
                f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n")
                
                for category, data in self.results.items():
                    f.write(f"\n{'='*60}\n")
                    f.write(f"{category.upper()}\n")
                    f.write(f"{'='*60}\n")
                    f.write(json.dumps(data, indent=2))
                    f.write("\n")
            
            self.print_status(f"Text report saved to: {txt_filename}", "success")
        except Exception as e:
            self.print_status(f"Error saving results: {e}", "error")

    def display_menu(self):
        """Display main menu"""
        menu = f"""
{Colors.CYAN}┌─────────────────────────────────────────┐
│          MADARA OSINT Search Options           │
├─────────────────────────────────────────┤{Colors.END}
│ 1. Username Search                      │
│ 2. Email Analysis                       │
│ 3. Phone Number Lookup                  │
│ 4. Domain Investigation                 │
│ 5. IP Address Lookup                    │
│ 6. Save Results                         │
│ 7. View Current Results                 │
│ 8. Clear Results                        │
│ 9. Exit                                 │
{Colors.CYAN}└─────────────────────────────────────────┘{Colors.END}
"""
        print(menu)

    def view_results(self):
        """Display current results"""
        if not self.results:
            self.print_status("No results to display", "warning")
            return
        
        print(f"\n{Colors.BOLD}Current Results:{Colors.END}")
        print(json.dumps(self.results, indent=2))

    def run(self):
        """Main program loop"""
        self.banner()
        
        while True:
            self.display_menu()
            choice = input(f"{Colors.GREEN}Select option: {Colors.END}").strip()
            
            if choice == "1":
                username = input(f"{Colors.CYAN}Enter username: {Colors.END}").strip()
                if username:
                    self.results["username_search"] = self.username_search(username)
                
            elif choice == "2":
                email = input(f"{Colors.CYAN}Enter email: {Colors.END}").strip()
                if email:
                    self.results["email_search"] = self.email_search(email)
                
            elif choice == "3":
                phone = input(f"{Colors.CYAN}Enter phone number: {Colors.END}").strip()
                if phone:
                    self.results["phone_search"] = self.phone_search(phone)
                
            elif choice == "4":
                domain = input(f"{Colors.CYAN}Enter domain: {Colors.END}").strip()
                if domain:
                    self.results["domain_search"] = self.domain_search(domain)
                
            elif choice == "5":
                ip = input(f"{Colors.CYAN}Enter IP address: {Colors.END}").strip()
                if ip:
                    self.results["ip_search"] = self.ip_search(ip)
                
            elif choice == "6":
                filename = input(f"{Colors.CYAN}Enter filename (press Enter for default): {Colors.END}").strip()
                self.save_results(filename if filename else None)
                
            elif choice == "7":
                self.view_results()
                
            elif choice == "8":
                confirm = input(f"{Colors.WARNING}Clear all results? (y/n): {Colors.END}").strip().lower()
                if confirm == 'y':
                    self.results = {}
                    self.print_status("Results cleared", "success")
                
            elif choice == "9":
                self.print_status("Exiting... Stay safe!", "info")
                break
                
            else:
                self.print_status("Invalid option", "error")
            
            input(f"\n{Colors.CYAN}Press Enter to continue...{Colors.END}")
            os.system('clear' if os.name == 'posix' else 'cls')
            self.banner()

def main():
    """Entry point"""
    try:
        tool = OSINTTool()
        tool.run()
    except KeyboardInterrupt:
        print(f"\n{Colors.WARNING}Program interrupted by user{Colors.END}")
    except Exception as e:
        print(f"{Colors.FAIL}Error: {e}{Colors.END}")

if __name__ == "__main__":
    main()
