#!/usr/bin/env python3

import os
import re
import json
import argparse
import requests
import urllib3
from urllib.parse import urljoin, urlparse
from colorama import init, Fore, Style
from concurrent.futures import ThreadPoolExecutor, as_completed
import time
from datetime import datetime
import csv
import socket

init(autoreset=True)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class DotNetVersionCVEScanner:
    def __init__(self, timeout=15):
        self.timeout = timeout
        self.session = requests.Session()
        self.session.verify = False
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
        })
        
        self.cve_database = {
            "CVE-2024-0057": {
                "description": ".NET, .NET Framework, and Visual Studio Security Feature Bypass Vulnerability",
                "cvss_score": 9.8,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "published": "2024-01-09",
                "affected_versions": {
                    "dotnet_framework": ["4.8.0-4.8.04690.00", "4.7.2.*", "4.7.1.*", "4.7.*", "4.6.2.*", "4.6.1.*", "4.6.*", "4.5.2.*", "4.5.1.*", "4.5.*"],
                    "dotnet_core": ["6.0.0-6.0.25", "7.0.0-7.0.14", "8.0.0"],
                    "powershell": ["7.2.0-7.2.17", "7.3.0-7.3.10", "7.4.0"]
                },
                "references": ["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2024-0057"]
            },
            "CVE-2023-36049": {
                "description": "Microsoft .NET Framework CRLF Injection Arbitrary File Write/Deletion Vulnerability",
                "cvss_score": 8.8,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                "published": "2023-11-14",
                "affected_versions": {
                    "dotnet_framework": ["4.8.*", "4.7.2.*", "4.7.1.*", "4.7.*", "4.6.2.*", "4.6.1.*", "4.6.*"],
                    "dotnet_core": ["6.0.*", "7.0.*"],
                    "powershell": ["7.2.*", "7.3.*", "7.4.*"]
                },
                "references": ["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36049"]
            },
            "CVE-2023-36558": {
                "description": "ASP.NET Core Security Feature Bypass Vulnerability",
                "cvss_score": 8.2,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H",
                "published": "2023-11-14",
                "affected_versions": {
                    "dotnet_core": ["6.0.0-6.0.24", "7.0.0-7.0.13", "8.0.0"],
                    "aspnet_core": ["6.0.0-6.0.24", "7.0.0-7.0.13", "8.0.0"]
                },
                "references": ["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36558"]
            },
            "CVE-2023-36038": {
                "description": "ASP.NET Core Denial of Service Vulnerability",
                "cvss_score": 7.5,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                "published": "2023-11-14",
                "affected_versions": {
                    "dotnet_core": ["6.0.0-6.0.24", "7.0.0-7.0.13", "8.0.0"],
                    "aspnet_core": ["6.0.0-6.0.24", "7.0.0-7.0.13", "8.0.0"]
                },
                "references": ["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-36038"]
            },
            "CVE-2023-35390": {
                "description": ".NET Remote Code Execution Vulnerability",
                "cvss_score": 8.1,
                "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "published": "2023-08-08",
                "affected_versions": {
                    "dotnet_framework": ["4.8.*", "4.7.2.*", "4.7.1.*", "4.7.*", "4.6.2.*"],
                    "dotnet_core": ["6.0.0-6.0.20", "7.0.0-7.0.9"]
                },
                "references": ["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-35390"]
            },
            "CVE-2023-33170": {
                "description": "ASP.NET and Visual Studio Security Feature Bypass Vulnerability",
                "cvss_score": 8.2,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:H",
                "published": "2023-07-11",
                "affected_versions": {
                    "dotnet_framework": ["4.8.*", "4.7.2.*", "4.7.1.*", "4.7.*", "4.6.2.*"],
                    "dotnet_core": ["6.0.0-6.0.18", "7.0.0-7.0.7"]
                },
                "references": ["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-33170"]
            },
            "CVE-2023-29331": {
                "description": ".NET, .NET Framework, and Visual Studio Denial of Service Vulnerability",
                "cvss_score": 7.5,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                "published": "2023-06-13",
                "affected_versions": {
                    "dotnet_framework": ["4.8.*", "4.7.2.*", "4.7.1.*", "4.7.*", "4.6.2.*"],
                    "dotnet_core": ["6.0.0-6.0.17", "7.0.0-7.0.6"]
                },
                "references": ["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-29331"]
            },
            "CVE-2023-24936": {
                "description": ".NET, .NET Framework, and Visual Studio Elevation of Privilege Vulnerability",
                "cvss_score": 7.8,
                "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                "published": "2023-05-09",
                "affected_versions": {
                    "dotnet_framework": ["4.8.*", "4.7.2.*", "4.7.1.*", "4.7.*", "4.6.2.*"],
                    "dotnet_core": ["6.0.0-6.0.16", "7.0.0-7.0.5"]
                },
                "references": ["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-24936"]
            },
            "CVE-2023-21538": {
                "description": ".NET Denial of Service Vulnerability",
                "cvss_score": 7.5,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                "published": "2023-01-10",
                "affected_versions": {
                    "dotnet_framework": ["4.8.*", "4.7.2.*", "4.7.1.*", "4.7.*", "4.6.2.*"],
                    "dotnet_core": ["6.0.0-6.0.12", "7.0.0-7.0.1"]
                },
                "references": ["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2023-21538"]
            },
            "CVE-2022-41032": {
                "description": ".NET Elevation of Privilege Vulnerability",
                "cvss_score": 7.8,
                "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
                "published": "2022-11-08",
                "affected_versions": {
                    "dotnet_framework": ["4.8.*", "4.7.2.*", "4.7.1.*", "4.7.*", "4.6.2.*"],
                    "dotnet_core": ["6.0.0-6.0.10", "7.0.0"]
                },
                "references": ["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-41032"]
            },
            "CVE-2022-38013": {
                "description": ".NET Information Disclosure Vulnerability",
                "cvss_score": 6.5,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:N/A:N",
                "published": "2022-09-13",
                "affected_versions": {
                    "dotnet_framework": ["4.8.*", "4.7.2.*", "4.7.1.*", "4.7.*", "4.6.2.*"],
                    "dotnet_core": ["6.0.0-6.0.8", "3.1.0-3.1.28"]
                },
                "references": ["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-38013"]
            },
            "CVE-2022-30184": {
                "description": ".NET Information Disclosure Vulnerability",
                "cvss_score": 5.5,
                "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
                "published": "2022-06-14",
                "affected_versions": {
                    "dotnet_framework": ["4.8.*", "4.7.2.*", "4.7.1.*", "4.7.*", "4.6.2.*"],
                    "dotnet_core": ["6.0.0-6.0.5", "3.1.0-3.1.25"]
                },
                "references": ["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2022-30184"]
            },
            "CVE-2021-31957": {
                "description": "ASP.NET Denial of Service Vulnerability",
                "cvss_score": 7.5,
                "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
                "published": "2021-06-08",
                "affected_versions": {
                    "dotnet_framework": ["4.8.*", "4.7.2.*", "4.7.1.*", "4.7.*", "4.6.2.*"],
                    "dotnet_core": ["5.0.0-5.0.6", "3.1.0-3.1.15"]
                },
                "references": ["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-31957"]
            },
            "CVE-2021-26701": {
                "description": ".NET Core Remote Code Execution Vulnerability",
                "cvss_score": 8.1,
                "cvss_vector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
                "published": "2021-02-25",
                "affected_versions": {
                    "dotnet_core": ["5.0.0-5.0.3", "3.1.0-3.1.12", "2.1.0-2.1.25"]
                },
                "references": ["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2021-26701"]
            },
            "CVE-2020-1147": {
                "description": ".NET Framework Remote Code Execution Vulnerability",
                "cvss_score": 7.8,
                "cvss_vector": "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H",
                "published": "2020-07-14",
                "affected_versions": {
                    "dotnet_framework": ["4.8.*", "4.7.2.*", "4.7.1.*", "4.7.*", "4.6.2.*", "4.6.1.*", "4.6.*", "4.5.2.*", "4.5.1.*", "4.5.*", "3.5.*", "3.0.*", "2.0.*"]
                },
                "references": ["https://msrc.microsoft.com/update-guide/vulnerability/CVE-2020-1147"]
            }
        }

    def banner(self):
        print(f"""{Fore.CYAN}
    ██████╗  ██████╗ ████████╗███╗   ██╗███████╗████████╗
    ██╔══██╗██╔═══██╗╚══██╔══╝████╗  ██║██╔════╝╚══██╔══╝
    ██║  ██║██║   ██║   ██║   ██╔██╗ ██║█████╗     ██║
    ██║  ██║██║   ██║   ██║   ██║╚██╗██║██╔══╝     ██║
    ██████╔╝╚██████╔╝   ██║   ██║ ╚████║███████╗   ██║
    ╚═════╝  ╚═════╝    ╚═╝   ╚═╝  ╚═══╝╚══════╝   ╚═╝
    {Fore.RED} ██████╗██╗   ██╗███████╗    ███████╗ ██████╗ █████╗ ███╗   ██╗
    ██╔════╝██║   ██║██╔════╝    ██╔════╝██╔════╝██╔══██╗████╗  ██║
    ██║     ██║   ██║█████╗      ███████╗██║     ███████║██╔██╗ ██║
    ██║     ╚██╗ ██╔╝██╔══╝      ╚════██║██║     ██╔══██║██║╚██╗██║
    ╚██████╗ ╚████╔╝ ███████╗    ███████║╚██████╗██║  ██║██║ ╚████║
     ╚═════╝  ╚═══╝  ╚══════╝    ╚══════╝ ╚═════╝╚═╝  ╚═╝╚═╝  ╚═══╝
{Fore.WHITE}    .NET Framework / Core / ASP.NET Version Vulnerability Scanner
    ──────────────────────────────────────────────────────────────
      ▸ Extracts .NET Framework, Core, and ASP.NET versions
      ▸ Checks against {Fore.YELLOW}{len(self.cve_database)}{Fore.WHITE} known CVEs with CVSS scoring
      ▸ Header, error-page, and content-based detection
      ▸ Export results to JSON / CSV
      {Fore.MAGENTA}  author: c0d3ninja{Style.RESET_ALL}
""")

    def test_connectivity(self, host, port, timeout=5):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((host, port))
            sock.close()
            return result == 0
        except Exception:
            return False

    def extract_dotnet_versions(self, url):
        print(f"{Fore.CYAN}[*] Extracting .NET versions from: {url}{Style.RESET_ALL}")
        
        probe_paths = [
            '/',
            '/Account/',
            '/Admin/',
            '/Login/',
            '/Default.aspx',
            '/WebForm1.aspx',
            '/Account/Login',
            '/Account/Register',
            '/Home/Index',
            '/api/values',
            '/WebResource.axd',
            '/ScriptResource.axd',
            '/Trace.axd',
            '/elmah.axd',
            '/glimpse.axd',
            '/nonexistentpage.aspx',  # Force 404 error
            '/test.aspx',             # Force error
            '/error.aspx'             # Force error
        ]
        
        version_info = {
            'dotnet_framework': None,
            'dotnet_core': None,
            'aspnet_version': None,
            'aspnet_core': None,
            'mvc_version': None,
            'iis_version': None,
            'detection_methods': [],
            'error_pages': [],
            'headers_found': {},
            'content_indicators': []
        }
        
        for path in probe_paths:
            try:
                test_url = urljoin(url, path)
                print(f"{Fore.YELLOW}[*] Probing: {path}{Style.RESET_ALL}")
                
                response = self.session.get(test_url, timeout=self.timeout, allow_redirects=True)
                
                headers = response.headers
                
                if 'X-AspNet-Version' in headers:
                    version_info['aspnet_version'] = headers['X-AspNet-Version']
                    version_info['detection_methods'].append(f'X-AspNet-Version header from {path}')
                    version_info['headers_found']['X-AspNet-Version'] = headers['X-AspNet-Version']
                
                if 'Server' in headers:
                    server = headers['Server']
                    version_info['headers_found']['Server'] = server
                    
                    iis_match = re.search(r'Microsoft-IIS/(\d+\.\d+)', server)
                    if iis_match:
                        version_info['iis_version'] = iis_match.group(1)
                        version_info['detection_methods'].append(f'IIS version from Server header in {path}')
                
                if 'X-Powered-By' in headers:
                    powered_by = headers['X-Powered-By']
                    version_info['headers_found']['X-Powered-By'] = powered_by
                    
                    aspnet_match = re.search(r'ASP\.NET', powered_by)
                    if aspnet_match:
                        version_info['detection_methods'].append(f'ASP.NET detected in X-Powered-By from {path}')
                
                if 'X-AspNetMvc-Version' in headers:
                    version_info['mvc_version'] = headers['X-AspNetMvc-Version']
                    version_info['detection_methods'].append(f'MVC version from X-AspNetMvc-Version header in {path}')
                    version_info['headers_found']['X-AspNetMvc-Version'] = headers['X-AspNetMvc-Version']
                
                content = response.text
                content_lower = content.lower()
                
                framework_patterns = [
                    r'microsoft \.net framework version[:\s]*(\d+\.\d+\.\d+(?:\.\d+)?)',
                    r'\.net framework (\d+\.\d+(?:\.\d+)?)',
                    r'version information[:\s]*microsoft \.net framework version[:\s]*(\d+\.\d+\.\d+(?:\.\d+)?)'
                ]
                
                for pattern in framework_patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    if matches:
                        version_info['dotnet_framework'] = matches[0]
                        version_info['detection_methods'].append(f'.NET Framework version from {path} content')
                        break
                
                aspnet_patterns = [
                    r'asp\.net version[:\s]*(\d+\.\d+\.\d+(?:\.\d+)?)',
                    r'version information[:\s]*asp\.net version[:\s]*(\d+\.\d+\.\d+(?:\.\d+)?)'
                ]
                
                for pattern in aspnet_patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    if matches and not version_info['aspnet_version']:
                        version_info['aspnet_version'] = matches[0]
                        version_info['detection_methods'].append(f'ASP.NET version from {path} content')
                        break
                
                dotnet_core_patterns = [
                    r'\.net core (\d+\.\d+(?:\.\d+)?)',
                    r'asp\.net core (\d+\.\d+(?:\.\d+)?)',
                    r'microsoft\.aspnetcore\.app["\s]*:\s*["\s]*(\d+\.\d+\.\d+)'
                ]
                
                for pattern in dotnet_core_patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    if matches:
                        if 'asp.net core' in pattern.lower():
                            version_info['aspnet_core'] = matches[0]
                            version_info['detection_methods'].append(f'ASP.NET Core version from {path} content')
                        else:
                            version_info['dotnet_core'] = matches[0]
                            version_info['detection_methods'].append(f'.NET Core version from {path} content')
                        break
                
                mvc_patterns = [
                    r'system\.web\.mvc, version=(\d+\.\d+\.\d+\.\d+)',
                    r'mvc (\d+\.\d+(?:\.\d+)?)'
                ]
                
                for pattern in mvc_patterns:
                    matches = re.findall(pattern, content, re.IGNORECASE)
                    if matches and not version_info['mvc_version']:
                        version_info['mvc_version'] = matches[0]
                        version_info['detection_methods'].append(f'MVC version from {path} content')
                        break
                
                dotnet_indicators = [
                    'viewstate', '__viewstate', '__eventvalidation',
                    'asp:content', 'runat="server"', 'masterpagefile',
                    'webresource.axd', 'scriptresource.axd',
                    'server error in', 'asp.net', 'system.web',
                    'system.web.mvc', 'system.web.httpexception'
                ]
                
                for indicator in dotnet_indicators:
                    if indicator in content_lower:
                        if indicator not in version_info['content_indicators']:
                            version_info['content_indicators'].append(indicator)
                
                error_indicators = [
                    'server error in',
                    'asp.net version',
                    'microsoft .net framework version',
                    'system.web.httpexception',
                    'system.web.mvc',
                    'requested url:'
                ]
                
                if any(indicator in content_lower for indicator in error_indicators):
                    if response.status_code in [404, 500, 403]:
                        version_info['error_pages'].append({
                            'path': path,
                            'status_code': response.status_code,
                            'url': test_url
                        })
                
                if version_info['dotnet_framework'] or version_info['dotnet_core'] or version_info['aspnet_version']:
                    pass
                
            except requests.exceptions.RequestException as e:
                print(f"{Fore.YELLOW}[!] Error probing {path}: {str(e)}{Style.RESET_ALL}")
                continue
            except Exception as e:
                print(f"{Fore.YELLOW}[!] Unexpected error probing {path}: {str(e)}{Style.RESET_ALL}")
                continue
        
        return version_info

    def check_version_vulnerabilities(self, version_info):
        vulnerabilities = []
        
        if version_info['dotnet_framework']:
            framework_version = version_info['dotnet_framework']
            for cve_id, cve_data in self.cve_database.items():
                if 'dotnet_framework' in cve_data['affected_versions']:
                    if self.is_version_vulnerable(framework_version, cve_data['affected_versions']['dotnet_framework']):
                        vulnerabilities.append({
                            'cve_id': cve_id,
                            'product': '.NET Framework',
                            'version': framework_version,
                            'cve_data': cve_data
                        })
        
        if version_info['dotnet_core']:
            core_version = version_info['dotnet_core']
            for cve_id, cve_data in self.cve_database.items():
                if 'dotnet_core' in cve_data['affected_versions']:
                    if self.is_version_vulnerable(core_version, cve_data['affected_versions']['dotnet_core']):
                        vulnerabilities.append({
                            'cve_id': cve_id,
                            'product': '.NET Core',
                            'version': core_version,
                            'cve_data': cve_data
                        })
        
        if version_info['aspnet_core']:
            aspnet_core_version = version_info['aspnet_core']
            for cve_id, cve_data in self.cve_database.items():
                if 'aspnet_core' in cve_data['affected_versions']:
                    if self.is_version_vulnerable(aspnet_core_version, cve_data['affected_versions']['aspnet_core']):
                        vulnerabilities.append({
                            'cve_id': cve_id,
                            'product': 'ASP.NET Core',
                            'version': aspnet_core_version,
                            'cve_data': cve_data
                        })
        
        if version_info['aspnet_version']:
            aspnet_version = version_info['aspnet_version']
            
            for cve_id, cve_data in self.cve_database.items():
                if 'dotnet_framework' in cve_data['affected_versions']:
                    if self.is_version_vulnerable(aspnet_version, cve_data['affected_versions']['dotnet_framework']):
                        vulnerabilities.append({
                            'cve_id': cve_id,
                            'product': '.NET Framework (from ASP.NET version)',
                            'version': aspnet_version,
                            'cve_data': cve_data
                        })
            
            if not version_info['dotnet_framework'] or version_info['dotnet_framework'] == "4.0.30319":
                aspnet_to_framework = {
                    '4.8': '4.8',
                    '4.7': '4.7',
                    '4.6': '4.6',
                    '4.5': '4.5',
                    '4.0': '4.0',
                    '3.5': '3.5',
                    '2.0': '2.0'
                }
                
                for aspnet_ver, framework_ver in aspnet_to_framework.items():
                    if aspnet_version.startswith(aspnet_ver):
                        for cve_id, cve_data in self.cve_database.items():
                            if 'dotnet_framework' in cve_data['affected_versions']:
                                if self.is_version_vulnerable(framework_ver, cve_data['affected_versions']['dotnet_framework']):
                                    duplicate = False
                                    for existing_vuln in vulnerabilities:
                                        if existing_vuln['cve_id'] == cve_id and existing_vuln['product'].startswith('.NET Framework'):
                                            duplicate = True
                                            break
                                    
                                    if not duplicate:
                                        vulnerabilities.append({
                                            'cve_id': cve_id,
                                            'product': '.NET Framework (mapped from ASP.NET)',
                                            'version': f'{framework_ver} (from ASP.NET {aspnet_version})',
                                            'cve_data': cve_data
                                        })
                        break
        
        return vulnerabilities

    def is_version_vulnerable(self, version, vulnerable_patterns):
        try:
            clean_version = re.split(r'[-+]', version)[0]
            
            for pattern in vulnerable_patterns:
                if '*' in pattern:
                    base_version = pattern.replace('.*', '')
                    if clean_version.startswith(base_version):
                        return True
                elif '-' in pattern:
                    try:
                        start_version, end_version = pattern.split('-')
                        if self.compare_versions(clean_version, start_version) >= 0 and \
                           self.compare_versions(clean_version, end_version) <= 0:
                            return True
                    except:
                        continue
                else:
                    if clean_version == pattern:
                        return True
            
            return False
        except:
            return False

    def compare_versions(self, version1, version2):
        try:
            def version_tuple(v):
                return tuple(map(int, v.split('.')))
            
            v1_tuple = version_tuple(version1)
            v2_tuple = version_tuple(version2)
            
            max_len = max(len(v1_tuple), len(v2_tuple))
            v1_tuple += (0,) * (max_len - len(v1_tuple))
            v2_tuple += (0,) * (max_len - len(v2_tuple))
            
            if v1_tuple < v2_tuple:
                return -1
            elif v1_tuple > v2_tuple:
                return 1
            else:
                return 0
        except:
            return 0

    def scan_target(self, target):
        print(f"\n{Fore.CYAN}[*] Scanning target: {target}{Style.RESET_ALL}")
        
        if not target.startswith(('http://', 'https://')):
            urls_to_try = [f'http://{target}', f'https://{target}']
        else:
            urls_to_try = [target]
        
        for url in urls_to_try:
            try:
                parsed = urlparse(url)
                host = parsed.hostname
                port = parsed.port or (443 if parsed.scheme == 'https' else 80)
                
                if not self.test_connectivity(host, port, 5):
                    print(f"{Fore.YELLOW}[!] Cannot connect to {url}{Style.RESET_ALL}")
                    continue
                
                print(f"{Fore.GREEN}[+] Connected to {url}{Style.RESET_ALL}")
                
                version_info = self.extract_dotnet_versions(url)
                
                vulnerabilities = self.check_version_vulnerabilities(version_info)
                
                return {
                    'target': url,
                    'status': 'success',
                    'version_info': version_info,
                    'vulnerabilities': vulnerabilities,
                    'scan_time': datetime.now().isoformat()
                }
                
            except Exception as e:
                print(f"{Fore.RED}[!] Error scanning {url}: {str(e)}{Style.RESET_ALL}")
                continue
        
        return {
            'target': target,
            'status': 'failed',
            'error': 'Could not connect to target',
            'scan_time': datetime.now().isoformat()
        }

    def generate_report(self, results):
        print(f"\n{Fore.CYAN}{'='*100}")
        print(f".NET Version CVE Scanner - Vulnerability Assessment Report")
        print(f"{'='*100}{Style.RESET_ALL}")
        
        total_targets = len(results)
        successful_scans = len([r for r in results if r['status'] == 'success'])
        total_vulnerabilities = 0
        critical_vulns = 0
        high_vulns = 0
        
        for result in results:
            if result['status'] == 'success':
                vulns = result.get('vulnerabilities', [])
                total_vulnerabilities += len(vulns)
                
                for vuln in vulns:
                    cvss_score = vuln['cve_data']['cvss_score']
                    if cvss_score >= 9.0:
                        critical_vulns += 1
                    elif cvss_score >= 7.0:
                        high_vulns += 1
        
        print(f"Scan Summary:")
        print(f"  Total Targets: {total_targets}")
        print(f"  Successful Scans: {Fore.GREEN}{successful_scans}{Style.RESET_ALL}")
        print(f"  Failed Scans: {Fore.RED}{total_targets - successful_scans}{Style.RESET_ALL}")
        print(f"  Total Vulnerabilities: {Fore.YELLOW}{total_vulnerabilities}{Style.RESET_ALL}")
        print(f"  Critical (CVSS 9.0+): {Fore.RED}{critical_vulns}{Style.RESET_ALL}")
        print(f"  High (CVSS 7.0-8.9): {Fore.YELLOW}{high_vulns}{Style.RESET_ALL}")
        print()
        
        for result in results:
            target = result['target']
            print(f"{Fore.CYAN}Target: {target}{Style.RESET_ALL}")
            
            if result['status'] != 'success':
                print(f"  {Fore.RED}Status: FAILED{Style.RESET_ALL}")
                print(f"  Error: {result.get('error', 'Unknown error')}")
                print()
                continue
            
            print(f"  {Fore.GREEN}Status: SUCCESS{Style.RESET_ALL}")
            
            version_info = result['version_info']
            print(f"  Version Information:")
            
            if version_info['dotnet_framework']:
                print(f"    .NET Framework: {Fore.YELLOW}{version_info['dotnet_framework']}{Style.RESET_ALL}")
            
            if version_info['dotnet_core']:
                print(f"    .NET Core: {Fore.YELLOW}{version_info['dotnet_core']}{Style.RESET_ALL}")
            
            if version_info['aspnet_version']:
                print(f"    ASP.NET: {Fore.YELLOW}{version_info['aspnet_version']}{Style.RESET_ALL}")
            
            if version_info['aspnet_core']:
                print(f"    ASP.NET Core: {Fore.YELLOW}{version_info['aspnet_core']}{Style.RESET_ALL}")
            
            if version_info['mvc_version']:
                print(f"    MVC: {Fore.YELLOW}{version_info['mvc_version']}{Style.RESET_ALL}")
            
            if version_info['iis_version']:
                print(f"    IIS: {Fore.YELLOW}{version_info['iis_version']}{Style.RESET_ALL}")
            
            if not any([version_info['dotnet_framework'], version_info['dotnet_core'], 
                       version_info['aspnet_version'], version_info['aspnet_core']]):
                print(f"    {Fore.YELLOW}No specific .NET versions detected{Style.RESET_ALL}")
                if version_info['content_indicators']:
                    print(f"    .NET Indicators: {', '.join(version_info['content_indicators'])}")
            
            if version_info['detection_methods']:
                print(f"  Detection Methods:")
                for method in version_info['detection_methods']:
                    print(f"    • {method}")
            
            vulnerabilities = result.get('vulnerabilities', [])
            if vulnerabilities:
                print(f"  {Fore.RED}Vulnerabilities Found: {len(vulnerabilities)}{Style.RESET_ALL}")
                
                vulnerabilities.sort(key=lambda x: x['cve_data']['cvss_score'], reverse=True)
                
                for vuln in vulnerabilities:
                    cve_id = vuln['cve_id']
                    product = vuln['product']
                    version = vuln['version']
                    cve_data = vuln['cve_data']
                    
                    cvss_score = cve_data['cvss_score']
                    if cvss_score >= 9.0:
                        score_color = Fore.RED
                        severity = "CRITICAL"
                    elif cvss_score >= 7.0:
                        score_color = Fore.YELLOW
                        severity = "HIGH"
                    elif cvss_score >= 4.0:
                        score_color = Fore.BLUE
                        severity = "MEDIUM"
                    else:
                        score_color = Fore.GREEN
                        severity = "LOW"
                    
                    print(f"    {Fore.RED}• {cve_id}{Style.RESET_ALL} - {score_color}{severity} (CVSS {cvss_score}){Style.RESET_ALL}")
                    print(f"      Product: {product}")
                    print(f"      Version: {version}")
                    print(f"      Description: {cve_data['description']}")
                    print(f"      Published: {cve_data['published']}")
                    print(f"      CVSS Vector: {cve_data['cvss_vector']}")
                    if cve_data['references']:
                        print(f"      References: {', '.join(cve_data['references'])}")
                    print()
            else:
                print(f"  {Fore.GREEN}No known vulnerabilities found{Style.RESET_ALL}")
            
            print()
        
        print(f"{Fore.CYAN}Scan completed at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{Style.RESET_ALL}")

    def export_results(self, results, output_file, format='json'):
        try:
            if format.lower() == 'json':
                with open(output_file, 'w') as f:
                    json.dump(results, f, indent=2, default=str)
                print(f"{Fore.GREEN}[+] Results exported to JSON: {output_file}{Style.RESET_ALL}")
            
            elif format.lower() == 'csv':
                with open(output_file, 'w', newline='') as f:
                    writer = csv.writer(f)
                    
                    writer.writerow([
                        'Target', 'Status', 'NET_Framework', 'NET_Core', 'ASP_NET', 
                        'ASP_NET_Core', 'MVC', 'IIS', 'CVE_ID', 'Product', 'Version',
                        'CVSS_Score', 'Severity', 'Description', 'Published'
                    ])
                    
                    for result in results:
                        target = result['target']
                        status = result['status']
                        
                        if status != 'success':
                            writer.writerow([target, status, '', '', '', '', '', '', '', '', '', '', '', '', ''])
                            continue
                        
                        version_info = result['version_info']
                        vulnerabilities = result.get('vulnerabilities', [])
                        
                        if not vulnerabilities:
                            writer.writerow([
                                target, status,
                                version_info.get('dotnet_framework', ''),
                                version_info.get('dotnet_core', ''),
                                version_info.get('aspnet_version', ''),
                                version_info.get('aspnet_core', ''),
                                version_info.get('mvc_version', ''),
                                version_info.get('iis_version', ''),
                                '', '', '', '', '', '', ''
                            ])
                        else:
                            for vuln in vulnerabilities:
                                cvss_score = vuln['cve_data']['cvss_score']
                                if cvss_score >= 9.0:
                                    severity = "CRITICAL"
                                elif cvss_score >= 7.0:
                                    severity = "HIGH"
                                elif cvss_score >= 4.0:
                                    severity = "MEDIUM"
                                else:
                                    severity = "LOW"
                                
                                writer.writerow([
                                    target, status,
                                    version_info.get('dotnet_framework', ''),
                                    version_info.get('dotnet_core', ''),
                                    version_info.get('aspnet_version', ''),
                                    version_info.get('aspnet_core', ''),
                                    version_info.get('mvc_version', ''),
                                    version_info.get('iis_version', ''),
                                    vuln['cve_id'],
                                    vuln['product'],
                                    vuln['version'],
                                    cvss_score,
                                    severity,
                                    vuln['cve_data']['description'],
                                    vuln['cve_data']['published']
                                ])
                
                print(f"{Fore.GREEN}[+] Results exported to CSV: {output_file}{Style.RESET_ALL}")
            
        except Exception as e:
            print(f"{Fore.RED}[!] Error exporting results: {e}{Style.RESET_ALL}")

def main():
    parser = argparse.ArgumentParser(description='.NET Version CVE Scanner')
    parser.add_argument('-t', '--target', help='Single target to scan')
    parser.add_argument('-f', '--file', help='File containing targets to scan')
    parser.add_argument('--timeout', type=int, default=15, help='Request timeout (default: 15)')
    parser.add_argument('-o', '--output', help='Output file for results')
    parser.add_argument('--format', choices=['json', 'csv'], default='json', help='Output format (default: json)')
    parser.add_argument('--threads', type=int, default=5, help='Number of threads (default: 5)')
    
    args = parser.parse_args()
    
    scanner = DotNetVersionCVEScanner(timeout=args.timeout)
    scanner.banner()
    
    targets = []
    if args.target:
        targets = [args.target]
    elif args.file:
        try:
            with open(args.file, 'r') as f:
                targets = [line.strip() for line in f if line.strip()]
        except Exception as e:
            print(f"{Fore.RED}[!] Error reading file: {e}{Style.RESET_ALL}")
            return
    
    if not targets:
        print(f"{Fore.YELLOW}[!] No targets specified. Use -t for single target or -f for file{Style.RESET_ALL}")
        parser.print_help()
        return
    
    print(f"{Fore.CYAN}[*] Starting scan of {len(targets)} target(s)...{Style.RESET_ALL}")
    
    results = []
    
    if args.threads > 1:
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            future_to_target = {executor.submit(scanner.scan_target, target): target for target in targets}
            
            for future in as_completed(future_to_target):
                target = future_to_target[future]
                try:
                    result = future.result()
                    results.append(result)
                except Exception as e:
                    print(f"{Fore.RED}[!] Error scanning {target}: {e}{Style.RESET_ALL}")
                    results.append({
                        'target': target,
                        'status': 'failed',
                        'error': str(e),
                        'scan_time': datetime.now().isoformat()
                    })
    else:
        for target in targets:
            result = scanner.scan_target(target)
            results.append(result)
    
    scanner.generate_report(results)
    
    if args.output:
        scanner.export_results(results, args.output, args.format)

if __name__ == "__main__":
    main() 
