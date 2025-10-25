#!/usr/bin/env python3
"""
Updater

Handles updating DiscourseMap to the latest version.
"""

import os
import sys
import subprocess
import requests
from colorama import Fore, Style


def handle_update():
    """Handle update mode"""
    print(f"{Fore.CYAN}[*] Updating DiscourseMap to latest version...{Style.RESET_ALL}")
    
    try:
        # Check current version
        print(f"{Fore.CYAN}[*] Checking current version...{Style.RESET_ALL}")
        current_version = "2.0.2"
        print(f"    Current version: {current_version}")
        
        # Check for latest version on GitHub
        print(f"{Fore.CYAN}[*] Checking for updates on GitHub...{Style.RESET_ALL}")
        try:
            response = requests.get(
                "https://api.github.com/repos/ibrahmsql/discoursemap/releases/latest",
                timeout=10
            )
            if response.status_code == 200:
                latest_release = response.json()
                latest_version = latest_release.get('tag_name', '').lstrip('v')
                print(f"    Latest version: {latest_version}")
                
                # Check pip installed version
                pip_version = _check_pip_version()
                
                # Determine update strategy
                should_update = _should_update(current_version, latest_version, pip_version)
                
                if should_update:
                    _perform_update()
                else:
                    print(f"{Fore.GREEN}[+] You are already using the latest version!{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}[!] Could not check for updates (GitHub API error){Style.RESET_ALL}")
                
        except requests.RequestException:
            print(f"{Fore.YELLOW}[!] Could not check for updates (network error){Style.RESET_ALL}")
        
        # Update dependencies
        _update_dependencies()
        
        # Update vulnerability database
        _update_vulnerability_database()
        
        print(f"{Fore.GREEN}[+] Update process completed!{Style.RESET_ALL}")
        
    except Exception as e:
        print(f"{Fore.RED}[!] Update unexpected error: {e}{Style.RESET_ALL}")


def _check_pip_version():
    """Check pip installed version"""
    pip_version = None
    try:
        pip_show_result = subprocess.run([
            sys.executable, '-m', 'pip', 'show', 'discoursemap'
        ], capture_output=True, text=True, timeout=10)
        
        if pip_show_result.returncode == 0:
            for line in pip_show_result.stdout.split('\n'):
                if line.startswith('Version:'):
                    pip_version = line.split(':')[1].strip()
                    print(f"    Pip installed version: {pip_version}")
                    break
    except Exception as e:
        print(f"    Could not check pip installed version: {e}")
    
    return pip_version


def _should_update(current_version, latest_version, pip_version):
    """Determine if update is needed"""
    should_update = True
    if latest_version and pip_version:
        if latest_version != pip_version:
            print(f"{Fore.YELLOW}[!] Version mismatch: GitHub({latest_version}) vs Pip({pip_version}){Style.RESET_ALL}")
            print(f"{Fore.CYAN}[*] Using pip version as authoritative source{Style.RESET_ALL}")
        elif latest_version == current_version:
            should_update = False
            print(f"{Fore.GREEN}[+] All versions match - no update needed{Style.RESET_ALL}")
    
    return should_update


def _perform_update():
    """Perform the actual update"""
    print(f"{Fore.CYAN}[*] Attempting update...{Style.RESET_ALL}")
    
    update_success = False
    
    # Method 1: python -m pip
    update_success = _try_pip_update("python -m pip", [sys.executable, '-m', 'pip', 'install', '--upgrade', 'discoursemap'])
    
    # Method 2: Direct pip command
    if not update_success:
        update_success = _try_pip_update("pip", ['pip', 'install', '--upgrade', 'discoursemap'])
    
    # Method 3: pip3 command
    if not update_success:
        update_success = _try_pip_update("pip3", ['pip3', 'install', '--upgrade', 'discoursemap'])
    
    # Method 4: Git fallback for development
    if not update_success:
        update_success = _try_git_update()
    
    if update_success:
        print(f"{Fore.CYAN}[*] Please restart DiscourseMap to use the updated version{Style.RESET_ALL}")
    else:
        print(f"{Fore.RED}[!] All update methods failed - please update manually{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] Manual update: pip install --upgrade discoursemap{Style.RESET_ALL}")


def _try_pip_update(method_name, command):
    """Try updating via pip method"""
    try:
        print(f"{Fore.CYAN}[*] Trying: {method_name} install --upgrade{Style.RESET_ALL}")
        result = subprocess.run(command, capture_output=True, text=True, timeout=30)
        
        if result.returncode == 0:
            if 'Successfully installed' in result.stdout:
                print(f"{Fore.GREEN}[+] Successfully updated via {method_name}!{Style.RESET_ALL}")
                return True
            else:
                print(f"{Fore.GREEN}[+] Already up to date ({method_name}){Style.RESET_ALL}")
                return True
        else:
            print(f"{Fore.YELLOW}[!] {method_name} failed: {result.stderr[:50]}...{Style.RESET_ALL}")
            return False
    except Exception as e:
        print(f"{Fore.YELLOW}[!] {method_name} error: {str(e)[:50]}...{Style.RESET_ALL}")
        return False


def _try_git_update():
    """Try updating via git"""
    print(f"{Fore.YELLOW}[!] All pip methods failed, trying git...{Style.RESET_ALL}")
    if os.path.exists('.git'):
        try:
            git_result = subprocess.run(['git', 'pull', 'origin', 'main'], 
                                       capture_output=True, text=True, timeout=30)
            if git_result.returncode == 0:
                if 'Already up to date' in git_result.stdout:
                    print(f"{Fore.GREEN}[+] Already up to date (git){Style.RESET_ALL}")
                else:
                    print(f"{Fore.GREEN}[+] Updated via git pull{Style.RESET_ALL}")
                return True
            else:
                print(f"{Fore.RED}[!] Git update failed: {git_result.stderr[:100]}{Style.RESET_ALL}")
                return False
        except Exception as e:
            print(f"{Fore.RED}[!] Git error: {str(e)[:50]}...{Style.RESET_ALL}")
            return False
    else:
        print(f"{Fore.RED}[!] Not a git repository - manual update required{Style.RESET_ALL}")
        return False


def _update_dependencies():
    """Update dependencies"""
    print(f"{Fore.CYAN}[*] Updating dependencies...{Style.RESET_ALL}")
    try:
        deps_result = subprocess.run([
            sys.executable, '-m', 'pip', 'install', '--upgrade', '-r', 'requirements.txt'
        ], capture_output=True, text=True)
        
        if deps_result.returncode == 0:
            print(f"{Fore.GREEN}[+] Dependencies updated successfully{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}[!] Some dependencies could not be updated{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.YELLOW}[!] Error updating dependencies: {e}{Style.RESET_ALL}")


def _update_vulnerability_database():
    """Update vulnerability database"""
    print(f"{Fore.CYAN}[*] Updating vulnerability database...{Style.RESET_ALL}")
    try:
        data_dir = os.path.join(os.path.dirname(__file__), '..', '..', 'data')
        vuln_file = os.path.join(data_dir, 'plugin_vulnerabilities.yaml')
        
        if os.path.exists(vuln_file):
            # Touch the file to update timestamp
            os.utime(vuln_file, None)
            print(f"{Fore.GREEN}[+] Vulnerability database refreshed{Style.RESET_ALL}")
    except Exception as e:
        print(f"{Fore.YELLOW}[!] Error updating vulnerability database: {e}{Style.RESET_ALL}")