#!/usr/bin/env python3
"""
Nginx Log Parser
Parses nginx log files, converts them to CSV format, and commits to Git repository.

Author: GitHub Copilot
Date: February 2026
"""

import re
import csv
import sys
import os
import argparse
import subprocess
from datetime import datetime
from typing import List, Dict, Optional
import json


class NginxLogParser:
    """Parser for nginx log files with support for various nginx log formats."""
    
    def __init__(self):
        # Extended nginx log format pattern
        # This pattern matches the format in the provided log file
        self.log_pattern = re.compile(
            r'(?P<remote_addr>\S+)\s+'
            r'(?P<remote_user>\S+)\s+'
            r'(?P<time_local>\S+)\s+'
            r'\[(?P<timestamp>[^\]]+)\]\s+'
            r'"(?P<request>[^"]*)"\s+'
            r'(?P<status>\d+)\s+'
            r'(?P<body_bytes_sent>\S+)\s+'
            r'"(?P<http_referer>[^"]*)"\s+'
            r'"(?P<http_user_agent>[^"]*)"\s+'
            r'(?P<request_length>\S+)\s+'
            r'(?P<request_time>\S+)\s+'
            r'\[(?P<upstream_name>[^\]]*)\]\s+'
            r'\[(?P<upstream_addr_list>[^\]]*)\]\s+'
            r'(?P<upstream_addr>\S+)\s+'
            r'(?P<upstream_response_length>\S+)\s+'
            r'(?P<upstream_response_time>\S+)\s+'
            r'(?P<upstream_status>\S+)\s+'
            r'(?P<request_id>\S+)'
        )
        
        # Standard nginx combined log format (fallback)
        self.standard_pattern = re.compile(
            r'(?P<remote_addr>\S+)\s+'
            r'(?P<remote_user>\S+)\s+'
            r'(?P<remote_user2>\S+)\s+'
            r'\[(?P<timestamp>[^\]]+)\]\s+'
            r'"(?P<request>[^"]*)"\s+'
            r'(?P<status>\d+)\s+'
            r'(?P<body_bytes_sent>\S+)\s+'
            r'"(?P<http_referer>[^"]*)"\s+'
            r'"(?P<http_user_agent>[^"]*)"'
        )
        
        self.csv_headers = [
            'timestamp', 'remote_addr', 'method', 'url', 'protocol', 
            'status', 'body_bytes_sent', 'http_referer', 'http_user_agent',
            'request_length', 'request_time', 'upstream_name', 'upstream_addr',
            'upstream_response_length', 'upstream_response_time', 'upstream_status',
            'request_id'
        ]

    def parse_request(self, request_line: str) -> Dict[str, str]:
        """Parse the request line into method, URL, and protocol."""
        parts = request_line.split()
        return {
            'method': parts[0] if len(parts) > 0 else '',
            'url': parts[1] if len(parts) > 1 else '',
            'protocol': parts[2] if len(parts) > 2 else ''
        }

    def parse_line(self, line: str) -> Optional[Dict[str, str]]:
        """Parse a single nginx log line."""
        line = line.strip()
        if not line:
            return None
            
        # Try extended format first
        match = self.log_pattern.match(line)
        if match:
            data = match.groupdict()
            # Parse request into components
            request_parts = self.parse_request(data.get('request', ''))
            
            return {
                'timestamp': data.get('timestamp', ''),
                'remote_addr': data.get('remote_addr', ''),
                'method': request_parts.get('method', ''),
                'url': request_parts.get('url', ''),
                'protocol': request_parts.get('protocol', ''),
                'status': data.get('status', ''),
                'body_bytes_sent': data.get('body_bytes_sent', ''),
                'http_referer': data.get('http_referer', ''),
                'http_user_agent': data.get('http_user_agent', ''),
                'request_length': data.get('request_length', ''),
                'request_time': data.get('request_time', ''),
                'upstream_name': data.get('upstream_name', ''),
                'upstream_addr': data.get('upstream_addr', ''),
                'upstream_response_length': data.get('upstream_response_length', ''),
                'upstream_response_time': data.get('upstream_response_time', ''),
                'upstream_status': data.get('upstream_status', ''),
                'request_id': data.get('request_id', '')
            }
        
        # Try standard format as fallback
        match = self.standard_pattern.match(line)
        if match:
            data = match.groupdict()
            request_parts = self.parse_request(data.get('request', ''))
            
            return {
                'timestamp': data.get('timestamp', ''),
                'remote_addr': data.get('remote_addr', ''),
                'method': request_parts.get('method', ''),
                'url': request_parts.get('url', ''),
                'protocol': request_parts.get('protocol', ''),
                'status': data.get('status', ''),
                'body_bytes_sent': data.get('body_bytes_sent', ''),
                'http_referer': data.get('http_referer', ''),
                'http_user_agent': data.get('http_user_agent', ''),
                'request_length': '',
                'request_time': '',
                'upstream_name': '',
                'upstream_addr': '',
                'upstream_response_length': '',
                'upstream_response_time': '',
                'upstream_status': '',
                'request_id': ''
            }
        
        print(f"Warning: Could not parse line: {line[:100]}...", file=sys.stderr)
        return None

    def parse_log_file(self, file_path: str) -> List[Dict[str, str]]:
        """Parse the entire log file."""
        parsed_logs = []
        
        try:
            if file_path == '-':
                # Read from stdin
                for line_num, line in enumerate(sys.stdin, 1):
                    parsed_line = self.parse_line(line)
                    if parsed_line:
                        parsed_logs.append(parsed_line)
            else:
                # Read from file
                with open(file_path, 'r', encoding='utf-8') as f:
                    for line_num, line in enumerate(f, 1):
                        parsed_line = self.parse_line(line)
                        if parsed_line:
                            parsed_logs.append(parsed_line)
                            
        except FileNotFoundError:
            print(f"Error: File not found: {file_path}", file=sys.stderr)
            sys.exit(1)
        except Exception as e:
            print(f"Error reading file: {e}", file=sys.stderr)
            sys.exit(1)
            
        return parsed_logs

    def filter_logs(self, logs: List[Dict[str, str]], filters: Dict[str, str]) -> List[Dict[str, str]]:
        """Apply filters to the log data."""
        if not filters:
            return logs
            
        filtered_logs = []
        for log_entry in logs:
            include = True
            for field, value in filters.items():
                if field in log_entry and value.lower() not in log_entry[field].lower():
                    include = False
                    break
            if include:
                filtered_logs.append(log_entry)
                
        return filtered_logs

    def sort_logs(self, logs: List[Dict[str, str]], sort_by: str, reverse: bool = False) -> List[Dict[str, str]]:
        """Sort logs by specified field."""
        if sort_by not in self.csv_headers:
            print(f"Warning: Unknown sort field '{sort_by}'. Using 'timestamp'.", file=sys.stderr)
            sort_by = 'timestamp'
            
        return sorted(logs, key=lambda x: x.get(sort_by, ''), reverse=reverse)

    def paginate_logs(self, logs: List[Dict[str, str]], page: int, per_page: int) -> List[Dict[str, str]]:
        """Paginate log data."""
        start_idx = (page - 1) * per_page
        end_idx = start_idx + per_page
        return logs[start_idx:end_idx]

    def write_csv(self, logs: List[Dict[str, str]], output_file: str):
        """Write parsed logs to CSV file."""
        try:
            with open(output_file, 'w', newline='', encoding='utf-8') as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=self.csv_headers)
                writer.writeheader()
                for log_entry in logs:
                    writer.writerow(log_entry)
            print(f"Successfully wrote {len(logs)} log entries to {output_file}")
        except Exception as e:
            print(f"Error writing CSV file: {e}", file=sys.stderr)
            sys.exit(1)


class GitManager:
    """Manages Git operations for the parsed logs."""
    
    def __init__(self, repo_path: str):
        self.repo_path = repo_path
        
    def is_git_repo(self) -> bool:
        """Check if the current directory is a git repository."""
        try:
            subprocess.run(['git', 'rev-parse', '--git-dir'], 
                         cwd=self.repo_path, capture_output=True, check=True)
            return True
        except subprocess.CalledProcessError:
            return False
    
    def init_repo(self):
        """Initialize a new Git repository."""
        try:
            subprocess.run(['git', 'init'], cwd=self.repo_path, check=True)
            print(f"Initialized Git repository in {self.repo_path}")
        except subprocess.CalledProcessError as e:
            print(f"Error initializing Git repository: {e}", file=sys.stderr)
            sys.exit(1)
    
    def add_file(self, file_path: str):
        """Add file to Git staging area."""
        try:
            subprocess.run(['git', 'add', file_path], cwd=self.repo_path, check=True)
        except subprocess.CalledProcessError as e:
            print(f"Error adding file to Git: {e}", file=sys.stderr)
            sys.exit(1)
    
    def commit(self, message: str):
        """Commit staged changes."""
        try:
            subprocess.run(['git', 'commit', '-m', message], cwd=self.repo_path, check=True)
            print(f"Successfully committed with message: {message}")
        except subprocess.CalledProcessError as e:
            print(f"Error committing to Git: {e}", file=sys.stderr)
            sys.exit(1)
    
    def push(self, remote: str = 'origin', branch: str = 'main'):
        """Push commits to remote repository."""
        try:
            subprocess.run(['git', 'push', remote, branch], cwd=self.repo_path, check=True)
            print(f"Successfully pushed to {remote}/{branch}")
        except subprocess.CalledProcessError as e:
            print(f"Warning: Could not push to remote: {e}", file=sys.stderr)
            print("You may need to configure the remote repository first.")


def main():
    parser = argparse.ArgumentParser(description='Parse nginx logs and convert to CSV')
    parser.add_argument('input_file', 
                       help='Input nginx log file path (use "-" for stdin)')
    parser.add_argument('-o', '--output', 
                       default='nginx_logs.csv',
                       help='Output CSV file path (default: nginx_logs.csv)')
    parser.add_argument('--repo-path', 
                       default='.',
                       help='Git repository path (default: current directory)')
    parser.add_argument('--no-git', 
                       action='store_true',
                       help='Skip Git operations')
    parser.add_argument('--no-push', 
                       action='store_true',
                       help='Skip Git push (commit only)')
    parser.add_argument('--commit-message', 
                       default='Add nginx log analysis',
                       help='Git commit message')
    
    # Filtering and sorting options
    parser.add_argument('--filter-status', 
                       help='Filter by HTTP status code')
    parser.add_argument('--filter-ip', 
                       help='Filter by IP address')
    parser.add_argument('--filter-url', 
                       help='Filter by URL pattern')
    parser.add_argument('--sort-by', 
                       default='timestamp',
                       help='Sort by field (default: timestamp)')
    parser.add_argument('--reverse', 
                       action='store_true',
                       help='Sort in reverse order')
    parser.add_argument('--page', 
                       type=int, default=1,
                       help='Page number for pagination (default: 1)')
    parser.add_argument('--per-page', 
                       type=int, default=0,
                       help='Records per page (0 = no pagination)')
    
    args = parser.parse_args()
    
    # Initialize parser
    log_parser = NginxLogParser()
    
    # Parse log file
    print(f"Parsing log file: {args.input_file}")
    logs = log_parser.parse_log_file(args.input_file)
    
    if not logs:
        print("No logs were parsed successfully.", file=sys.stderr)
        sys.exit(1)
    
    # Apply filters
    filters = {}
    if args.filter_status:
        filters['status'] = args.filter_status
    if args.filter_ip:
        filters['remote_addr'] = args.filter_ip
    if args.filter_url:
        filters['url'] = args.filter_url
    
    if filters:
        logs = log_parser.filter_logs(logs, filters)
        print(f"After filtering: {len(logs)} log entries")
    
    # Sort logs
    logs = log_parser.sort_logs(logs, args.sort_by, args.reverse)
    
    # Paginate if requested
    if args.per_page > 0:
        logs = log_parser.paginate_logs(logs, args.page, args.per_page)
        print(f"Showing page {args.page}: {len(logs)} log entries")
    
    # Write CSV
    output_path = os.path.join(args.repo_path, args.output)
    log_parser.write_csv(logs, output_path)
    
    # Git operations
    if not args.no_git:
        git_manager = GitManager(args.repo_path)
        
        # Initialize repo if needed
        if not git_manager.is_git_repo():
            git_manager.init_repo()
        
        # Add and commit
        git_manager.add_file(args.output)
        
        # Create detailed commit message
        commit_msg = f"{args.commit_message}\n\nProcessed {len(logs)} log entries from {args.input_file}"
        if filters:
            commit_msg += f"\nFilters applied: {filters}"
        commit_msg += f"\nGenerated at: {datetime.now().isoformat()}"
        
        git_manager.commit(commit_msg)
        
        # Push if requested
        if not args.no_push:
            git_manager.push()
    
    print("Log parsing and processing completed successfully!")


if __name__ == '__main__':
    main()