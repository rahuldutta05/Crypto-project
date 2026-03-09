"""
Security Monitor - Logs ALL security events for penetration testing analysis
This module tracks:
- Connection attempts
- Authentication failures
- Replay attacks
- Timing attacks
- MITM attempts
- Unusual patterns
"""

import json
import os
from datetime import datetime, timedelta
from collections import defaultdict
import hashlib

from github_storage import load_json, save_json


class SecurityMonitor:
    def __init__(self, storage_file='security_events.json'):
        self.storage_file = storage_file
        self.events = self._load_events()
        self.on_event = None  # Callback function for real-time notifications
        self.attack_patterns = defaultdict(list)

    def _load_events(self):
        """Load security events from github_storage"""
        return load_json(self.storage_file, default=[])

    def _save_events(self):
        """Persist security events via github_storage"""
        save_json(self.storage_file, self.events)

    def log_event(self, event_type, details):
        """
        Log a security event

        Event types:
        - connection: New device connected
        - auth_success: Successful authentication
        - auth_failure: Failed authentication attempt
        - replay_attack_detected: Duplicate nonce found
        - timing_anomaly: Unusual response time pattern
        - unauthorized_attempt: Action without verification
        - key_expired: Message key destroyed
        - message_sent: Message transmitted
        - disconnection: Device disconnected
        - suspicious_pattern: Anomalous behavior detected
        - brute_force_detected: Multiple auth failures
        - mitm_detected: Safety number mismatch
        """

        event = {
            'id': hashlib.sha256(
                f"{event_type}{datetime.utcnow().isoformat()}Z".encode()
            ).hexdigest()[:16],
            'timestamp': datetime.utcnow().isoformat() + 'Z',
            'event_type': event_type,
            'severity': self._calculate_severity(event_type),
            'details': details,
            'analyzed': False
        }

        self.events.insert(0, event)
        self._save_events()

        # Notify via callback if registered
        if self.on_event:
            self.on_event(event)

        # Check for attack patterns (NO recursive log_event calls inside!)
        self._detect_patterns(event_type, details)

        # Real-time alerting for critical events
        if event['severity'] == 'critical':
            self._trigger_alert(event)

        return event

    def _calculate_severity(self, event_type):
        """Assign severity level to event"""
        severity_map = {
            'connection': 'info',
            'auth_success': 'info',
            'auth_failure': 'warning',
            'replay_attack_detected': 'critical',
            'timing_anomaly': 'warning',
            'unauthorized_attempt': 'high',
            'key_expired': 'info',
            'message_sent': 'info',
            'disconnection': 'info',
            'suspicious_pattern': 'high',
            'brute_force_detected': 'critical',
            'mitm_detected': 'critical',
            'error': 'warning'
        }
        return severity_map.get(event_type, 'info')

    def _detect_patterns(self, event_type, details):
        """
        Detect attack patterns from event sequences.
        NOTE: This method must NOT call self.log_event() to avoid infinite recursion.
        Instead it directly appends pattern events.
        """

        # Track IP-based patterns
        if 'ip' in details:
            ip = details['ip']
            self.attack_patterns[ip].append({
                'type': event_type,
                'timestamp': datetime.utcnow()
            })

            # Check for brute force (multiple auth failures from same IP)
            recent_failures = [
                e for e in self.attack_patterns[ip]
                if e['type'] == 'auth_failure'
                and (datetime.utcnow() - e['timestamp']) < timedelta(minutes=5)
            ]

            if len(recent_failures) >= 5:
                # Direct append to avoid recursion
                bf_event = {
                    'id': hashlib.sha256(
                        f"brute_force_detected{datetime.utcnow().isoformat()}Z".encode()
                    ).hexdigest()[:16],
                    'timestamp': datetime.utcnow().isoformat() + 'Z',
                    'event_type': 'brute_force_detected',
                    'severity': 'critical',
                    'details': {
                        'ip': ip,
                        'attempts': len(recent_failures),
                        'timeframe': '5 minutes'
                    },
                    'analyzed': False
                }
                self.events.append(bf_event)
                self._save_events()

                print(f"\n🚨 SECURITY ALERT: brute_force_detected")
                print(f"   Severity: critical")
                print(f"   IP: {ip}, Attempts: {len(recent_failures)}\n")

                # Clear pattern to avoid repeated alerts
                self.attack_patterns[ip] = []

        # Check for multiple replay attack pattern
        if event_type == 'replay_attack_detected':
            recent_replays = [
                e for e in self.events
                if e['event_type'] == 'replay_attack_detected'
                and (datetime.utcnow() - datetime.fromisoformat(e['timestamp'])) < timedelta(minutes=10)
            ]

            if len(recent_replays) >= 3:
                # Direct append to avoid recursion
                sp_event = {
                    'id': hashlib.sha256(
                        f"suspicious_pattern{datetime.utcnow().isoformat()}Z".encode()
                    ).hexdigest()[:16],
                    'timestamp': datetime.utcnow().isoformat() + 'Z',
                    'event_type': 'suspicious_pattern',
                    'severity': 'high',
                    'details': {
                        'pattern': 'multiple_replay_attempts',
                        'count': len(recent_replays),
                        'recommendation': 'Possible automated attack tool detected'
                    },
                    'analyzed': False
                }
                self.events.append(sp_event)
                self._save_events()

    def _trigger_alert(self, event):
        """Trigger real-time alert for critical events"""
        print(f"\n🚨 SECURITY ALERT: {event['event_type']}")
        print(f"   Severity: {event['severity']}")
        print(f"   Details: {event['details']}")
        print(f"   Time: {event['timestamp']}\n")

    def get_events(self, filters=None):
        """
        Get security events with optional filters

        Filters:
        - event_type: Filter by event type string
        - severity: Filter by severity level string
        - time_range: Tuple of (start_iso_str, end_iso_str)
        - ip: Filter by IP address
        """

        filtered_events = self.events

        if filters:
            if 'event_type' in filters:
                filtered_events = [
                    e for e in filtered_events
                    if e['event_type'] == filters['event_type']
                ]

            if 'severity' in filters:
                filtered_events = [
                    e for e in filtered_events
                    if e['severity'] == filters['severity']
                ]

            if 'time_range' in filters:
                start_str, end_str = filters['time_range']
                # Compare as strings (ISO format sorts lexicographically)
                filtered_events = [
                    e for e in filtered_events
                    if start_str <= e['timestamp'] <= end_str
                ]

            if 'ip' in filters:
                filtered_events = [
                    e for e in filtered_events
                    if e.get('details', {}).get('ip') == filters['ip']
                ]

        return filtered_events

    def get_attack_summary(self):
        """Generate summary of detected attacks"""

        attack_types = defaultdict(int)
        severity_counts = defaultdict(int)
        ip_attacks = defaultdict(int)

        for event in self.events:
            if event['severity'] in ['warning', 'high', 'critical']:
                attack_types[event['event_type']] += 1
                severity_counts[event['severity']] += 1

                ip = event.get('details', {}).get('ip')
                if ip:
                    ip_attacks[ip] += 1

        total_attacks = sum(attack_types.values())
        successful_attacks = attack_types.get('unauthorized_access', 0)

        return {
            'total_security_events': len(self.events),
            'total_attacks_detected': total_attacks,
            'successful_attacks': successful_attacks,
            'attack_success_rate': (successful_attacks / total_attacks * 100) if total_attacks > 0 else 0,
            'attacks_by_type': dict(attack_types),
            'severity_distribution': dict(severity_counts),
            'top_attacking_ips': dict(sorted(ip_attacks.items(), key=lambda x: x[1], reverse=True)[:10]),
            'most_common_attack': max(attack_types.items(), key=lambda x: x[1])[0] if attack_types else None
        }

    def get_timeline(self, hours=24):
        """Get attack timeline for the last N hours"""

        cutoff = datetime.utcnow() - timedelta(hours=hours)
        cutoff_str = cutoff.isoformat() + 'Z'
        recent_events = [
            e for e in self.events
            if e['timestamp'] >= cutoff_str
        ]

        timeline = defaultdict(lambda: {'total': 0, 'by_type': defaultdict(int)})

        for event in recent_events:
            timestamp = datetime.fromisoformat(event['timestamp'])
            hour_key = timestamp.strftime('%Y-%m-%d %H:00')

            timeline[hour_key]['total'] += 1
            timeline[hour_key]['by_type'][event['event_type']] += 1

        # Convert defaultdicts to plain dicts for JSON serialization
        result = {}
        for k, v in timeline.items():
            result[k] = {
                'total': v['total'],
                'by_type': dict(v['by_type'])
            }
        return result

    def clear_old_events(self, days=30):
        """Clear events older than N days"""

        cutoff = datetime.utcnow() - timedelta(days=days)
        cutoff_str = cutoff.isoformat() + 'Z'
        self.events = [
            e for e in self.events
            if e['timestamp'] >= cutoff_str
        ]
        self._save_events()

        return len(self.events)

    def export_for_analysis(self, format='json'):
        """Export events for external analysis tools"""

        if format == 'json':
            return json.dumps(self.events, indent=2)

        elif format == 'csv':
            import csv
            from io import StringIO

            output = StringIO()
            if self.events:
                fieldnames = ['timestamp', 'event_type', 'severity', 'id']
                writer = csv.DictWriter(output, fieldnames=fieldnames, extrasaction='ignore')
                writer.writeheader()

                for event in self.events:
                    row = {
                        'timestamp': event['timestamp'],
                        'event_type': event['event_type'],
                        'severity': event['severity'],
                        'id': event['id']
                    }
                    writer.writerow(row)

            return output.getvalue()

        return None

    def analyze_penetration_test(self):
        """
        Analyze results from penetration testing
        Returns detailed report of what was attempted and what succeeded
        """

        report = {
            'test_summary': self.get_attack_summary(),
            'timeline': self.get_timeline(),
            'vulnerabilities_found': [],
            'security_strengths': [],
            'recommendations': []
        }

        # Analyze authentication
        auth_failures = len([e for e in self.events if e['event_type'] == 'auth_failure'])
        auth_successes = len([e for e in self.events if e['event_type'] == 'auth_success'])

        if auth_failures > 0 and auth_successes == 0:
            report['security_strengths'].append(
                "✓ Zero-knowledge authentication: All unauthorized attempts blocked"
            )

        # Analyze replay attacks
        replay_attacks = len([e for e in self.events if e['event_type'] == 'replay_attack_detected'])

        if replay_attacks > 0:
            report['security_strengths'].append(
                f"✓ Replay protection: {replay_attacks} replay attacks detected and blocked"
            )

        # Analyze brute force
        brute_force = len([e for e in self.events if e['event_type'] == 'brute_force_detected'])

        if brute_force > 0:
            report['security_strengths'].append(
                f"✓ Brute force protection: {brute_force} brute force attempts detected"
            )

        # Check for any successful breaches
        unauthorized = len([e for e in self.events if e['event_type'] == 'unauthorized_access'])

        if unauthorized > 0:
            report['vulnerabilities_found'].append(
                f"⚠ {unauthorized} unauthorized access attempts succeeded - investigate immediately"
            )

        # Timing attack analysis
        timing_anomalies = len([e for e in self.events if e['event_type'] == 'timing_anomaly'])

        if timing_anomalies == 0:
            report['security_strengths'].append(
                "✓ No timing attack patterns detected - constant-time operations effective"
            )

        return report


# Global instance
security_monitor = SecurityMonitor()
