"""
Admin Routes - Security Dashboard for Penetration Testing Analysis
View all attack attempts, their success/failure, and security metrics
"""

from flask import Blueprint, request, jsonify
import json
from datetime import datetime, timedelta, timezone
from monitoring.security_monitor import security_monitor

admin_bp = Blueprint('admin', __name__)


@admin_bp.route('/security-events', methods=['GET'])
def get_security_events():
    """
    Get all security events with optional filtering

    Query params:
    - event_type: Filter by type
    - severity: Filter by severity (info/warning/high/critical)
    - hours: Get events from last N hours
    - ip: Filter by IP address
    """
    try:
        filters = {}

        if request.args.get('event_type'):
            filters['event_type'] = request.args.get('event_type')

        if request.args.get('severity'):
            filters['severity'] = request.args.get('severity')

        if request.args.get('hours'):
            hours = int(request.args.get('hours'))
            end_time = datetime.now(timezone.utc)
            start_time = end_time - timedelta(hours=hours)
            # Use ISO strings — get_events does string comparison
            filters['time_range'] = (start_time.isoformat().replace('+00:00', 'Z'), end_time.isoformat().replace('+00:00', 'Z'))

        if request.args.get('ip'):
            filters['ip'] = request.args.get('ip')

        events = security_monitor.get_events(filters if filters else None)

        return jsonify({
            'events': events,
            'total': len(events),
            'filters_applied': list(filters.keys())
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 400


@admin_bp.route('/attack-summary', methods=['GET'])
def get_attack_summary():
    """
    Get comprehensive summary of all attacks.
    Shows what succeeded vs what failed.
    """
    try:
        summary = security_monitor.get_attack_summary()

        return jsonify({
            'summary': summary,
            'generated_at': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
            'interpretation': {
                'total_attacks': summary['total_attacks_detected'],
                'success_rate': f"{summary['attack_success_rate']:.2f}%",
                'most_common': summary['most_common_attack'],
                'verdict': 'SECURE' if summary['attack_success_rate'] < 1 else 'VULNERABLE'
            }
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 400


@admin_bp.route('/attack-timeline', methods=['GET'])
def get_attack_timeline():
    """
    Get timeline of attacks over last N hours
    """
    try:
        hours = int(request.args.get('hours', 24))
        timeline = security_monitor.get_timeline(hours)

        return jsonify({
            'timeline': timeline,
            'period': f'Last {hours} hours',
            'generated_at': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 400


@admin_bp.route('/penetration-test-report', methods=['GET'])
def get_penetration_test_report():
    """
    Generate comprehensive penetration testing report
    """
    try:
        report = security_monitor.analyze_penetration_test()

        return jsonify({
            'report': report,
            'generated_at': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
            'recommendation': generate_recommendation(report)
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 400


@admin_bp.route('/export-events', methods=['GET'])
def export_events():
    """
    Export security events for external analysis (JSON or CSV)
    """
    try:
        fmt = request.args.get('format', 'json')

        if fmt == 'json':
            data = security_monitor.export_for_analysis('json')
            return data, 200, {
                'Content-Type': 'application/json',
                'Content-Disposition': (
                    f'attachment; filename=security_events_'
                    f'{datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")}Z.json'
                )
            }

        elif fmt == 'csv':
            data = security_monitor.export_for_analysis('csv')
            return data, 200, {
                'Content-Type': 'text/csv',
                'Content-Disposition': (
                    f'attachment; filename=security_events_'
                    f'{datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")}Z.csv'
                )
            }

        else:
            return jsonify({'error': 'Invalid format. Use json or csv'}), 400

    except Exception as e:
        return jsonify({'error': str(e)}), 400


@admin_bp.route('/attack-types', methods=['GET'])
def get_attack_types():
    """Get breakdown of attack types detected"""
    try:
        events = security_monitor.get_events()

        attack_types = {
            'replay_attacks': 0,
            'brute_force': 0,
            'mitm_attempts': 0,
            'unauthorized_access': 0,
            'timing_attacks': 0,
            'other': 0
        }

        for event in events:
            if event['event_type'] == 'replay_attack_detected':
                attack_types['replay_attacks'] += 1
            elif event['event_type'] == 'brute_force_detected':
                attack_types['brute_force'] += 1
            elif event['event_type'] == 'mitm_detected':
                attack_types['mitm_attempts'] += 1
            elif event['event_type'] == 'unauthorized_attempt':
                attack_types['unauthorized_access'] += 1
            elif event['event_type'] == 'timing_anomaly':
                attack_types['timing_attacks'] += 1
            elif event['severity'] in ['warning', 'high', 'critical']:
                attack_types['other'] += 1

        return jsonify({
            'attack_types': attack_types,
            'total_attacks': sum(attack_types.values())
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 400


@admin_bp.route('/system-stats', methods=['GET'])
def get_system_stats():
    """Get overall system statistics"""
    try:
        def _load(path, default=None):
            default = default if default is not None else {}
            try:
                with open(path, 'r') as f:
                    return json.load(f)
            except Exception:
                return default

        messages = _load('storage/messages.json')
        devices = _load('storage/devices.json')
        proofs = _load('storage/proof.json')
        nonces = _load('storage/nonces.json', [])

        active_messages = sum(1 for m in messages.values() if m.get('status') == 'active')
        expired_messages = sum(1 for m in messages.values() if m.get('status') == 'expired')
        paired_devices = sum(1 for d in devices.values() if d.get('status') == 'paired')

        attack_summary = security_monitor.get_attack_summary()

        return jsonify({
            'timestamp': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z'),
            'core_principles': {
                'anonymous_verifiable': {
                    'total_devices': len(devices),
                    'paired_devices': paired_devices,
                    'verification_method': 'zero_knowledge_proof'
                },
                'proof_of_existence': {
                    'total_proofs': len(proofs),
                    'messages_verified': len(messages),
                    'content_stored': False
                },
                'cryptographic_expiry': {
                    'active_messages': active_messages,
                    'expired_messages': expired_messages,
                    'keys_destroyed': expired_messages,
                    'recovery_possible': False
                }
            },
            'security': {
                'total_attacks_detected': attack_summary['total_attacks_detected'],
                'successful_attacks': attack_summary['successful_attacks'],
                'attack_success_rate': attack_summary['attack_success_rate'],
                'nonces_tracked': len(nonces),
                'replay_attacks_blocked': attack_summary['attacks_by_type'].get('replay_attack_detected', 0)
            },
            'performance': {
                'total_messages_sent': len(messages),
                'total_proofs_created': len(proofs),
                'unique_nonces': len(nonces)
            }
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 400


@admin_bp.route('/threat-assessment', methods=['GET'])
def get_threat_assessment():
    """Assess current threat level based on recent activity"""
    try:
        cutoff = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat().replace('+00:00', 'Z')
        events = security_monitor.get_events()
        recent_events = [e for e in events if e['timestamp'] >= cutoff]

        critical_events = [e for e in recent_events if e['severity'] == 'critical']
        high_events = [e for e in recent_events if e['severity'] == 'high']

        if len(critical_events) > 5:
            threat_level = 'CRITICAL'
            color = '#ff0000'
        elif len(critical_events) > 0 or len(high_events) > 10:
            threat_level = 'HIGH'
            color = '#ff8800'
        elif len(high_events) > 0:
            threat_level = 'ELEVATED'
            color = '#ffaa00'
        else:
            threat_level = 'LOW'
            color = '#00ff00'

        return jsonify({
            'threat_level': threat_level,
            'color': color,
            'recent_activity': {
                'critical_events': len(critical_events),
                'high_events': len(high_events),
                'total_events': len(recent_events),
                'timeframe': 'Last 1 hour'
            },
            'recommendation': get_threat_recommendation(threat_level)
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 400


@admin_bp.route('/clear-old-events', methods=['POST'])
def clear_old_events():
    """Clear security events older than N days"""
    try:
        days = int(request.json.get('days', 30))
        remaining = security_monitor.clear_old_events(days)

        return jsonify({
            'success': True,
            'remaining_events': remaining,
            'message': f'Cleared events older than {days} days'
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 400


def generate_recommendation(report):
    """Generate security recommendations based on report"""
    recommendations = []

    if report['test_summary']['successful_attacks'] > 0:
        recommendations.append('🚨 CRITICAL: Successful attacks detected - immediate action required')

    if report['test_summary']['attack_success_rate'] < 1:
        recommendations.append('✓ GOOD: Attack success rate below 1% - security measures effective')

    if 'replay_attack_detected' in report['test_summary']['attacks_by_type']:
        count = report['test_summary']['attacks_by_type']['replay_attack_detected']
        recommendations.append(f'✓ GOOD: {count} replay attacks blocked by nonce tracking')

    if len(report['security_strengths']) >= 3:
        recommendations.append('✓ EXCELLENT: Multiple security layers functioning correctly')

    if len(report['vulnerabilities_found']) == 0:
        recommendations.append('✓ NO VULNERABILITIES: No security weaknesses detected')
    else:
        recommendations.append(
            f'⚠ ACTION NEEDED: {len(report["vulnerabilities_found"])} vulnerabilities require attention'
        )

    return recommendations


def get_threat_recommendation(threat_level):
    """Get recommendations based on threat level"""
    recommendations = {
        'CRITICAL': '🚨 Immediate investigation required. Possible active attack in progress.',
        'HIGH': '⚠️ Enhanced monitoring recommended. Review recent security events.',
        'ELEVATED': '📊 Monitor situation. Unusual activity detected.',
        'LOW': '✓ System operating normally. Routine monitoring sufficient.'
    }
    return recommendations.get(threat_level, 'Unknown threat level')


@admin_bp.route('/simulate-attack', methods=['POST'])
def simulate_attack():
    """
    Simulate an attack event for demo/testing purposes.
    Logs a clearly-labelled SIMULATED event so the dashboard
    shows it in Recent Security Events and Attacks by Type.

    Body: { "attack_type": "replay_attack_detected" }
    Supported types:
      replay_attack_detected | unauthorized_attempt | auth_failure |
      brute_force_detected   | suspicious_pattern   | mitm_detected
    """
    ALLOWED_TYPES = {
        'replay_attack_detected',
        'unauthorized_attempt',
        'auth_failure',
        'brute_force_detected',
        'suspicious_pattern',
        'mitm_detected',
    }

    try:
        data = request.json or {}
        attack_type = data.get('attack_type', 'suspicious_pattern')

        if attack_type not in ALLOWED_TYPES:
            return jsonify({'error': f'Unknown attack_type. Allowed: {sorted(ALLOWED_TYPES)}'}), 400

        event = security_monitor.log_event(attack_type, {
            'simulated': True,
            'source': 'admin_simulation',
            'note': f'Simulated {attack_type} via Admin Dashboard',
            'ip': request.remote_addr,
            'timestamp': datetime.now(timezone.utc).isoformat().replace('+00:00', 'Z')
        })

        return jsonify({
            'success': True,
            'event_id': event['id'],
            'attack_type': attack_type,
            'severity': event['severity'],
            'message': f'Simulated {attack_type} event logged successfully'
        })

    except Exception as e:
        return jsonify({'error': str(e)}), 400

