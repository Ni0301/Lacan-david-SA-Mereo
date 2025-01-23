import pandas as pd
import re
from datetime import datetime
import matplotlib.pyplot as plt
import seaborn as sns
import base64
from io import BytesIO
import webbrowser
import os
from collections import Counter

def analyze_tcpdump(file_path):
    try:
        with open(file_path, 'r', encoding='utf-8') as file:
            lines = file.readlines()
        
        protocols, ip_src, ip_dst, packets = [], [], [], []
        tcp_flags = {'SYN': 0, 'PUSH-ACK': 0, 'SYN-ACK': 0, 'ACK': 0}
        ip_pattern = r'IP (?:([0-9]+(?:\.[0-9]+){3})\.([0-9]+))? ?([0-9]+(?:\.[0-9]+){3})?'
        packet_pattern = re.compile(r'(\d{2}:\d{2}:\d{2}\.\d{6})\s+IP\s+(.*?)\s+>\s+(.*?):\s+(.*)')
        
        for line in lines:
            match = packet_pattern.match(line)
            if match:
                timestamp, src, dst, info = match.groups()
                packets.append({'timestamp': timestamp, 'source': src, 'destination': dst, 'info': info})
                
                if 'Flags [S]' in info:
                    tcp_flags['SYN'] += 1
                elif 'Flags [P.]' in info:
                    tcp_flags['PUSH-ACK'] += 1
                elif 'Flags [S.]' in info:
                    tcp_flags['SYN-ACK'] += 1
                elif 'Flags [A]' in info:
                    tcp_flags['ACK'] += 1
            
            if 'IP' in line:
                parts = line.split('>')
                if len(parts) > 1:
                    proto = parts[1].strip().split(':')[0].strip().split('.')[-1]
                    protocols.append(proto)
                
                ip_match = re.search(ip_pattern, line)
                if ip_match:
                    if ip_match.group(1):
                        ip_src.append(ip_match.group(1))
                    if ip_match.group(3):
                        ip_dst.append(ip_match.group(3))

        protocol_counts = Counter(protocols)
        ip_counts = Counter(ip_src)
        
        stats = {
            'network_stats': {
                'packets_analyzed': len(packets),
                'packets_rate': f"{len(packets)/60:.1f}/s",
                'anomalies': {
                    'count': sum(1 for p in packets if 'Flags [S]' in p['info']),
                    'percentage': f"{sum(1 for p in packets if 'Flags [S]' in p['info'])/len(packets)*100:.1f}%"
                },
                'suspicious_ips': {
                    'count': len(set(p['source'] for p in packets if 'Flags [S]' in p['info'])),
                    'percentage': f"{len(set(p['source'] for p in packets if 'Flags [S]' in p['info']))/len(set(p['source'] for p in packets))*100:.1f}%"
                },
                'services': {
                    'count': len(set(p['destination'].split('.')[-1] for p in packets if '.' in p['destination'])),
                    'percentage': '-'
                },
                'tcp_flags': tcp_flags
            },
            'protocol_distribution': protocol_counts,
            'detected_anomalies': []
        }

        threshold = len(packets) / len(set(p['source'] for p in packets)) * 2
        for src, count in ip_counts.items():
            if count > threshold:
                stats['detected_anomalies'].append({
                    'timestamp': packets[0]['timestamp'] if packets else '',
                    'ip_source': src,
                    'type': 'Traffic Burst',
                    'details': f'Pic de trafic: {count/60:.2f} paquets/s',
                    'level': 'HIGH'
                })

        return stats

    except Exception as e:
        print(f"Erreur lors de l'analyse du fichier: {str(e)}")
        return None

def generate_flags_chart(tcp_flags):
    plt.figure(figsize=(12, 8))
    sns.set_style("whitegrid")

    flags, counts = zip(*tcp_flags.items())
    sns.barplot(x=list(flags), y=list(counts), palette='Blues_d')

    plt.xlabel('TCP Flags', fontsize=12)
    plt.ylabel('Count', fontsize=12)
    plt.title('TCP Flags Distribution', fontsize=14)
    plt.xticks(rotation=45, ha='right')
    plt.tight_layout()
    
    return plot_to_base64()

def plot_to_base64():
    buffer = BytesIO()
    plt.savefig(buffer, format='png')
    buffer.seek(0)
    image_png = buffer.getvalue()
    buffer.close()
    plt.close()
    return base64.b64encode(image_png).decode()

def generate_html_report(stats):
    html_content = f"""
    <!DOCTYPE html>
    <html lang="fr">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>Rapport d'analyse</title>
        <style>
            body {{
                font-family: Arial, sans-serif;
                line-height: 1.6;
                color: #333;
                background-color: #f8f9fa;
                padding: 2rem;
            }}
            .container {{
                max-width: 1200px;
                margin: 0 auto;
                background-color: #fff;
                padding: 2rem;
                box-shadow: 0 1px 3px rgba(0,0,0,0.1);
            }}
            .stats-overview {{
                display: grid;
                grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
                gap: 1.5rem;
                margin-bottom: 2rem;
            }}
            .stat-card {{
                background-color: #fff;
                padding: 1.5rem;
                border: 1px solid #dee2e6;
            }}
            .value {{
                font-size: 1.8rem;
                font-weight: bold;
                color: #333;
            }}
            .subvalue {{
                color: #6c757d;
                font-size: 0.9rem;
            }}
            .anomalies-table {{
                width: 100%;
                border-collapse: collapse;
                margin-top: 1rem;
            }}
            .anomalies-table th, .anomalies-table td {{
                padding: 0.75rem;
                border: 1px solid #dee2e6;
            }}
            .anomalies-table th {{
                background-color: #f8f9fa;
                font-weight: 600;
            }}
            .level-high {{
                color: #dc3545;
                font-weight: 500;
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <h1>Rapport d'analyse du trafic réseau</h1>
            
            <div class="stats-overview">
                <div class="stat-card">
                    <h3>Paquets analysés</h3>
                    <div class="value">{stats['network_stats']['packets_analyzed']}</div>
                    <div class="subvalue">{stats['network_stats']['packets_rate']}</div>
                </div>
                
                <div class="stat-card">
                    <h3>Anomalies</h3>
                    <div class="value">{stats['network_stats']['anomalies']['count']}</div>
                    <div class="subvalue">{stats['network_stats']['anomalies']['percentage']}</div>
                </div>
                
                <div class="stat-card">
                    <h3>IPs suspectes</h3>
                    <div class="value">{stats['network_stats']['suspicious_ips']['count']}</div>
                    <div class="subvalue">{stats['network_stats']['suspicious_ips']['percentage']}</div>
                </div>
                
                <div class="stat-card">
                    <h3>Services</h3>
                    <div class="value">{stats['network_stats']['services']['count']}</div>
                    <div class="subvalue">{stats['network_stats']['services']['percentage']}</div>
                </div>
            </div>

            <div class="charts-section">
                <img src="data:image/png;base64,{generate_flags_chart(stats['network_stats']['tcp_flags'])}" 
                     alt="TCP Flags Distribution" style="width:100%">
            </div>
            
            <div class="stats-section">
                <h2>Anomalies détectées</h2>
                <table class="anomalies-table">
                    <tr>
                        <th>Timestamp</th>
                        <th>IP Source</th>
                        <th>Type</th>
                        <th>Détails</th>
                        <th>Niveau</th>
                    </tr>
    """
    
    for anomaly in stats['detected_anomalies']:
        html_content += f"""
                    <tr>
                        <td>{anomaly['timestamp']}</td>
                        <td>{anomaly['ip_source']}</td>
                        <td>{anomaly['type']}</td>
                        <td>{anomaly['details']}</td>
                        <td class="level-high">{anomaly['level']}</td>
                    </tr>
        """

    html_content += """
                </table>
            </div>
        </div>
    </body>
    </html>
    """

    with open('analyse.html', 'w', encoding='utf-8') as f:
        f.write(html_content)
    
    webbrowser.open('file://' + os.path.realpath('analyse.html'))

def main():
    file_path = 'tcp.txt'
    stats = analyze_tcpdump(file_path)
    if stats:
        generate_html_report(stats)
    else:
        print("Erreur lors de l'analyse des données")

if __name__ == "__main__":
    main()