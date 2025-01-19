import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import re
from datetime import datetime
import csv
import markdown
import webbrowser
import os
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
import numpy as np

class NetworkAnalyzer:
    def __init__(self, root):
        self.root = root
        self.root.title("Analyseur de fichier dump réseau")
        self.root.geometry("1200x800")
        
        # Configuration de l'interface
        self.setup_ui()
        
        # Variables pour stocker les données
        self.dump_data = []
        self.analyzed_data = {}
        
    def setup_ui(self):
        # Frame principale
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, columnspan=2, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Frame gauche pour les contrôles
        left_frame = ttk.Frame(main_frame)
        left_frame.grid(row=0, column=0, padx=5, sticky=(tk.N, tk.S))
        
        # Frame droite pour les graphiques
        right_frame = ttk.Frame(main_frame)
        right_frame.grid(row=0, column=1, padx=5, sticky=(tk.N, tk.S))
        
        # Boutons dans la frame gauche
        ttk.Button(left_frame, text="Sélectionner fichier dump", 
                  command=self.load_file).grid(row=0, column=0, pady=5)
        
        # Zone de résultats
        self.result_text = tk.Text(left_frame, height=20, width=50)
        self.result_text.grid(row=1, column=0, pady=5)
        
        # Boutons d'analyse
        ttk.Button(left_frame, text="Analyser", 
                  command=self.analyze_data).grid(row=2, column=0, pady=5)
        ttk.Button(left_frame, text="Exporter CSV", 
                  command=self.export_csv).grid(row=3, column=0, pady=5)
        ttk.Button(left_frame, text="Générer Rapport HTML", 
                  command=self.generate_html_report).grid(row=4, column=0, pady=5)
        
        # Frame pour les graphiques
        self.charts_frame = ttk.Frame(right_frame)
        self.charts_frame.grid(row=0, column=0, pady=5)

    def load_file(self):
        filename = filedialog.askopenfilename(
            filetypes=[("Fichiers texte", "*.txt"), ("Tous les fichiers", "*.*")])
        if filename:
            try:
                with open(filename, 'r') as file:
                    self.dump_data = file.readlines()
                self.result_text.insert(tk.END, f"Fichier chargé : {filename}\n")
            except Exception as e:
                messagebox.showerror("Erreur", f"Erreur lors de la lecture du fichier : {str(e)}")

    def analyze_data(self):
        if not self.dump_data:
            messagebox.showwarning("Attention", "Veuillez d'abord charger un fichier")
            return

        self.analyzed_data = {
            'connections': [],
            'ip_stats': {},
            'flags_stats': {},
            'attack_types': {},
            'packet_sizes': [],
            'hourly_distribution': {i: 0 for i in range(24)},
            'timestamps': []
        }

        for line in self.dump_data:
            if 'IP' in line and '.ssh' in line:
                # Extraction des informations
                timestamp_match = re.search(r'(\d{2}):(\d{2}):(\d{2}\.\d{6})', line)
                ip_match = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', line)
                flags_match = re.search(r'Flags \[(.*?)\]', line)
                length_match = re.search(r'length (\d+)', line)
                attack_type_match = re.search(r'Potentielle attaque (.*?)\.', line)

                if timestamp_match and ip_match:
                    hour = int(timestamp_match.group(1))
                    self.analyzed_data['hourly_distribution'][hour] += 1

                    connection = {
                        'timestamp': f"{timestamp_match.group(1)}:{timestamp_match.group(2)}:{timestamp_match.group(3)}",
                        'ip': ip_match.group(1),
                        'flags': flags_match.group(1) if flags_match else '',
                        'length': length_match.group(1) if length_match else '0',
                        'attack_type': attack_type_match.group(1) if attack_type_match else 'Unknown'
                    }
                    
                    self.analyzed_data['connections'].append(connection)
                    
                    # Mise à jour des statistiques
                    if connection['attack_type'] in self.analyzed_data['attack_types']:
                        self.analyzed_data['attack_types'][connection['attack_type']] += 1
                    else:
                        self.analyzed_data['attack_types'][connection['attack_type']] = 1
                    
                    if connection['length'] != '0':
                        self.analyzed_data['packet_sizes'].append(int(connection['length']))

        self.display_analysis()
        self.display_charts()

    def display_charts(self):
        # Suppression des anciens graphiques
        for widget in self.charts_frame.winfo_children():
            widget.destroy()
        
        # Création de la figure avec les sous-graphiques
        fig = plt.Figure(figsize=(12, 8))
        
        # Graphique en secteurs des types d'attaques
        ax1 = fig.add_subplot(221)
        attack_labels = list(self.analyzed_data['attack_types'].keys())
        attack_sizes = list(self.analyzed_data['attack_types'].values())
        ax1.pie(attack_sizes, labels=attack_labels, autopct='%1.1f%%')
        ax1.set_title('Distribution des types d\'attaques')
        
        # Graphique en secteurs de la distribution horaire
        ax2 = fig.add_subplot(222)
        hours = list(self.analyzed_data['hourly_distribution'].keys())
        counts = list(self.analyzed_data['hourly_distribution'].values())
        ax2.pie(counts, labels=[f"{h}h" for h in hours], autopct='%1.1f%%')
        ax2.set_title('Distribution horaire des attaques')
        
        # Histogramme des tailles de paquets
        ax3 = fig.add_subplot(223)
        ax3.hist(self.analyzed_data['packet_sizes'], bins=30)
        ax3.set_title('Distribution des tailles de paquets')
        ax3.set_xlabel('Taille (bytes)')
        ax3.set_ylabel('Fréquence')
        
        # Ajout du canvas à l'interface
        canvas = FigureCanvasTkAgg(fig, self.charts_frame)
        canvas.draw()
        canvas.get_tk_widget().grid(row=0, column=0)

    def display_analysis(self):
        self.result_text.delete(1.0, tk.END)
        
        # Affichage des statistiques détaillées
        self.result_text.insert(tk.END, "=== Analyse approfondie du trafic réseau ===\n\n")
        
        # Statistiques générales
        self.result_text.insert(tk.END, f"Nombre total de connexions : {len(self.analyzed_data['connections'])}\n")
        
        # Statistiques des paquets
        if self.analyzed_data['packet_sizes']:
            avg_size = sum(self.analyzed_data['packet_sizes']) / len(self.analyzed_data['packet_sizes'])
            max_size = max(self.analyzed_data['packet_sizes'])
            min_size = min(self.analyzed_data['packet_sizes'])
            self.result_text.insert(tk.END, f"\nStatistiques des paquets:\n")
            self.result_text.insert(tk.END, f"- Taille moyenne: {avg_size:.2f} bytes\n")
            self.result_text.insert(tk.END, f"- Taille maximale: {max_size} bytes\n")
            self.result_text.insert(tk.END, f"- Taille minimale: {min_size} bytes\n")
        
        # Top 5 des IPs les plus actives
        ip_counts = {}
        for conn in self.analyzed_data['connections']:
            ip_counts[conn['ip']] = ip_counts.get(conn['ip'], 0) + 1
        
        self.result_text.insert(tk.END, "\nTop 5 des IPs les plus actives:\n")
        for ip, count in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]:
            self.result_text.insert(tk.END, f"- {ip}: {count} connexions\n")

    def export_csv(self):
        if not self.analyzed_data:
            messagebox.showwarning("Attention", "Aucune donnée à exporter")
            return

        filename = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("Fichiers CSV", "*.csv"), ("Tous les fichiers", "*.*")]
        )
        
        if filename:
            with open(filename, 'w', newline='') as csvfile:
                writer = csv.DictWriter(csvfile, 
                    fieldnames=['timestamp', 'ip', 'flags', 'length', 'attack_type'])
                writer.writeheader()
                writer.writerows(self.analyzed_data['connections'])
            
            messagebox.showinfo("Succès", "Données exportées avec succès")

    def generate_html_report(self):
        if not self.analyzed_data:
            messagebox.showwarning("Attention", "Aucune donnée à analyser")
            return

        # Sauvegarde des graphiques pour le rapport
        plt.figure(figsize=(15, 10))
        
        # Graphique des types d'attaques
        plt.subplot(221)
        attack_labels = list(self.analyzed_data['attack_types'].keys())
        attack_sizes = list(self.analyzed_data['attack_types'].values())
        plt.pie(attack_sizes, labels=attack_labels, autopct='%1.1f%%')
        plt.title('Distribution des types d\'attaques')
        
        # Sauvegarde temporaire des graphiques
        temp_chart_path = "temp_charts.png"
        plt.savefig(temp_chart_path)
        plt.close()

        report_md = """
# Rapport d'analyse réseau approfondie

## Statistiques générales
- Nombre total de connexions: {total_conn}
- Période d'analyse: {time_range}

## Analyse des attaques
{attack_analysis}

## Distribution horaire
{hourly_distribution}

## Statistiques des paquets
- Taille moyenne: {avg_packet_size:.2f} bytes
- Taille maximale: {max_packet_size} bytes
- Taille minimale: {min_packet_size} bytes

## Top 5 des IPs les plus actives
{top_ips}

![Graphiques d'analyse]({chart_path})
        """.format(
            total_conn=len(self.analyzed_data['connections']),
            time_range=self.get_time_range(),
            attack_analysis=self.get_attack_analysis_md(),
            hourly_distribution=self.get_hourly_distribution_md(),
            avg_packet_size=np.mean(self.analyzed_data['packet_sizes']) if self.analyzed_data['packet_sizes'] else 0,
            max_packet_size=max(self.analyzed_data['packet_sizes']) if self.analyzed_data['packet_sizes'] else 0,
            min_packet_size=min(self.analyzed_data['packet_sizes']) if self.analyzed_data['packet_sizes'] else 0,
            top_ips=self.get_top_ips_md(),
            chart_path=temp_chart_path
        )

        # Conversion en HTML
        html_content = markdown.markdown(report_md)
        
        # Sauvegarde du rapport
        filename = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[("Fichiers HTML", "*.html"), ("Tous les fichiers", "*.*")]
        )
        
        if filename:
            with open(filename, 'w', encoding='utf-8') as f:
                f.write(html_content)
            webbrowser.open('file://' + os.path.realpath(filename))
            
            # Nettoyage du fichier temporaire des graphiques
            try:
                os.remove(temp_chart_path)
            except:
                pass

    def get_time_range(self):
        if not self.analyzed_data['connections']:
            return "Aucune donnée"
        
        timestamps = [conn['timestamp'] for conn in self.analyzed_data['connections']]
        return f"De {min(timestamps)} à {max(timestamps)}"

    def get_attack_analysis_md(self):
        attack_md = "\n### Distribution des types d'attaques\n"
        for attack_type, count in self.analyzed_data['attack_types'].items():
            percentage = (count / len(self.analyzed_data['connections'])) * 100
            attack_md += f"- {attack_type}: {count} occurrences ({percentage:.1f}%)\n"
        return attack_md

    def get_hourly_distribution_md(self):
        dist_md = "\n### Distribution horaire des attaques\n"
        for hour, count in self.analyzed_data['hourly_distribution'].items():
            if count > 0:
                percentage = (count / len(self.analyzed_data['connections'])) * 100
                dist_md += f"- {hour}h: {count} attaques ({percentage:.1f}%)\n"
        return dist_md

    def get_top_ips_md(self):
        ip_counts = {}
        for conn in self.analyzed_data['connections']:
            ip_counts[conn['ip']] = ip_counts.get(conn['ip'], 0) + 1
        
        top_ips_md = ""
        for ip, count in sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]:
            percentage = (count / len(self.analyzed_data['connections'])) * 100
            top_ips_md += f"- {ip}: {count} connexions ({percentage:.1f}%)\n"
        return top_ips_md

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkAnalyzer(root)
    root.mainloop()