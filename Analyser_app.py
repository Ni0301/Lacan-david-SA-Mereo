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

class AnalyseurReseau:
    def __init__(self, root):
        self.root = root
        self.root.title("Analyseur de Trafic Réseau")
        self.root.geometry("1400x800")
        
        # Initialisation des données
        self.donnees_dump = []
        self.donnees_analysees = None
        
        # Configuration de l'interface
        self.creer_interface()
        
    def creer_interface(self):
        # Frame principale
        frame_principale = ttk.Frame(self.root, padding="10")
        frame_principale.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        self.root.grid_columnconfigure(0, weight=1)
        self.root.grid_rowconfigure(0, weight=1)
        
        # Panneau de contrôle gauche
        frame_gauche = ttk.Frame(frame_principale)
        frame_gauche.grid(row=0, column=0, padx=5, sticky=(tk.N, tk.S, tk.W, tk.E))
        
        # Boutons
        ttk.Button(frame_gauche, text="Charger Fichier Dump", 
                  command=self.charger_fichier).grid(row=0, column=0, pady=5, sticky=tk.W)
        ttk.Button(frame_gauche, text="Analyser les Données", 
                  command=self.analyser_donnees).grid(row=1, column=0, pady=5, sticky=tk.W)
        ttk.Button(frame_gauche, text="Exporter en CSV", 
                  command=self.exporter_csv).grid(row=2, column=0, pady=5, sticky=tk.W)
        ttk.Button(frame_gauche, text="Générer Rapport HTML", 
                  command=self.generer_rapport_html).grid(row=3, column=0, pady=5, sticky=tk.W)
        
        # Zone de texte pour les résultats
        self.texte_resultats = tk.Text(frame_gauche, height=20, width=50)
        self.texte_resultats.grid(row=4, column=0, pady=5, sticky=(tk.W, tk.E))
        
        # Frame droite pour les graphiques
        self.frame_graphiques = ttk.Frame(frame_principale)
        self.frame_graphiques.grid(row=0, column=1, padx=5, sticky=(tk.N, tk.S, tk.W, tk.E))
        frame_principale.grid_columnconfigure(1, weight=3)

    def parser_ligne_dump(self, ligne):
        """
        Parse une ligne du fichier dump et extrait les informations pertinentes
        """
        packet_info = {
            'timestamp': None,
            'ip': None,
            'length': 0,
            'flags': None
        }
        
        # Extraire le timestamp
        timestamp_match = re.search(r'(\d{2}):(\d{2}):(\d{2}\.\d+)', ligne)
        if timestamp_match:
            packet_info['timestamp'] = timestamp_match.group(0)
            
        # Extraire l'adresse IP
        ip_match = re.search(r'IP\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', ligne)
        if ip_match:
            packet_info['ip'] = ip_match.group(1)
            
        # Extraire la longueur
        length_match = re.search(r'length\s+(\d+)', ligne)
        if length_match:
            packet_info['length'] = int(length_match.group(1))
            
        # Extraire les flags TCP
        flags_match = re.search(r'Flags\s+\[([^\]]+)\]', ligne)
        if flags_match:
            packet_info['flags'] = flags_match.group(1)
            
        return packet_info

    def analyser_flags_tcp(self, flags):
        """
        Analyse les flags TCP et retourne la catégorie appropriée
        """
        if not flags:
            return 'Autres'
            
        # Convertir les flags en majuscules mais conserver les points
        flags = flags.upper()
        
        if 'S' in flags and '.' not in flags:
            return 'SYN'
        elif '.' in flags and 'P' in flags:
            return 'PUSH-ACK'
        elif 'S' in flags and '.' in flags:
            return 'SYN-ACK'
        elif '.' in flags:
            return 'ACK'
            
        return 'Autres'
        
    def analyser_donnees(self):
        if not self.donnees_dump:
            messagebox.showwarning("Attention", "Veuillez d'abord charger un fichier")
            return
            
        self.donnees_analysees = {
            'connexions': [],
            'tailles_paquets': [],
            'distribution_horaire': [0] * 24,
            'flags_stats': {
                'SYN': 0,
                'ACK': 0,
                'PUSH-ACK': 0,
                'SYN-ACK': 0,
                'Autres': 0
            }
        }
        
        for ligne in self.donnees_dump:
            packet_info = self.parser_ligne_dump(ligne)
            
            if packet_info['ip']:  # Si la ligne contient des informations valides
                # Ajouter la connexion
                self.donnees_analysees['connexions'].append(packet_info)
                
                # Traiter la taille du paquet
                if packet_info['length'] > 0:
                    self.donnees_analysees['tailles_paquets'].append(packet_info['length'])
                
                # Traiter l'heure
                if packet_info['timestamp']:
                    heure = int(packet_info['timestamp'].split(':')[0])
                    self.donnees_analysees['distribution_horaire'][heure] += 1
                
                # Analyser les flags TCP
                if packet_info['flags']:
                    flag_type = self.analyser_flags_tcp(packet_info['flags'])
                    self.donnees_analysees['flags_stats'][flag_type] += 1
        
        self.afficher_analyse()
        self.afficher_graphiques()

    def afficher_graphiques(self):
        # Nettoyage des graphiques précédents
        for widget in self.frame_graphiques.winfo_children():
            widget.destroy()
            
        # Création de la figure avec sous-graphiques
        fig = plt.Figure(figsize=(15, 5))
        
        # Distribution des Flags TCP (à gauche)
        ax1 = fig.add_subplot(131)
        if self.donnees_analysees.get('flags_stats'):
            labels = []
            sizes = []
            colors = {
                'SYN': '#2ecc71',      # Vert
                'ACK': '#e67e22',      # Orange
                'PUSH-ACK': '#3498db', # Bleu
                'SYN-ACK': '#9b59b6',  # Violet
                'Autres': '#95a5a6'    # Gris
            }
            
            # Calculer le total pour les pourcentages
            total_flags = sum(self.donnees_analysees['flags_stats'].values())
            
            # Préparer les données pour le camembert
            for flag_type, count in self.donnees_analysees['flags_stats'].items():
                if count > 0:
                    labels.append(flag_type)
                    sizes.append(count)
                    
            if sizes:
                wedges, texts, autotexts = ax1.pie(sizes,
                                                  labels=labels,
                                                  colors=[colors[label] for label in labels],
                                                  autopct='%1.1f%%',
                                                  startangle=90)
                plt.setp(autotexts, size=8)
                plt.setp(texts, size=8)
            
            ax1.set_title('Distribution des Flags TCP')
        
        # Distribution Horaire (au centre)
        ax2 = fig.add_subplot(132)
        heures = range(24)
        bars = ax2.bar(heures, self.donnees_analysees['distribution_horaire'], color='#3498db')
        ax2.set_title('Distribution Horaire des Connexions')
        ax2.set_xlabel('Heure')
        ax2.set_ylabel('Nombre de Connexions')
        ax2.grid(True, linestyle='--', alpha=0.7)
        ax2.set_xlim(-1, 24)
        
        # Distribution des Tailles de Paquets (à droite)
        ax3 = fig.add_subplot(133)
        if self.donnees_analysees['tailles_paquets']:
            n_bins = min(30, len(set(self.donnees_analysees['tailles_paquets'])))
            ax3.hist(self.donnees_analysees['tailles_paquets'],
                    bins=n_bins,
                    color='#3498db',
                    edgecolor='black')
            ax3.set_title('Distribution des Tailles de Paquets')
            ax3.set_xlabel('Taille (octets)')
            ax3.set_ylabel('Fréquence')
            ax3.grid(True, linestyle='--', alpha=0.7)
            ax3.set_axisbelow(True)
        
        fig.tight_layout()
        canvas = FigureCanvasTkAgg(fig, self.frame_graphiques)
        canvas.draw()
        canvas.get_tk_widget().pack(side=tk.TOP, fill=tk.BOTH, expand=True)

    def charger_fichier(self):
        fichier = filedialog.askopenfilename(
            filetypes=[("Fichiers texte", "*.txt"), ("Fichiers log", "*.log"), ("Tous les fichiers", "*.*")]
        )
        if fichier:
            try:
                with open(fichier, 'r') as f:
                    self.donnees_dump = f.readlines()
                self.texte_resultats.delete(1.0, tk.END)
                self.texte_resultats.insert(tk.END, f"Fichier chargé : {fichier}\n")
            except Exception as e:
                messagebox.showerror("Erreur", f"Erreur lors de la lecture du fichier : {str(e)}")

    def exporter_csv(self):
        if not self.donnees_analysees:
            messagebox.showwarning("Attention", "Pas de données à exporter")
            return
            
        fichier = filedialog.asksaveasfilename(
            defaultextension=".csv",
            filetypes=[("Fichiers CSV", "*.csv"), ("Tous les fichiers", "*.*")]
        )
        
        if fichier:
            with open(fichier, 'w', newline='') as csvfile:
                writer = csv.DictWriter(csvfile, 
                    fieldnames=['timestamp', 'ip', 'length', 'flags'])
                writer.writeheader()
                writer.writerows(self.donnees_analysees['connexions'])
            messagebox.showinfo("Succès", "Données exportées avec succès")

    def generer_rapport_html(self):
        if not self.donnees_analysees:
            messagebox.showwarning("Attention", "Pas de données pour générer le rapport")
            return
            
        fichier = filedialog.asksaveasfilename(
            defaultextension=".html",
            filetypes=[("Fichiers HTML", "*.html"), ("Tous les fichiers", "*.*")]
        )
        
        if fichier:
            total_connexions = len(self.donnees_analysees['connexions'])
            taille_moy = sum(self.donnees_analysees['tailles_paquets']) / len(self.donnees_analysees['tailles_paquets']) if self.donnees_analysees['tailles_paquets'] else 0
            
            contenu_html = f"""
            <html>
            <head>
                <title>Rapport d'Analyse Réseau</title>
                <style>
                    body {{ font-family: Arial, sans-serif; margin: 40px; }}
                    h1 {{ color: #2c3e50; }}
                    h2 {{ color: #34495e; margin-top: 30px; }}
                    .stats {{ margin: 20px 0; }}
                    .distribution {{ margin: 20px 0; }}
                    table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
                    th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                    th {{ background-color: #f5f6fa; }}
                    .flag-stats {{ display: flex; flex-wrap: wrap; gap: 20px; }}
                    .flag-item {{ 
                        background: #f8f9fa;
                        padding: 15px;
                        border-radius: 5px;
                        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
                    }}
                </style>
            </head>
            <body>
                <h1>Rapport d'Analyse Réseau</h1>
                <div class="stats">
                    <h2>Statistiques Générales</h2>
                    <table>
                        <tr>
                            <td><strong>Connexions Totales</strong></td>
                            <td>{total_connexions}</td>
                        </tr>
                        <tr>
                            <td><strong>Taille Moyenne des Paquets</strong></td>
                            <td>{taille_moy:.2f} octets</td>
                        </tr>
                    </table>
                    
                    <h2>Distribution des Flags TCP</h2>
                    <div class="flag-stats">
                        {"".join(f'<div class="flag-item"><h3>{flag_type}</h3><p>{compte} paquets</p><p>{(compte/total_connexions)*100:.1f}%</p></div>' 
                                 for flag_type, compte in self.donnees_analysees['flags_stats'].items() if compte > 0)}
                    </div>
                    
                    <h2>Détails des Paquets</h2>
                    <table>
                        <tr>
                            <th>Type</th>
                            <th>Nombre</th>
                            <th>Pourcentage</th>
                        </tr>
                        {"".join(f'<tr><td>{flag_type}</td><td>{compte}</td><td>{(compte/total_connexions)*100:.1f}%</td></tr>' 
                                 for flag_type, compte in self.donnees_analysees['flags_stats'].items() if compte > 0)}
                    </table>
                </div>
                
                <div class="distribution">
                    <h2>Distribution Horaire</h2>
                    <table>
                        <tr>
                            <th>Heure</th>
                            <th>Nombre de Connexions</th>
                        </tr>
                        {"".join(f'<tr><td>{heure:02d}h</td><td>{count}</td></tr>' 
                                 for heure, count in enumerate(self.donnees_analysees['distribution_horaire']) if count > 0)}
                    </table>
                </div>
            </body>
            </html>
            """
            
            with open(fichier, 'w', encoding='utf-8') as f:
                f.write(contenu_html)
            webbrowser.open('file://' + os.path.realpath(fichier))

    def afficher_analyse(self):
        """Affiche les résultats de l'analyse dans la zone de texte"""
        self.texte_resultats.delete(1.0, tk.END)
        
        # En-tête
        self.texte_resultats.insert(tk.END, "=== Résultats de l'Analyse Réseau ===\n\n")
        
        # Statistiques générales
        total_connexions = len(self.donnees_analysees['connexions'])
        self.texte_resultats.insert(tk.END, f"Connexions Totales : {total_connexions}\n\n")
        
        # Statistiques des paquets
        if self.donnees_analysees['tailles_paquets']:
            taille_moy = sum(self.donnees_analysees['tailles_paquets']) / len(self.donnees_analysees['tailles_paquets'])
            taille_max = max(self.donnees_analysees['tailles_paquets'])
            taille_min = min(self.donnees_analysees['tailles_paquets'])
            
            self.texte_resultats.insert(tk.END, "Statistiques des Paquets :\n")
            self.texte_resultats.insert(tk.END, f"- Taille Moyenne : {taille_moy:.2f} octets\n")
            self.texte_resultats.insert(tk.END, f"- Taille Maximum : {taille_max} octets\n")
            self.texte_resultats.insert(tk.END, f"- Taille Minimum : {taille_min} octets\n\n")
        
        # Distribution des flags TCP
        self.texte_resultats.insert(tk.END, "Distribution des Flags TCP :\n")
        for flag_type, compte in self.donnees_analysees['flags_stats'].items():
            if compte > 0:
                pourcentage = (compte / total_connexions) * 100
                self.texte_resultats.insert(tk.END, f"- {flag_type}: {compte} ({pourcentage:.1f}%)\n")
        
        self.texte_resultats.see(1.0)  # Scroll to top

    def _setup_styles(self):
        """Configure les styles de l'interface"""
        style = ttk.Style()
        
        # Configuration générale
        style.configure(".", font=('Helvetica', 10))
        
        # Style des boutons
        style.configure("TButton", padding=6, relief="flat", background="#2980b9")
        
        # Style des frames
        style.configure("TFrame", background="#f5f6fa")
        
        # Style des labels
        style.configure("TLabel", padding=6, background="#f5f6fa")

if __name__ == "__main__":
    try:
        root = tk.Tk()
        root.title("Analyseur de Trafic Réseau")
        
        # Définir l'icône si disponible
        try:
            root.iconbitmap("icon.ico")
        except:
            pass
            
        # Configurer le style de la fenêtre
        root.configure(bg='#f5f6fa')
        
        # Créer et lancer l'application
        app = AnalyseurReseau(root)
        
        # Centrer la fenêtre
        window_width = 1400
        window_height = 800
        screen_width = root.winfo_screenwidth()
        screen_height = root.winfo_screenheight()
        center_x = int(screen_width/2 - window_width/2)
        center_y = int(screen_height/2 - window_height/2)
        root.geometry(f'{window_width}x{window_height}+{center_x}+{center_y}')
        
        # Lancer la boucle principale
        root.mainloop()
        
    except Exception as e:
        messagebox.showerror("Erreur", f"Une erreur est survenue lors du lancement de l'application : {str(e)}")
        raise