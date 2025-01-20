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

    def analyser_donnees(self):
        if not self.donnees_dump:
            messagebox.showwarning("Attention", "Veuillez d'abord charger un fichier")
            return
            
        self.donnees_analysees = {
            'connexions': [],
            'tailles_paquets': [],
            'distribution_horaire': [0] * 24,
            'types_attaques': {
                'Scan SYN': 0,
                'Connexion SSH Établie': 0,
                'Tentative de Reset': 0,
                'Scan FIN': 0,
                'Scan complet': 0,
                'Autre': 0
            },
            'flags_stats': {}
        }
        
        for ligne in self.donnees_dump:
            if 'IP' in ligne and '.ssh' in ligne:
                # Extraction des informations avec regex
                timestamp = re.search(r'(\d{2}):(\d{2}):(\d{2}\.\d{6})', ligne)
                ip = re.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', ligne)
                longueur = re.search(r'length (\d+)', ligne)
                flags = re.search(r'Flags \[(.*?)\]', ligne)
                
                if timestamp and ip:
                    heure = int(timestamp.group(1))
                    self.donnees_analysees['distribution_horaire'][heure] += 1
                    
                    # Création de l'enregistrement de connexion
                    connexion = {
                        'timestamp': f"{timestamp.group(1)}:{timestamp.group(2)}:{timestamp.group(3)}",
                        'ip': ip.group(1),
                        'taille': int(longueur.group(1)) if longueur else 0,
                        'flags': flags.group(1) if flags else ''
                    }
                    
                    self.donnees_analysees['connexions'].append(connexion)
                    
                    # Suivi des tailles de paquets
                    if connexion['taille'] > 0:
                        self.donnees_analysees['tailles_paquets'].append(connexion['taille'])
                    
                    # Analyse des flags
                    if flags:
                        flag_sequence = flags.group(1)
                        self.donnees_analysees['flags_stats'][flag_sequence] = self.donnees_analysees['flags_stats'].get(flag_sequence, 0) + 1
                        
                        # Classification basée sur les flags TCP
                        if 'S' in flag_sequence and not ('A' in flag_sequence):
                            self.donnees_analysees['types_attaques']['Scan SYN'] += 1
                        elif 'S' in flag_sequence and 'A' in flag_sequence:
                            self.donnees_analysees['types_attaques']['Connexion SSH Établie'] += 1
                        elif 'R' in flag_sequence:
                            self.donnees_analysees['types_attaques']['Tentative de Reset'] += 1
                        elif 'F' in flag_sequence and not ('A' in flag_sequence):
                            self.donnees_analysees['types_attaques']['Scan FIN'] += 1
                        elif 'S' in flag_sequence and 'F' in flag_sequence and 'P' in flag_sequence:
                            self.donnees_analysees['types_attaques']['Scan complet'] += 1
                        else:
                            self.donnees_analysees['types_attaques']['Autre'] += 1
        
        self.afficher_analyse()
        self.afficher_graphiques()
        
    def afficher_analyse(self):
        self.texte_resultats.delete(1.0, tk.END)
        
        # Affichage des statistiques générales
        total_connexions = len(self.donnees_analysees['connexions'])
        self.texte_resultats.insert(tk.END, f"=== Résultats de l'Analyse Réseau ===\n\n")
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
        
        # Statistiques des types d'attaques
        self.texte_resultats.insert(tk.END, "Types d'Attaques :\n")
        for type_attaque, compte in self.donnees_analysees['types_attaques'].items():
            if compte > 0:
                pourcentage = (compte / total_connexions) * 100
                self.texte_resultats.insert(tk.END, f"- {type_attaque}: {compte} ({pourcentage:.1f}%)\n")

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
            colors = ['#2ecc71', '#e67e22', '#3498db', '#2980b9', '#95a5a6']
            
            total_flags = sum(self.donnees_analysees['flags_stats'].values())
            
            for flag_type, count in self.donnees_analysees['flags_stats'].items():
                if count > 0:
                    labels.append(flag_type)
                    sizes.append(count)
            
            if sizes:  # Vérifier qu'il y a des données à afficher
                wedges, texts, autotexts = ax1.pie(sizes,
                                                  labels=labels,
                                                  colors=colors[:len(sizes)],
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
        
        # Ajout d'une grille
        ax2.yaxis.grid(True, linestyle='--', alpha=0.7)
        ax2.set_axisbelow(True)  # Mettre la grille en arrière-plan
        
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
        
        # Ajuster les espaces entre les graphiques
        fig.tight_layout()
        
        # Création du canvas et affichage
        canvas = FigureCanvasTkAgg(fig, self.frame_graphiques)
        canvas.draw()
        
        # Utiliser pack au lieu de grid pour une meilleure gestion de l'espace
        canvas.get_tk_widget().pack(side=tk.TOP, fill=tk.BOTH, expand=True)

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
                    fieldnames=['timestamp', 'ip', 'taille'])
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
                    .stats {{ margin: 20px 0; }}
                </style>
            </head>
            <body>
                <h1>Rapport d'Analyse Réseau</h1>
                <div class="stats">
                    <h2>Statistiques Générales</h2>
                    <p>Connexions Totales : {total_connexions}</p>
                    <p>Taille Moyenne des Paquets : {taille_moy:.2f} octets</p>
                    
                    <h2>Distribution des Attaques</h2>
                    <ul>
                    {"".join(f"<li>{type_}: {compte} ({(compte/total_connexions)*100:.1f}%)</li>" 
                             for type_, compte in self.donnees_analysees['types_attaques'].items() if compte > 0)}
                    </ul>
                </div>
            </body>
            </html>
            """
            
            with open(fichier, 'w', encoding='utf-8') as f:
                f.write(contenu_html)
            webbrowser.open('file://' + os.path.realpath(fichier))

if __name__ == "__main__":
    root = tk.Tk()
    app = AnalyseurReseau(root)
    root.mainloop()