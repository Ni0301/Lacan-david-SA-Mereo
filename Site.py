import csv
from datetime import datetime
import markdown
import subprocess
import sys

def lire_fichier_tcpdump(nom_fichier):
    """Lit le contenu d'un fichier tcpdump."""
    with open(nom_fichier, 'r', encoding='utf-8') as fichier:
        contenu = fichier.readlines()
    return contenu

def extraire_info_paquet(ligne):
    """Extrait les informations pertinentes d'une ligne tcpdump."""
    try:
        # Format attendu: timestamp IP_source > IP_dest: protocole length taille
        elements = ligne.split()
        timestamp = elements[0]
        ip_source = elements[2]
        ip_dest = elements[4].rstrip(':')
        taille = int(elements[-1])
        
        return {
            "timestamp": timestamp,
            "ip_source": ip_source,
            "ip_dest": ip_dest,
            "taille": taille
        }
    except (IndexError, ValueError):
        return None

def generer_csv(paquets, nom_fichier_sortie):
    """Génère un fichier CSV à partir des données des paquets."""
    with open(nom_fichier_sortie, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=["timestamp", "ip_source", "ip_dest", "taille"])
        writer.writeheader()
        for paquet in paquets:
            if paquet:
                writer.writerow(paquet)

def analyser_trafic(paquets):
    """Analyse le trafic pour détecter les activités suspectes."""
    stats_ip = {}
    for paquet in paquets:
        if paquet:
            ip = paquet["ip_source"]
            if ip not in stats_ip:
                stats_ip[ip] = {"count": 0, "total_size": 0}
            stats_ip[ip]["count"] += 1
            stats_ip[ip]["total_size"] += paquet["taille"]
    
    # Détecter les IP suspectes (seuil arbitraire pour l'exemple)
    suspects = []
    for ip, stats in stats_ip.items():
        if stats["count"] > 1000 or stats["total_size"] > 1000000:  # Seuils à ajuster
            suspects.append({
                "ip": ip,
                "nb_paquets": stats["count"],
                "volume_total": stats["total_size"]
            })
    
    return suspects

def generer_rapport_markdown(suspects):
    """Génère un rapport en format Markdown."""
    md_content = """
# Rapport d'analyse du trafic réseau

## Activités suspectes détectées

| IP Source | Nombre de paquets | Volume total (octets) |
|-----------|------------------|---------------------|
"""
    
    for suspect in suspects:
        md_content += f"| {suspect['ip']} | {suspect['nb_paquets']} | {suspect['volume_total']} |\n"
    
    return md_content

def generer_html(md_content):
    """Convertit le contenu Markdown en page HTML."""
    html_content = markdown.markdown(md_content)
    
    html_complet = f"""
<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        table {{ border-collapse: collapse; width: 100%; margin: 20px 0; }}
        th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
        th {{ background-color: #f2f2f2; }}
    </style>
</head>
<body>
{html_content}
</body>
</html>
"""
    
    with open('rapport_reseau.html', 'w', encoding='utf-8') as f:
        f.write(html_complet)

def main():
    try:
        # 1. Lecture du fichier tcpdump
        contenu = lire_fichier_tcpdump('fichier1000.txt')
        
        # 2. Extraction des informations
        paquets = [extraire_info_paquet(ligne) for ligne in contenu]
        
        # 3. Génération du CSV
        generer_csv(paquets, 'analyse_reseau.csv')
        
        # 4. Analyse du trafic
        suspects = analyser_trafic(paquets)
        
        # 5. Génération du rapport
        md_content = generer_rapport_markdown(suspects)
        generer_html(md_content)
        
        print("Analyse terminée avec succès!")
        print("- Fichier CSV généré: analyse_reseau.csv")
        print("- Rapport HTML généré: rapport_reseau.html")
        
    except FileNotFoundError:
        print("Erreur: Fichier de capture réseau non trouvé")
    except Exception as e:
        print(f"Une erreur s'est produite: {str(e)}")

if __name__ == "__main__":
    main()