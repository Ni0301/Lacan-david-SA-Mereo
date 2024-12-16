import subprocess
import sys

# Inst markdown
try:
    import markdown
except ImportError:
    print("Installation de markdown...")
    subprocess.check_call([sys.executable, "-m", "pip", "install", "markdown"])
    import markdown

def extraire_seances_r107(evenements_csv, groupe_tp):
    seances_r107 = []
    
    for evt in evenements_csv:
        champs = evt.split(';')
        intitule = champs[5]
        groupes = champs[8]
        
        if "R1.07" in intitule and groupe_tp in groupes:
            date = champs[1]
            duree = champs[3]
            modalite = champs[4]
            seances_r107.append([date, duree, modalite])
    
    return seances_r107

def compter_seances_par_mois(seances):
    compte_mois = {
        '09': 0,  
        '10': 0,  
        '11': 0,  
        '12': 0   
    }
    
    for seance in seances:
        date = seance[0]  
        mois = date.split('-')[1]
        if seance[2] == 'TP':  
            compte_mois[mois] += 1
    
    return compte_mois

def creer_markdown(seances, compte_mois):
    # Contenu markdown
    md_content = """
# Analyse des séances R1.07

## Tableau des séances

| Date | Durée | Type |
|------|--------|------|
"""
    
    for seance in seances:
        md_content += f"| {seance[0]} | {seance[1]} | {seance[2]} |\n"
    
    # graph
    md_content += """
## Répartition des séances TP par mois

![Graphique des séances](seances_r107.png)
"""
    
    return md_content

def generer_html(md_content):
    # markdown en HTML
    html_content = markdown.markdown(md_content)
    
    # style CSS
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
        img {{ max-width: 100%; height: auto; }}
    </style>
</head>
<body>
{html_content}
</body>
</html>
"""
    
    # save fichier HTML
    with open('rapport_r107.html', 'w', encoding='utf-8') as f:
        f.write(html_complet)
        
if __name__ == "__main__":
    try:
        # fichier calendrier
        with open('ADE_RT1_Septembre2023_Decembre2023.ics', 'r', encoding='utf-8') as fichier:
            contenu = fichier.read()
        
        # prise des évènement
        from Programme2 import extraire_evenements, convertir_evenement_csv
        evenements = extraire_evenements(contenu)
        evenements_csv = [convertir_evenement_csv(evt) for evt in evenements]
        
        # prise séaces
        groupe_tp = "RT1-TP A2"
        seances_r107 = extraire_seances_r107(evenements_csv, groupe_tp)
        
        # séances/ mois
        compte_mois = compter_seances_par_mois(seances_r107)
        
        # contenue markdown
        md_content = creer_markdown(seances_r107, compte_mois)
        
        generer_html(md_content)
        
        print("Le rapport HTML a été généré avec succès : rapport_r107.html")
        
    except FileNotFoundError:
        print("Le fichier de calendrier n'a pas été trouvé.")
    except Exception as e:
        print(f"Une erreur s'est produite : {str(e)}")