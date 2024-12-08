def lire_fichier_ics(nom_fichier):
    with open(nom_fichier, 'r', encoding='utf-8') as fichier:
        contenu = fichier.read()
    return contenu

def extraire_valeur(contenu, identificateur):
    for ligne in contenu.split('\n'):
        if ligne.startswith(identificateur + ':'):
            return ligne.split(':', 1)[1]
    return "vide"

def convertir_date_ics(date_ics):
    # Format input: YYYYMMDDTHHMMSSZ
    # Format output: DD-MM-YYYY
    annee = date_ics[0:4]
    mois = date_ics[4:6]
    jour = date_ics[6:8]
    return f"{jour}-{mois}-{annee}"

def convertir_heure_ics(heure_ics):
    # Extrait l'heure du format YYYYMMDDTHHMMSSZ
    heure = heure_ics[9:11]
    minutes = heure_ics[11:13]
    return f"{heure}:{minutes}"

def calculer_duree(debut_ics, fin_ics):
    debut_h = int(debut_ics[9:11])
    debut_m = int(debut_ics[11:13])
    fin_h = int(fin_ics[9:11])
    fin_m = int(fin_ics[11:13])
    
    duree_minutes = (fin_h * 60 + fin_m) - (debut_h * 60 + debut_m)
    heures = duree_minutes // 60
    minutes = duree_minutes % 60
    
    return f"{heures:02d}:{minutes:02d}"

def extraire_modalite(description):
    if "CM" in description:
        return "CM"
    elif "TD" in description:
        return "TD"
    elif "TP" in description:
        return "TP"
    elif "DS" in description:
        return "DS"
    elif "Proj" in description:
        return "Proj"
    return "vide"

def extraire_evenements(contenu_ics):
    evenements = []
    evenement_courant = []
    dans_evenement = False
    
    for ligne in contenu_ics.split('\n'):
        if ligne.startswith('BEGIN:VEVENT'):
            dans_evenement = True
            evenement_courant = []
        elif ligne.startswith('END:VEVENT'):
            dans_evenement = False
            evenements.append('\n'.join(evenement_courant))
        elif dans_evenement:
            evenement_courant.append(ligne)
            
    return evenements

def convertir_evenement_csv(evenement):
    # Extraction des données
    uid = extraire_valeur(evenement, "UID")
    dtstart = extraire_valeur(evenement, "DTSTART")
    dtend = extraire_valeur(evenement, "DTEND")
    summary = extraire_valeur(evenement, "SUMMARY")
    location = extraire_valeur(evenement, "LOCATION")
    description = extraire_valeur(evenement, "DESCRIPTION")

    # Conversion des dates et calcul de la durée
    date = convertir_date_ics(dtstart)
    heure = convertir_heure_ics(dtstart)
    duree = calculer_duree(dtstart, dtend)
    
    # Détermination de la modalité
    modalite = extraire_modalite(summary)
    
    # Extraction des groupes et profs depuis la description
    groupes = []
    profs = []
    for ligne in description.split('\n'):
        if "RT1-" in ligne:
            groupes.append(ligne.strip())
        elif len(ligne.strip()) > 0 and not ligne.startswith('('):
            profs.append(ligne.strip())
            
    # Formatage final
    groupes_str = "|".join(groupes) if groupes else "vide"
    profs_str = "|".join(profs) if profs else "vide"
    salles_str = location.replace(',', '|')

    return f"{uid};{date};{heure};{duree};{modalite};{summary};{salles_str};{profs_str};{groupes_str}"

# Programme principal
if __name__ == "__main__":
    nom_fichier = "ADE_RT1_Septembre2023_Decembre2023.ics"
    try:
        contenu = lire_fichier_ics(nom_fichier)
        evenements = extraire_evenements(contenu)
        resultats = [convertir_evenement_csv(evt) for evt in evenements]
        
        # Affichage des résultats
        for resultat in resultats:
            print(resultat)
            
    except FileNotFoundError:
        print(f"Le fichier {nom_fichier} n'a pas été trouvé.")
    except Exception as e:
        print(f"Une erreur s'est produite : {str(e)}")