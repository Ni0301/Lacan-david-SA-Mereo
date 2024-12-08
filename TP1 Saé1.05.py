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
    annee = date_ics[0:4]
    mois = date_ics[4:6]
    jour = date_ics[6:8]
    return f"{jour}-{mois}-{annee}"

def convertir_heure_ics(heure_ics):
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

def convertir_evenement_csv(contenu_ics):
    uid = extraire_valeur(contenu_ics, "UID")
    dtstart = extraire_valeur(contenu_ics, "DTSTART")
    dtend = extraire_valeur(contenu_ics, "DTEND")
    summary = extraire_valeur(contenu_ics, "SUMMARY")
    location = extraire_valeur(contenu_ics, "LOCATION")
    description = extraire_valeur(contenu_ics, "DESCRIPTION")
    date = convertir_date_ics(dtstart)
    heure = convertir_heure_ics(dtstart)
    duree = calculer_duree(dtstart, dtend)
    modalite = extraire_modalite(summary)
    groupes = []
    profs = []
    for ligne in description.split('\n'):
        if "RT1-" in ligne:
            groupes.append(ligne.strip())
        elif len(ligne.strip()) > 0 and not ligne.startswith('('):
            profs.append(ligne.strip())
            
    groupes_str = "|".join(groupes) if groupes else "vide"
    profs_str = "|".join(profs) if profs else "vide"
    salles_str = location.replace(',', '|')

    return f"{uid};{date};{heure};{duree};{modalite};{summary};{salles_str};{profs_str};{groupes_str}"
if __name__ == "__main__":
    nom_fichier = "evenementSAE_15.ics"
    contenu = lire_fichier_ics(nom_fichier)
    resultat = convertir_evenement_csv(contenu)
    print(resultat)