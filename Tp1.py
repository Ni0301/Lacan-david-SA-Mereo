from datetime import datetime

def lire_fichier_ics(nom_fichier):
    """Lit le contenu d'un fichier .ics."""
    with open(nom_fichier, 'r', encoding='utf-8') as fichier:
        contenu = fichier.readlines()
    return contenu

def extraire_evenement_ics(contenu):
    """Extrait les informations pertinentes d'un fichier .ics."""
    evenement = {}
    for ligne in contenu:
        if ligne.startswith("UID:"):
            evenement["uid"] = ligne.split("UID:")[1].strip()
        elif ligne.startswith("DTSTART:"):
            evenement["dtstart"] = ligne.split("DTSTART:")[1].strip()
        elif ligne.startswith("DTEND:"):
            evenement["dtend"] = ligne.split("DTEND:")[1].strip()
        elif ligne.startswith("SUMMARY:"):
            evenement["summary"] = ligne.split("SUMMARY:")[1].strip()
        elif ligne.startswith("LOCATION:"):
            evenement["location"] = ligne.split("LOCATION:")[1].strip()
        elif ligne.startswith("DESCRIPTION:"):
            evenement["description"] = ligne.split("DESCRIPTION:")[1].strip()
    return evenement

def convertir_format_date(date_ics):
    """Convertit une date AAAAMMJJThhmmssZ en JJ-MM-AAAA et HH:MM."""
    date_obj = datetime.strptime(date_ics, "%Y%m%dT%H%M%SZ")
    date_str = date_obj.strftime("%d-%m-%Y")
    heure_str = date_obj.strftime("%H:%M")
    return date_str, heure_str

def calculer_duree(dtstart, dtend):
    """Calcule la durée entre DTSTART et DTEND."""
    date_debut = datetime.strptime(dtstart, "%Y%m%dT%H%M%SZ")
    date_fin = datetime.strptime(dtend, "%Y%m%dT%H%M%SZ")
    duree = date_fin - date_debut
    heures, secondes = divmod(duree.total_seconds(), 3600)
    minutes = secondes // 60
    return f"{int(heures):02}:{int(minutes):02}"

def generer_pseudo_csv(evenement):
    """Génère une chaîne pseudo-CSV à partir des informations de l'événement."""
    date, heure = convertir_format_date(evenement["dtstart"])
    duree = calculer_duree(evenement["dtstart"], evenement["dtend"])
    salles = evenement.get("location", "").replace(",", "|")
    
    # Extraire les professeurs et groupes depuis DESCRIPTION
    description = evenement.get("description", "").split("\n")
    profs, groupes = [], []
    for ligne in description:
        if ligne.strip().isupper():  # Professeurs supposés en majuscules
            profs.append(ligne.strip())
        elif ligne.strip():
            groupes.append(ligne.strip())
    
    profs_str = "|".join(profs)
    groupes_str = "|".join(groupes)
    
    # Construire la chaîne pseudo-CSV
    return f'{evenement["uid"]};{date};{heure};{duree};CM;{evenement["summary"]};{salles};{profs_str};{groupes_str}'

def main():
    # Nom du fichier .ics
    nom_fichier = "C:\\NINO\\Projet\\evenementSAE_15.ics"
    
    # Lire et traiter le fichier
    contenu = lire_fichier_ics(nom_fichier)
    evenement = extraire_evenement_ics(contenu)
    print(generer_pseudo_csv(evenement))

if __name__ == "__main__":
    main()
