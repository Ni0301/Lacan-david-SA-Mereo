from Programme2 import extraire_evenements, convertir_evenement_csv

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

if __name__ == "__main__":
    with open('ADE_RT1_Septembre2023_Decembre2023.ics', 'r', encoding='utf-8') as fichier:
        contenu = fichier.read()
    
    evenements = extraire_evenements(contenu)
    evenements_csv = [convertir_evenement_csv(evt) for evt in evenements]
    
    groupe_tp = "RT1-TP A1"  
    seances_r107 = extraire_seances_r107(evenements_csv, groupe_tp)
    
    print("Date\t\tDurée\tType")
    print("-" * 30)
    for seance in seances_r107:
        print(f"{seance[0]}\t{seance[1]}\t{seance[2]}")