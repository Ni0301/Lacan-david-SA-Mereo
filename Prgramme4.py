from Programme3 import extraire_seances_r107, extraire_evenements, convertir_evenement_csv
import matplotlib.pyplot as plt

def compter_seances_par_mois(seances):
    compte_mois = {
        '09': 0,  
        '10': 0,  
        '11': 0,  
        '12': 0   
    }
    
    #Tp par mois
    for seance in seances:
        date = seance[0]
        mois = date.split('-')[1]
        if seance[2] == 'TP':
            compte_mois[mois] += 1
    
    return compte_mois

def creer_graphique(compte_mois):
    mois = ['Septembre', 'Octobre', 'Novembre', 'Décembre']
    valeurs = list(compte_mois.values())
    
    # graph
    plt.figure(figsize=(10, 6))
    plt.bar(mois, valeurs)
    
    plt.title('Nombre de séances de TP R1.07 par mois')
    plt.xlabel('Mois')
    plt.ylabel('Nombre de séances')

    for i, v in enumerate(valeurs):
        plt.text(i, v, str(v), ha='center', va='bottom')

    plt.savefig('seances_r107.png')#save graph
    plt.close()

if __name__ == "__main__":
    with open('ADE_RT1_Septembre2023_Decembre2023.ics', 'r', encoding='utf-8') as fichier:
        contenu = fichier.read()
    
    evenements = extraire_evenements(contenu)
    evenements_csv = [convertir_evenement_csv(evt) for evt in evenements]
    
    groupe_tp = "RT1-TP A1"
    seances_r107 = extraire_seances_r107(evenements_csv, groupe_tp)
    compte_mois = compter_seances_par_mois(seances_r107)
    creer_graphique(compte_mois)