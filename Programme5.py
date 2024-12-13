import markdown
from Programme3 import extraire_seances_r107, extraire_evenements, convertir_evenement_csv
from Programme4 import compter_seances_par_mois, creer_graphique

def creer_markdown(seances, compte_mois):
    md_content = """
| Date | Durée | Type |
|------|--------|------|
"""