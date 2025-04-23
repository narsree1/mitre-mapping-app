import pandas as pd
import streamlit as st
import requests
from sentence_transformers import SentenceTransformer, util
import matplotlib.pyplot as plt
import seaborn as sns
import io

st.set_page_config(layout="wide")

# Load embedding model
model = SentenceTransformer('all-MiniLM-L6-v2')

# Preload MITRE ATT&CK data
@st.cache_data
def load_mitre_data():
    response = requests.get("https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json")
    attack_data = response.json()
    techniques = []

    for obj in attack_data['objects']:
        if obj.get('type') == 'attack-pattern':
            techniques.append({
                'id': obj.get('external_references', [{}])[0].get('external_id', 'N/A'),
                'name': obj.get('name', 'N/A'),
                'description': obj.get('description', ''),
                'tactic': ', '.join([phase['phase_name'] for phase in obj.get('kill_chain_phases', [])]),
                'url': obj.get('external_references', [{}])[0].get('url', '')
            })
    return techniques

mitre_techniques = load_mitre_data()

# Pre-compute embeddings
@st.cache_resource
def get_mitre_embeddings():
    descriptions = [tech['description'] for tech in mitre_techniques]
    return model.encode(descriptions, convert_to_tensor=True)

mitre_embeddings = get_mitre_embeddings()

# Map use case to MITRE using semantic similarity

def map_to_mitre(description):
    query_embedding = model.encode(description, convert_to_tensor=True)
    scores = util.cos_sim(query_embedding, mitre_embeddings)[0]
    best_match_idx = scores.argmax().item()
    best_tech = mitre_techniques[best_match_idx]
    return best_tech['tactic'], f"{best_tech['id']} - {best_tech['name']}", best_tech['url']

# Heatmap generation

def generate_heatmap(tactics):
    heatmap_data = pd.DataFrame(tactics, columns=['Tactic'])
    tactic_counts = heatmap_data['Tactic'].value_counts().reset_index()
    tactic_counts.columns = ['Tactic', 'Count']
    plt.figure(figsize=(12, 6))
    sns.barplot(data=tactic_counts, x='Tactic', y='Count', palette='viridis')
    plt.xticks(rotation=45)
    plt.title("MITRE Tactic Heatmap")
    buf = io.BytesIO()
    plt.tight_layout()
    plt.savefig(buf, format='png')
    st.image(buf)

# Streamlit UI

def main():
    st.title("MITRE ATT&CK Mapping Tool for Security Use Cases")
    uploaded_file = st.file_uploader("Upload a CSV with Use Case Name, Description, Log Source", type="csv")

    if uploaded_file is not None:
        df = pd.read_csv(uploaded_file)
        tactics, techniques, references = [], [], []

        for _, row in df.iterrows():
            tactic, technique, reference = map_to_mitre(row['Description'])
            tactics.append(tactic)
            techniques.append(technique)
            references.append(reference)

        df['Mapped MITRE Tactic(s)'] = tactics
        df['Mapped MITRE Technique(s)/Sub-techniques'] = techniques
        df['Reference Resource(s)'] = references

        st.success("Mapping complete!")
        st.dataframe(df)

        csv = df.to_csv(index=False).encode('utf-8')
        st.download_button("Download Results as CSV", csv, "mitre_mapped_output.csv", "text/csv")

        st.markdown("---")
        st.subheader("MITRE Tactic Heatmap")
        generate_heatmap(tactics)

if __name__ == '__main__':
    main()
