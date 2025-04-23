import pandas as pd
import streamlit as st
import requests
from sentence_transformers import SentenceTransformer, util
import matplotlib.pyplot as plt
import seaborn as sns
import io
import torch

st.set_page_config(layout="wide")

# Load embedding model with error handling
@st.cache_resource
def load_model():
    try:
        # Check if CUDA is available, otherwise use CPU
        device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        model = SentenceTransformer('all-MiniLM-L6-v2')
        model = model.to(device)
        return model
    except Exception as e:
        st.error(f"Error loading model: {e}")
        return None

# Preload MITRE ATT&CK data
@st.cache_data
def load_mitre_data():
    try:
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
    except Exception as e:
        st.error(f"Error loading MITRE data: {e}")
        return []

# Pre-compute embeddings
@st.cache_resource
def get_mitre_embeddings(model, techniques):
    if model is None or not techniques:
        return None
    
    try:
        descriptions = [tech['description'] for tech in techniques]
        return model.encode(descriptions, convert_to_tensor=True)
    except Exception as e:
        st.error(f"Error computing embeddings: {e}")
        return None

# Map use case to MITRE using semantic similarity
def map_to_mitre(description, model, mitre_techniques, mitre_embeddings):
    if model is None or mitre_embeddings is None:
        return "N/A", "N/A", "N/A"
    
    try:
        query_embedding = model.encode(description, convert_to_tensor=True)
        scores = util.cos_sim(query_embedding, mitre_embeddings)[0]
        best_match_idx = scores.argmax().item()
        best_tech = mitre_techniques[best_match_idx]
        return best_tech['tactic'], f"{best_tech['id']} - {best_tech['name']}", best_tech['url']
    except Exception as e:
        st.error(f"Error mapping to MITRE: {e}")
        return "Error", "Error", "Error"

# Heatmap generation
def generate_heatmap(tactics):
    try:
        if not tactics or all(t == "N/A" for t in tactics):
            st.warning("No valid tactics to display in heatmap")
            return
            
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
    except Exception as e:
        st.error(f"Error generating heatmap: {e}")

# Streamlit UI
def main():
    st.title("MITRE ATT&CK Mapping Tool for Security Use Cases")
    
    # Load model
    model = load_model()
    if model is None:
        st.error("Failed to load the sentence transformer model. Please check the logs.")
        return

    # Load MITRE data
    mitre_techniques = load_mitre_data()
    if not mitre_techniques:
        st.error("Failed to load MITRE ATT&CK data. Please check your internet connection.")
        return

    # Get MITRE embeddings
    mitre_embeddings = get_mitre_embeddings(model, mitre_techniques)
    if mitre_embeddings is None:
        st.error("Failed to compute MITRE embeddings. Please check the logs.")
        return

    uploaded_file = st.file_uploader("Upload a CSV with security use cases", type="csv")

    if uploaded_file is not None:
        try:
            df = pd.read_csv(uploaded_file)
            
            # Display the uploaded CSV structure
            st.subheader("CSV Structure")
            st.dataframe(df.head())
            
            # Check if required column exists
            required_col = None
            if 'Description' in df.columns:
                required_col = 'Description'
            elif 'description' in df.columns:
                required_col = 'description'
            else:
                st.error("Your CSV must contain a 'Description' column. Please check your file.")
                return
            
            tactics, techniques, references = [], [], []

            with st.spinner("Mapping use cases to MITRE ATT&CK..."):
                for _, row in df.iterrows():
                    tactic, technique, reference = map_to_mitre(row[required_col], model, mitre_techniques, mitre_embeddings)
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
            
        except Exception as e:
            st.error(f"An error occurred while processing the CSV: {str(e)}")

if __name__ == '__main__':
    main()
