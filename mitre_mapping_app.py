import pandas as pd
import streamlit as st
import requests
from sentence_transformers import SentenceTransformer, util
import torch
import json
import datetime
import base64

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
        tactic_mapping = {}  # To store tactic ID to name mapping

        # Extract tactics (kill chain phases)
        for obj in attack_data['objects']:
            if obj.get('type') == 'x-mitre-tactic':
                tactic_id = obj.get('external_references', [{}])[0].get('external_id', 'N/A')
                tactic_name = obj.get('name', 'N/A')
                tactic_mapping[tactic_name] = tactic_id

        for obj in attack_data['objects']:
            if obj.get('type') == 'attack-pattern':
                techniques.append({
                    'id': obj.get('external_references', [{}])[0].get('external_id', 'N/A'),
                    'name': obj.get('name', 'N/A'),
                    'description': obj.get('description', ''),
                    'tactic': ', '.join([phase['phase_name'] for phase in obj.get('kill_chain_phases', [])]),
                    'tactics_list': [phase['phase_name'] for phase in obj.get('kill_chain_phases', [])],
                    'url': obj.get('external_references', [{}])[0].get('url', '')
                })
        return techniques, tactic_mapping
    except Exception as e:
        st.error(f"Error loading MITRE data: {e}")
        return [], {}

# Pre-compute embeddings - Fixed to use underscore prefix for unhashable parameters
@st.cache_resource
def get_mitre_embeddings(_model, techniques):
    if _model is None or not techniques:
        return None
    
    try:
        descriptions = [tech['description'] for tech in techniques]
        return _model.encode(descriptions, convert_to_tensor=True)
    except Exception as e:
        st.error(f"Error computing embeddings: {e}")
        return None

# Map use case to MITRE using semantic similarity
def map_to_mitre(description, model, mitre_techniques, mitre_embeddings):
    if model is None or mitre_embeddings is None:
        return "N/A", "N/A", "N/A", []
    
    try:
        query_embedding = model.encode(description, convert_to_tensor=True)
        scores = util.cos_sim(query_embedding, mitre_embeddings)[0]
        best_match_idx = scores.argmax().item()
        best_tech = mitre_techniques[best_match_idx]
        return best_tech['tactic'], f"{best_tech['id']} - {best_tech['name']}", best_tech['url'], best_tech['tactics_list']
    except Exception as e:
        st.error(f"Error mapping to MITRE: {e}")
        return "Error", "Error", "Error", []

# Create Navigator Layer
def create_navigator_layer(techniques_count, tactic_mapping):
    try:
        # Initialize all techniques with score 0
        techniques_data = {}
        for tech_id, count in techniques_count.items():
            techniques_data[tech_id] = {
                "score": count,
                "enabled": True,
                "metadata": [],
                "links": [],
                "showSubtechniques": False
            }
        
        # Create layer file structure
        current_date = datetime.datetime.now().strftime("%Y-%m-%d")
        layer = {
            "name": f"Security Use Cases Mapping - {current_date}",
            "versions": {
                "attack": "13",
                "navigator": "4.8.1",
                "layer": "4.4"
            },
            "domain": "enterprise-attack",
            "description": f"Mapping of security use cases to MITRE ATT&CK techniques, generated on {current_date}",
            "filters": {
                "platforms": ["Linux", "macOS", "Windows", "Network", "PRE", "Containers", "Office 365", "SaaS", "IaaS", "Google Workspace", "Azure AD"]
            },
            "sorting": 0,
            "layout": {
                "layout": "side",
                "aggregateFunction": "max",
                "showID": True,
                "showName": True,
                "showAggregateScores": True,
                "countUnscored": False
            },
            "hideDisabled": False,
            "techniques": techniques_data,
            "gradient": {
                "colors": ["#ffffff", "#66b1ff", "#0d4a90"],
                "minValue": 0,
                "maxValue": max(techniques_count.values()) if techniques_count else 1
            },
            "legendItems": [],
            "metadata": [],
            "links": [],
            "showTacticRowBackground": True,
            "tacticRowBackground": "#dddddd",
            "selectTechniquesAcrossTactics": True,
            "selectSubtechniquesWithParent": False
        }
        
        return json.dumps(layer, indent=2)
    except Exception as e:
        st.error(f"Error creating Navigator layer: {e}")
        return "{}"

# Streamlit UI
def main():
    st.title("MITRE ATT&CK Mapping Tool for Security Use Cases")
    
    # Load model
    model = load_model()
    if model is None:
        st.error("Failed to load the sentence transformer model. Please check the logs.")
        return

    # Load MITRE data
    mitre_techniques, tactic_mapping = load_mitre_data()
    if not mitre_techniques:
        st.error("Failed to load MITRE ATT&CK data. Please check your internet connection.")
        return

    # Get MITRE embeddings - using the model object which can't be hashed
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
            
            tactics, techniques, references, all_tactics_lists = [], [], [], []
            techniques_count = {}  # For Navigator layer

            with st.spinner("Mapping use cases to MITRE ATT&CK..."):
                for _, row in df.iterrows():
                    tactic, technique, reference, tactics_list = map_to_mitre(row[required_col], model, mitre_techniques, mitre_embeddings)
                    tactics.append(tactic)
                    techniques.append(technique)
                    references.append(reference)
                    all_tactics_lists.append(tactics_list)
                    
                    # Extract technique ID for navigator
                    if '-' in technique:
                        tech_id = technique.split('-')[0].strip()
                        if tech_id in techniques_count:
                            techniques_count[tech_id] += 1
                        else:
                            techniques_count[tech_id] = 1

            df['Mapped MITRE Tactic(s)'] = tactics
            df['Mapped MITRE Technique(s)/Sub-techniques'] = techniques
            df['Reference Resource(s)'] = references

            st.success("Mapping complete!")
            st.dataframe(df)

            csv = df.to_csv(index=False).encode('utf-8')
            st.download_button("Download Results as CSV", csv, "mitre_mapped_output.csv", "text/csv")

            st.markdown("---")
            st.subheader("MITRE ATT&CK Navigator Layer")
            
            # Create Navigator layer
            navigator_layer = create_navigator_layer(techniques_count, tactic_mapping)
            
            # Create download link for the layer file
            b64 = base64.b64encode(navigator_layer.encode()).decode()
            href = f'<a href="data:application/json;base64,{b64}" download="navigator_layer.json">Download Navigator Layer File</a>'
            st.markdown(href, unsafe_allow_html=True)
            
            # Display instructions
            st.markdown("""
            ### Instructions to view in MITRE ATT&CK Navigator:
            
            1. Download the Navigator Layer file using the link above
            2. Visit [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
            3. Click on "Open Existing Layer" and upload the downloaded file
            """)
            
            # Show sample of the JSON (collapsible)
            with st.expander("Preview Navigator Layer JSON"):
                st.code(navigator_layer, language="json")
            
        except Exception as e:
            st.error(f"An error occurred while processing the CSV: {str(e)}")

if __name__ == '__main__':
    main()
