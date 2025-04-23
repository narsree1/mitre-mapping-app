import pandas as pd
import streamlit as st
import requests
from sentence_transformers import SentenceTransformer, util
import torch
import json
import datetime
import uuid
import plotly.graph_objects as go
from mitreattack.attack.framework import Framework
import numpy as np
import os

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
        # Using the Enterprise ATT&CK STIX data
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
                tech_id = obj.get('external_references', [{}])[0].get('external_id', 'N/A')
                
                # Skip sub-techniques for proper mapping in Navigator
                if '.' in tech_id:
                    continue
                    
                techniques.append({
                    'id': tech_id,
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

# Create MITRE ATT&CK heatmap using mitreattack-python and plotly
def generate_attack_heatmap(techniques_count, tactic_mapping):
    try:
        # Initialize MITRE ATT&CK framework
        attack = Framework()
        
        # Get all tactics and techniques
        enterprise_tactics = attack.get_tactics("enterprise")
        tactic_names = [tactic.name for tactic in enterprise_tactics]
        tactic_ids = [tactic.id for tactic in enterprise_tactics]
        
        # Create a matrix for the heatmap
        technique_matrix = []
        technique_labels = []
        max_count = max(techniques_count.values()) if techniques_count else 1
        
        # Get all techniques by tactic
        for tactic in enterprise_tactics:
            tactic_techniques = attack.get_techniques_by_tactic(tactic)
            
            # Get counts for techniques in this tactic
            for technique in tactic_techniques:
                if technique.id in techniques_count:
                    technique_matrix.append({
                        'tactic': tactic.name,
                        'technique': f"{technique.id}: {technique.name}",
                        'count': techniques_count[technique.id],
                        'normalized_count': techniques_count[technique.id] / max_count
                    })
                    technique_labels.append(f"{technique.id}: {technique.name}")
        
        # Create the heatmap using plotly
        df_heatmap = pd.DataFrame(technique_matrix)
        
        # Create pivot table for the heatmap
        heatmap_data = pd.pivot_table(
            df_heatmap, 
            values='normalized_count', 
            index=['technique'], 
            columns=['tactic'], 
            fill_value=0
        )
        
        # Create the plot
        fig = go.Figure(data=go.Heatmap(
            z=heatmap_data.values,
            x=heatmap_data.columns,
            y=heatmap_data.index,
            colorscale='Blues',
            showscale=True,
            colorbar=dict(
                title='Normalized Frequency',
            ),
            hoverongaps=False,
            hovertemplate=
            "<b>Technique:</b> %{y}<br>" +
            "<b>Tactic:</b> %{x}<br>" +
            "<b>Value:</b> %{z}<br>" +
            "<extra></extra>"
        ))
        
        fig.update_layout(
            title='MITRE ATT&CK Technique Coverage Heatmap',
            xaxis=dict(title='Tactics'),
            yaxis=dict(title='Techniques'),
            height=800,
            width=1200,
            margin=dict(l=50, r=50, t=100, b=100),
        )
        
        return fig
    except Exception as e:
        st.error(f"Error creating ATT&CK heatmap: {e}")
        return None

# Create Navigator Layer (will be used for JSON download option)
def create_navigator_layer(techniques_count):
    try:
        # Initialize techniques data with proper format for Navigator
        techniques_data = []
        
        for tech_id, count in techniques_count.items():
            techniques_data.append({
                "techniqueID": tech_id,
                "score": count,
                "color": "",
                "comment": f"Count: {count}",
                "enabled": True,
                "metadata": [],
                "links": [],
                "showSubtechniques": False
            })
        
        # Create layer file structure with updated ATT&CK version
        current_date = datetime.datetime.now().strftime("%Y-%m-%d")
        layer_id = str(uuid.uuid4())
        
        layer = {
            "name": f"Security Use Cases Mapping - {current_date}",
            "versions": {
                "attack": "17",  # Updated to v17
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
            "techniques": techniques_data,  # Using array format instead of object
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
        
        return json.dumps(layer, indent=2), layer_id
    except Exception as e:
        st.error(f"Error creating Navigator layer: {e}")
        return "{}", ""

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
            
            # Check if required column exists
            required_col = None
            if 'Description' in df.columns:
                required_col = 'Description'
            elif 'description' in df.columns:
                required_col = 'description'
            else:
                st.error("Your CSV must contain a 'Description' column. Please check your file.")
                return
            
            # Process the data without showing the raw CSV
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
            
            # Show only the final mapped view
            st.subheader("Mapped Security Use Cases")
            st.dataframe(df)

            csv = df.to_csv(index=False).encode('utf-8')
            st.download_button("Download Results as CSV", csv, "mitre_mapped_output.csv", "text/csv")

            st.markdown("---")
            st.subheader("MITRE ATT&CK Navigator View")
            
            # Generate and display the in-app ATT&CK heatmap
            heatmap_fig = generate_attack_heatmap(techniques_count, tactic_mapping)
            if heatmap_fig:
                st.plotly_chart(heatmap_fig, use_container_width=True)
            
            # Also provide option to download Navigator layer JSON
            navigator_layer, _ = create_navigator_layer(techniques_count)
            with st.expander("Download Navigator Layer for External Use"):
                st.download_button(
                    "Download Navigator Layer JSON", 
                    navigator_layer, 
                    "navigator_layer.json", 
                    "application/json"
                )
                st.markdown("You can upload this JSON to the [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) for more advanced visualization.")
            
        except Exception as e:
            st.error(f"An error occurred while processing the CSV: {str(e)}")

if __name__ == '__main__':
    main()
