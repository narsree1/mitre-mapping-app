import pandas as pd
import streamlit as st
import requests
from sentence_transformers import SentenceTransformer, util
import torch
import json
import datetime
import base64
import uuid
import io
import matplotlib.pyplot as plt
import numpy as np

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
        tactics = []
        tactic_mapping = {}  # To store tactic ID to name mapping

        # Extract tactics (kill chain phases)
        for obj in attack_data['objects']:
            if obj.get('type') == 'x-mitre-tactic':
                tactic_id = obj.get('external_references', [{}])[0].get('external_id', 'N/A')
                tactic_name = obj.get('name', 'N/A')
                tactic_mapping[tactic_name] = tactic_id
                tactics.append({
                    'id': tactic_id,
                    'name': tactic_name
                })

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
        return techniques, tactics, tactic_mapping
    except Exception as e:
        st.error(f"Error loading MITRE data: {e}")
        return [], [], {}

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

# Create a simple heatmap using matplotlib
def create_simple_heatmap(techniques_count, tactics, mitre_techniques):
    try:
        # Create a mapping from technique ID to tactics
        tech_to_tactics = {}
        for tech in mitre_techniques:
            tech_to_tactics[tech['id']] = tech['tactics_list']
        
        # Get all unique tactic names
        all_tactics = [tactic['name'] for tactic in tactics]
        
        # Create a matrix for the heatmap
        matrix = np.zeros((len(techniques_count), len(all_tactics)))
        tech_ids = list(techniques_count.keys())
        
        # Fill the matrix with technique counts
        for i, tech_id in enumerate(tech_ids):
            for tech in mitre_techniques:
                if tech['id'] == tech_id:
                    for tactic_name in tech['tactics_list']:
                        if tactic_name in all_tactics:
                            j = all_tactics.index(tactic_name)
                            matrix[i, j] = techniques_count[tech_id]
        
        # Create labels for techniques
        tech_labels = []
        for tech_id in tech_ids:
            for tech in mitre_techniques:
                if tech['id'] == tech_id:
                    tech_labels.append(f"{tech_id}: {tech['name']}")
                    break
            else:
                tech_labels.append(tech_id)
        
        # Create the figure
        fig, ax = plt.subplots(figsize=(12, len(tech_ids) * 0.4))
        im = ax.imshow(matrix, cmap='Blues')
        
        # Set ticks and labels
        ax.set_xticks(np.arange(len(all_tactics)))
        ax.set_yticks(np.arange(len(tech_labels)))
        ax.set_xticklabels(all_tactics, rotation=45, ha='right')
        ax.set_yticklabels(tech_labels)
        
        # Add a colorbar
        cbar = ax.figure.colorbar(im, ax=ax)
        cbar.ax.set_ylabel("Technique Count", rotation=-90, va="bottom")
        
        # Set title and adjust layout
        ax.set_title("MITRE ATT&CK Technique Coverage")
        plt.tight_layout()
        
        # Convert to image to display in Streamlit
        buf = io.BytesIO()
        plt.savefig(buf, format='png', bbox_inches='tight')
        buf.seek(0)
        
        return buf
    except Exception as e:
        st.error(f"Error creating heatmap: {str(e)}")
        return None

# Create an HTML representation of the ATT&CK matrix
def create_html_matrix(techniques_count, tactics, mitre_techniques):
    try:
        # Create a mapping from technique ID to technique info
        tech_info = {}
        for tech in mitre_techniques:
            tech_info[tech['id']] = {
                'name': tech['name'],
                'tactics': tech['tactics_list']
            }
        
        # Get all unique tactic names in the correct order
        tactic_names = [tactic['name'] for tactic in tactics]
        
        # Create an HTML table for the matrix
        html = """
        <style>
        .matrix-table {
            border-collapse: collapse;
            width: 100%;
            font-family: Arial, sans-serif;
        }
        .matrix-table th, .matrix-table td {
            border: 1px solid #ddd;
            padding: 8px;
            text-align: center;
        }
        .matrix-table th {
            background-color: #f2f2f2;
            position: sticky;
            top: 0;
        }
        .technique-cell {
            text-align: left;
            font-weight: bold;
        }
        .count-cell {
            background-color: #e6f2ff;
        }
        .count-cell-high {
            background-color: #0d4a90;
            color: white;
        }
        .count-cell-medium {
            background-color: #66b1ff;
            color: white;
        }
        .count-cell-low {
            background-color: #cce5ff;
        }
        </style>
        <table class="matrix-table">
            <tr>
                <th>Technique</th>
        """
        
        # Add tactic headers
        for tactic in tactic_names:
            html += f"<th>{tactic}</th>"
        
        html += "</tr>"
        
        # Maximum count for color scaling
        max_count = max(techniques_count.values()) if techniques_count else 1
        
        # Add technique rows
        for tech_id, count in techniques_count.items():
            if tech_id in tech_info:
                tech_name = tech_info[tech_id]['name']
                tactics_for_tech = tech_info[tech_id]['tactics']
                
                html += f"""
                <tr>
                    <td class="technique-cell">{tech_id}: {tech_name}</td>
                """
                
                for tactic in tactic_names:
                    if tactic in tactics_for_tech:
                        # Determine cell color based on count
                        color_class = "count-cell"
                        if count > max_count * 0.7:
                            color_class = "count-cell-high"
                        elif count > max_count * 0.3:
                            color_class = "count-cell-medium"
                        elif count > 0:
                            color_class = "count-cell-low"
                        
                        html += f'<td class="{color_class}">{count}</td>'
                    else:
                        html += '<td></td>'
                
                html += "</tr>"
        
        html += "</table>"
        return html
    except Exception as e:
        st.error(f"Error creating HTML matrix: {str(e)}")
        return f"<p>Error creating matrix: {str(e)}</p>"

# Streamlit UI
def main():
    st.title("MITRE ATT&CK Mapping Tool for Security Use Cases")
    
    # Load model
    model = load_model()
    if model is None:
        st.error("Failed to load the sentence transformer model. Please check the logs.")
        return

    # Load MITRE data
    mitre_techniques, tactics, tactic_mapping = load_mitre_data()
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
            
            tactics_list, techniques_list, references, all_tactics_lists = [], [], [], []
            techniques_count = {}  # For Navigator layer

            with st.spinner("Mapping use cases to MITRE ATT&CK..."):
                for _, row in df.iterrows():
                    tactic, technique, reference, tactics_list = map_to_mitre(row[required_col], model, mitre_techniques, mitre_embeddings)
                    tactics_list.append(tactic)
                    techniques_list.append(technique)
                    references.append(reference)
                    all_tactics_lists.append(tactics_list)
                    
                    # Extract technique ID for navigator
                    if '-' in technique:
                        tech_id = technique.split('-')[0].strip()
                        if tech_id in techniques_count:
                            techniques_count[tech_id] += 1
                        else:
                            techniques_count[tech_id] = 1

            df['Mapped MITRE Tactic(s)'] = tactics_list
            df['Mapped MITRE Technique(s)/Sub-techniques'] = techniques_list
            df['Reference Resource(s)'] = references

            st.success("Mapping complete!")
            
            # Show only the final mapped view
            st.subheader("Mapped Security Use Cases")
            st.dataframe(df)

            csv = df.to_csv(index=False).encode('utf-8')
            st.download_button("Download Results as CSV", csv, "mitre_mapped_output.csv", "text/csv")

            st.markdown("---")
            st.subheader("MITRE ATT&CK Navigator View")
            
            # Create and display HTML matrix
            st.write("### Technique Coverage Matrix")
            html_matrix = create_html_matrix(techniques_count, tactics, mitre_techniques)
            st.components.v1.html(html_matrix, height=len(techniques_count) * 50 + 100)
            
            # Create and display simple heatmap as fallback
            st.write("### Technique Heatmap")
            heatmap_buf = create_simple_heatmap(techniques_count, tactics, mitre_techniques)
            if heatmap_buf:
                st.image(heatmap_buf, use_column_width=True)
            
            # Provide download option for Navigator
            navigator_layer, _ = create_navigator_layer(techniques_count)
            with st.expander("Download Navigator Layer"):
                st.download_button(
                    "Download Navigator Layer JSON", 
                    navigator_layer, 
                    "navigator_layer.json", 
                    "application/json"
                )
                st.markdown("You can upload this JSON to the [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/) for more advanced visualization.")
            
        except Exception as e:
            st.error(f"An error occurred while processing the CSV: {str(e)}")
            st.error(f"Error details: {str(e.__class__.__name__)}")

if __name__ == '__main__':
    main()
