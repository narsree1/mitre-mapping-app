import pandas as pd
import streamlit as st
import requests
from sentence_transformers import SentenceTransformer, util
from heatmap_renderer import display_attack_matrix
import torch
import json
import datetime
import base64
import uuid
import plotly.graph_objects as go
import html
import os
import sys

# Add a command line flag to disable file watcher
# You would run this script with: streamlit run app.py -- --server.fileWatcherType none
if "--server.fileWatcherType" not in sys.argv:
    sys.argv.extend(["--", "--server.fileWatcherType", "none"])

# Set the page configuration
st.set_page_config(layout="wide")

# Load embedding model with error handling
@st.cache_resource
def load_model():
    try:
        device = torch.device('cuda' if torch.cuda.is_available() else 'cpu')
        model = SentenceTransformer('all-MiniLM-L6-v2')
        model = model.to(device)
        return model
    except Exception as e:
        st.error(f"Error loading model: {e}")
        return None

@st.cache_data
def load_mitre_data():
    try:
        response = requests.get("https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json")
        attack_data = response.json()
        techniques = []
        tactic_mapping = {}
        tactics_list = []

        # Extract tactics first to build the mapping and ordered list
        for obj in attack_data['objects']:
            if obj.get('type') == 'x-mitre-tactic':
                tactic_id = obj.get('external_references', [{}])[0].get('external_id', 'N/A')
                tactic_name = obj.get('name', 'N/A')
                tactic_mapping[tactic_name] = tactic_id
                # Store tactics with their order in the kill chain
                order = obj.get('x_mitre_shortname', '')
                tactics_list.append({
                    'id': tactic_id, 
                    'name': tactic_name,
                    'shortname': order
                })
        
        # Sort tactics by their kill chain order
        tactics_list = sorted(tactics_list, key=lambda x: x['shortname'])

        for obj in attack_data['objects']:
            if obj.get('type') == 'attack-pattern':
                tech_id = obj.get('external_references', [{}])[0].get('external_id', 'N/A')
                if '.' in tech_id:
                    continue  # Skip sub-techniques for simplified view
                techniques.append({
                    'id': tech_id,
                    'name': obj.get('name', 'N/A'),
                    'description': obj.get('description', ''),
                    'tactic': ', '.join([phase['phase_name'] for phase in obj.get('kill_chain_phases', [])]),
                    'tactics_list': [phase['phase_name'] for phase in obj.get('kill_chain_phases', [])],
                    'url': obj.get('external_references', [{}])[0].get('url', '')
                })
        return techniques, tactic_mapping, tactics_list
    except Exception as e:
        st.error(f"Error loading MITRE data: {e}")
        return [], {}, []

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

def create_navigator_layer(techniques_count):
    try:
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
        current_date = datetime.datetime.now().strftime("%Y-%m-%d")
        layer_id = str(uuid.uuid4())
        layer = {
            "name": f"Security Use Cases Mapping - {current_date}",
            "versions": {
                "attack": "17",
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
        return json.dumps(layer, indent=2), layer_id
    except Exception as e:
        st.error(f"Error creating Navigator layer: {e}")
        return "{}", ""

def render_mitre_heatmap(techniques_count, tactics_list, mitre_techniques):
    """Create an HTML heatmap visualization similar to MITRE ATT&CK Navigator"""
    
    # Create a mapping of technique ID to techniques
    tech_map = {tech['id']: tech for tech in mitre_techniques}
    
    # Create color scale function
    def get_color(count, max_count):
        if count == 0:
            return "#ffffff"  # White for zero
        elif count < max_count * 0.33:
            return "#66b1ff"  # Light blue for low
        elif count < max_count * 0.66:
            return "#3377cc"  # Medium blue
        else:
            return "#0d4a90"  # Dark blue for high
    
    max_count = max(techniques_count.values()) if techniques_count else 1
    
    # Start building the HTML for the heatmap
    html_content = """
    <style>
        .mitre-heatmap {
            width: 100%;
            font-family: Arial, sans-serif;
            border-collapse: collapse;
        }
        .mitre-tactic {
            background-color: #dddddd;
            padding: 10px;
            font-weight: bold;
            text-align: center;
            border: 1px solid #aaa;
        }
        .mitre-techniques {
            display: flex;
            flex-wrap: wrap;
            padding: 5px;
            border: 1px solid #aaa;
        }
        .technique-box {
            margin: 3px;
            padding: 5px;
            border-radius: 3px;
            border: 1px solid #888;
            text-align: center;
            width: 110px;
            height: 75px;
            font-size: 12px;
            display: flex;
            flex-direction: column;
            justify-content: center;
            overflow: hidden;
            position: relative;
        }
        .technique-id {
            font-weight: bold;
        }
        .technique-count {
            position: absolute;
            top: 2px;
            right: 5px;
            font-weight: bold;
        }
        .color-legend {
            display: flex;
            margin-top: 20px;
            justify-content: center;
        }
        .legend-item {
            display: flex;
            align-items: center;
            margin: 0 10px;
        }
        .legend-color {
            width: 20px;
            height: 20px;
            margin-right: 5px;
            border: 1px solid #888;
        }
    </style>
    <table class="mitre-heatmap">
    """
    
    # Add rows for each tactic
    for tactic in tactics_list:
        tactic_name = tactic['name']
        html_content += f'<tr><td class="mitre-tactic">{tactic_name}</td>'
        html_content += '<td class="mitre-techniques">'
        
        # Find all techniques for this tactic
        for tech in mitre_techniques:
            if tactic_name in tech['tactics_list']:
                tech_id = tech['id']
                count = techniques_count.get(tech_id, 0)
                color = get_color(count, max_count)
                
                # Create a technique box
                html_content += f"""
                <div class="technique-box" style="background-color: {color};">
                    <div class="technique-id">{tech_id}</div>
                    <div>{html.escape(tech['name'])}</div>
                    {f'<div class="technique-count">{count}</div>' if count > 0 else ''}
                </div>
                """
        
        html_content += '</td></tr>'
    
    # Add a color legend
    html_content += """
    </table>
    <div class="color-legend">
        <div class="legend-item">
            <div class="legend-color" style="background-color: #ffffff;"></div>
            <div>Not covered</div>
        </div>
        <div class="legend-item">
            <div class="legend-color" style="background-color: #66b1ff;"></div>
            <div>Low coverage</div>
        </div>
        <div class="legend-item">
            <div class="legend-color" style="background-color: #3377cc;"></div>
            <div>Medium coverage</div>
        </div>
        <div class="legend-item">
            <div class="legend-color" style="background-color: #0d4a90;"></div>
            <div>High coverage</div>
        </div>
    </div>
    """
    
    return html_content

def main():
    st.title("MITRE ATT&CK Mapping Tool for Security Use Cases")
    model = load_model()
    if model is None:
        return
    mitre_techniques, tactic_mapping, tactics_list = load_mitre_data()
    if not mitre_techniques:
        return
    mitre_embeddings = get_mitre_embeddings(model, mitre_techniques)
    if mitre_embeddings is None:
        return

    uploaded_file = st.file_uploader("Upload a CSV with security use cases", type="csv")

    if uploaded_file is not None:
        try:
            df = pd.read_csv(uploaded_file)
            st.subheader("CSV Structure")
            st.dataframe(df.head())
            required_col = 'Description' if 'Description' in df.columns else 'description' if 'description' in df.columns else None
            if not required_col:
                st.error("Your CSV must contain a 'Description' column.")
                return

            tactics, techniques, references, all_tactics_lists = [], [], [], []
            techniques_count = {}

            with st.spinner("Mapping use cases to MITRE ATT&CK..."):
                for _, row in df.iterrows():
                    tactic, technique, reference, tactics_list = map_to_mitre(row[required_col], model, mitre_techniques, mitre_embeddings)
                    tactics.append(tactic)
                    techniques.append(technique)
                    references.append(reference)
                    all_tactics_lists.append(tactics_list)
                    if '-' in technique:
                        tech_id = technique.split('-')[0].strip()
                        techniques_count[tech_id] = techniques_count.get(tech_id, 0) + 1

            df['Mapped MITRE Tactic(s)'] = tactics
            df['Mapped MITRE Technique(s)/Sub-techniques'] = techniques
            df['Reference Resource(s)'] = references

            st.success("Mapping complete!")
            st.dataframe(df)

            csv = df.to_csv(index=False).encode('utf-8')
            st.download_button("Download Results as CSV", csv, "mitre_mapped_output.csv", "text/csv")

            st.markdown("---")
            st.subheader("MITRE ATT&CK Coverage Overview")

            total_techniques = 203
            covered = len(techniques_count.keys())
            uncovered = total_techniques - covered
            coverage_percent = round((covered / total_techniques) * 100, 2)

            fig = go.Figure(data=[go.Pie(
                labels=['Covered Techniques', 'Remaining'],
                values=[covered, uncovered],
                hole=.6,
                marker=dict(colors=['green', 'lightgrey'])
            )])
            fig.update_layout(title_text=f'MITRE Coverage: {coverage_percent}%', showlegend=True)
            st.plotly_chart(fig, use_container_width=True)

            st.markdown("---")
            st.subheader("MITRE ATT&CK Navigator Layer")

            # NEW: Display the MITRE ATT&CK Matrix visualization
            st.markdown("### MITRE ATT&CK Matrix Visualization")
            display_attack_matrix(techniques_count)
            
            # Still provide the option to download the layer for external use
            navigator_layer, layer_id = create_navigator_layer(techniques_count)
            
            st.markdown("### Download Navigator Layer")
            st.download_button(
                label="Download Navigator Layer JSON",
                data=navigator_layer,
                file_name="navigator_layer.json",
                mime="application/json"
            )
            
            with st.expander("View Layer JSON"):
                st.code(navigator_layer, language="json")

        except Exception as e:
            st.exception(e)

if __name__ == '__main__':
    main()
