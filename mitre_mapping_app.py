import pandas as pd
import streamlit as st
import requests
from sentence_transformers import SentenceTransformer, util
import torch
import json
import datetime
import base64
import uuid
import plotly.graph_objects as go
import html
from collections import defaultdict

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

        for obj in attack_data['objects']:
            if obj.get('type') == 'x-mitre-tactic':
                tactic_id = obj.get('external_references', [{}])[0].get('external_id', 'N/A')
                tactic_name = obj.get('name', 'N/A')
                tactic_mapping[tactic_name] = tactic_id

        for obj in attack_data['objects']:
            if obj.get('type') == 'attack-pattern':
                tech_id = obj.get('external_references', [{}])[0].get('external_id', 'N/A')
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
        return techniques, tactic_mapping, attack_data  # Added attack_data to return values
    except Exception as e:
        st.error(f"Error loading MITRE data: {e}")
        return [], {}, {}

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
        return json.dumps(layer, indent=2), layer_id, layer  # Added layer object to return values
    except Exception as e:
        st.error(f"Error creating Navigator layer: {e}")
        return "{}", "", {}

def load_tactics_data(attack_data):
    """Extract and order tactics from MITRE ATT&CK data"""
    tactics = []
    tactics_by_shortname = {}
    
    for obj in attack_data['objects']:
        if obj.get('type') == 'x-mitre-tactic':
            shortname = obj.get('x_mitre_shortname', '')
            tactic_id = obj.get('external_references', [{}])[0].get('external_id', 'N/A')
            tactic_name = obj.get('name', 'N/A')
            
            tactic_data = {
                'id': tactic_id,
                'name': tactic_name,
                'shortname': shortname
            }
            
            tactics.append(tactic_data)
            tactics_by_shortname[shortname] = tactic_data
    
    # Define the standard MITRE ATT&CK kill chain order
    kill_chain_order = [
        "reconnaissance", "resource-development", "initial-access", 
        "execution", "persistence", "privilege-escalation", "defense-evasion",
        "credential-access", "discovery", "lateral-movement", "collection",
        "command-and-control", "exfiltration", "impact"
    ]
    
    # Sort tactics according to the kill chain
    sorted_tactics = []
    for phase in kill_chain_order:
        if phase in tactics_by_shortname:
            sorted_tactics.append(tactics_by_shortname[phase])
    
    return sorted_tactics

def organize_techniques_by_tactic(attack_data, sorted_tactics):
    """Group techniques by tactic"""
    techniques_by_tactic = defaultdict(list)
    all_techniques = []
    
    for obj in attack_data['objects']:
        if obj.get('type') == 'attack-pattern':
            tech_id = obj.get('external_references', [{}])[0].get('external_id', 'N/A')
            if '.' in tech_id:  # Skip sub-techniques for simplicity
                continue
            
            tech_name = obj.get('name', 'N/A')
            tech_desc = obj.get('description', '')
            
            technique = {
                'id': tech_id,
                'name': tech_name,
                'description': tech_desc,
                'tactics': []
            }
            
            # Get all tactics this technique belongs to
            for phase in obj.get('kill_chain_phases', []):
                phase_name = phase.get('phase_name', '')
                technique['tactics'].append(phase_name)
                
                # Add to the techniques by tactic mapping
                for tactic in sorted_tactics:
                    if phase_name == tactic['name']:
                        techniques_by_tactic[tactic['id']].append(technique)
            
            all_techniques.append(technique)
    
    return techniques_by_tactic, all_techniques

def get_severity_color(count, max_count):
    """Get appropriate color based on count/severity"""
    if count == 0:
        return "#ffffff"  # White for no coverage
    
    # Create a color scale based on the MITRE ATT&CK matrix
    if count >= max_count * 0.8:
        return "#ff6666"  # Red - Highest severity/count
    elif count >= max_count * 0.6:
        return "#ffb366"  # Orange - High severity/count
    elif count >= max_count * 0.4:
        return "#ffcc66"  # Yellow-Orange - Medium severity/count
    elif count >= max_count * 0.2:
        return "#adebad"  # Light Green - Low severity/count
    else:
        return "#d6f5d6"  # Very Light Green - Very Low severity/count

def render_attack_matrix(layer_json, attack_data):
    """Create HTML visualization of MITRE ATT&CK matrix with layer data"""
    # Extract layer data
    layer_name = layer_json.get('name', 'Security Use Cases Mapping')
    techniques_data = layer_json.get('techniques', [])
    
    # Create mapping of technique IDs to their score/count
    techniques_count = {}
    for tech in techniques_data:
        tech_id = tech.get('techniqueID')
        score = tech.get('score', 0)
        techniques_count[tech_id] = score
    
    max_count = max(techniques_count.values()) if techniques_count else 1
    
    # Process tactics and techniques
    sorted_tactics = load_tactics_data(attack_data)
    techniques_by_tactic, all_techniques = organize_techniques_by_tactic(attack_data, sorted_tactics)
    
    # Start building the HTML
    html_content = """
    <style>
        .attack-matrix {
            font-family: Arial, sans-serif;
            border-collapse: collapse;
            width: 100%;
        }
        .attack-matrix-header {
            background-color: #f5f5f5;
            padding: 10px;
            text-align: center;
            font-weight: bold;
            font-size: 16px;
            border-bottom: 1px solid #ddd;
            margin-bottom: 10px;
        }
        .tactic-row {
            display: table-row;
            border-bottom: 1px solid #ccc;
        }
        .tactic-header {
            display: table-cell;
            width: 150px;
            background-color: #dddddd;
            padding: 10px;
            font-weight: bold;
            text-align: center;
            vertical-align: middle;
            border: 1px solid #aaa;
        }
        .techniques-container {
            display: table-cell;
            padding: 5px;
            border: 1px solid #aaa;
        }
        .technique-cell {
            display: inline-block;
            width: 120px;
            height: 70px;
            margin: 5px;
            padding: 5px;
            border: 1px solid #888;
            border-radius: 3px;
            position: relative;
            vertical-align: top;
            overflow: hidden;
            font-size: 11px;
        }
        .technique-id {
            font-weight: bold;
            font-size: 12px;
        }
        .technique-name {
            font-size: 11px;
            line-height: 1.2;
            margin-top: 2px;
        }
        .technique-count {
            position: absolute;
            top: 3px;
            right: 5px;
            background-color: white;
            border-radius: 9px;
            min-width: 18px;
            height: 18px;
            font-size: 11px;
            text-align: center;
            line-height: 18px;
            font-weight: bold;
            padding: 0 4px;
            box-sizing: border-box;
            box-shadow: 0 0 2px rgba(0,0,0,0.3);
        }
        .color-legend {
            display: flex;
            margin: 15px 0;
            justify-content: center;
            flex-wrap: wrap;
        }
        .legend-item {
            display: flex;
            align-items: center;
            margin: 5px 10px;
        }
        .legend-color {
            width: 20px;
            height: 20px;
            margin-right: 5px;
            border: 1px solid #888;
        }
    </style>
    
    <div class="attack-matrix-wrapper">
        <div class="attack-matrix-header">{}</div>
        
        <div class="color-legend">
            <div class="legend-item">
                <div class="legend-color" style="background-color: #ffffff;"></div>
                <div>No Coverage</div>
            </div>
            <div class="legend-item">
                <div class="legend-color" style="background-color: #d6f5d6;"></div>
                <div>Very Low</div>
            </div>
            <div class="legend-item">
                <div class="legend-color" style="background-color: #adebad;"></div>
                <div>Low</div>
            </div>
            <div class="legend-item">
                <div class="legend-color" style="background-color: #ffcc66;"></div>
                <div>Medium</div>
            </div>
            <div class="legend-item">
                <div class="legend-color" style="background-color: #ffb366;"></div>
                <div>High</div>
            </div>
            <div class="legend-item">
                <div class="legend-color" style="background-color: #ff6666;"></div>
                <div>Very High</div>
            </div>
        </div>
        
        <div class="attack-matrix">
    """.format(layer_name)
    
    # Add rows for each tactic
    for tactic in sorted_tactics:
        tactic_id = tactic['id']
        tactic_name = tactic['name']
        
        html_content += f'<div class="tactic-row">'
        html_content += f'<div class="tactic-header">{tactic_name}</div>'
        html_content += '<div class="techniques-container">'
        
        # Add techniques for this tactic
        tech_list = techniques_by_tactic.get(tactic_id, [])
        for tech in tech_list:
            tech_id = tech['id']
            tech_name = tech['name']
            count = techniques_count.get(tech_id, 0)
            color = get_severity_color(count, max_count)
            
            html_content += f"""
            <div class="technique-cell" style="background-color: {color};" title="{html.escape(tech_name)} ({tech_id})">
                <div class="technique-id">{tech_id}</div>
                <div class="technique-name">{html.escape(tech_name)}</div>
                {f'<div class="technique-count">{count}</div>' if count > 0 else ''}
            </div>
            """
        
        html_content += '</div></div>'
    
    html_content += """
        </div>
    </div>
    """
    
    return html_content

def display_attack_navigator(layer_json, attack_data):
    """Display the MITRE ATT&CK Navigator in Streamlit"""
    matrix_html = render_attack_matrix(layer_json, attack_data)
    st.components.v1.html(matrix_html, height=900, scrolling=True)

def main():
    st.title("MITRE ATT&CK Mapping Tool for Security Use Cases")
    model = load_model()
    if model is None:
        return
    mitre_techniques, tactic_mapping, attack_data = load_mitre_data()  # Now receiving the attack_data
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
            st.subheader("MITRE ATT&CK Navigator")

            # Generate the Navigator layer
            navigator_layer_json, layer_id, layer_obj = create_navigator_layer(techniques_count)
            
            # Display visualization options in tabs
            viz_tabs = st.tabs(["Interactive Matrix", "Layer JSON", "Export Options"])
            
            with viz_tabs[0]:
                st.markdown("### MITRE ATT&CK Matrix Visualization")
                # Display the custom MITRE ATT&CK Navigator visualization
                display_attack_navigator(layer_obj, attack_data)
            
            with viz_tabs[1]:
                st.markdown("### Navigator Layer JSON")
                st.code(navigator_layer_json, language="json")
            
            with viz_tabs[2]:
                st.markdown("### Export Options")
                # Provide direct download for navigator layer JSON
                st.download_button(
                    label="Download Navigator Layer JSON",
                    data=navigator_layer_json,
                    file_name="navigator_layer.json",
                    mime="application/json"
                )
                
                st.markdown("### Using with Official MITRE ATT&CK Navigator")
                st.markdown("""
                **Steps to view this layer in the official Navigator:**
                1. Download the Navigator Layer JSON using the button above
                2. Visit the [MITRE ATT&CK Navigator](https://mitre-attack.github.io/attack-navigator/)
                3. Click "Open Existing Layer" and then "Upload from Local"
                4. Select the downloaded `navigator_layer.json` file
                """)

        except Exception as e:
            st.exception(e)

if __name__ == '__main__':
    main()
