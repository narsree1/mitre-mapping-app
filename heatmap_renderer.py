# heatmap_renderer.py
import streamlit as st
import requests
import json
import html
from collections import defaultdict

@st.cache_data
def load_mitre_data():
    """Load MITRE ATT&CK data for the matrix visualization"""
    try:
        response = requests.get("https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json")
        attack_data = response.json()
        
        # Process tactics to maintain the correct order
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
        
        # Process techniques
        techniques_by_tactic = defaultdict(list)
        all_techniques = []
        
        for obj in attack_data['objects']:
            if obj.get('type') == 'attack-pattern':
                tech_id = obj.get('external_references', [{}])[0].get('external_id', 'N/A')
                if '.' in tech_id:  # Skip sub-techniques for now
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
        
        return sorted_tactics, techniques_by_tactic, all_techniques
    
    except Exception as e:
        st.error(f"Error loading MITRE data: {e}")
        return [], {}, []

def get_severity_color(count, max_count):
    """Get the appropriate color for a technique based on its count/score"""
    if count == 0:
        return "#ffffff"  # White for no coverage
    
    # Create a color scale based on the image shared (red, orange, yellow, green)
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

def render_attack_matrix(techniques_count):
    """Create an HTML visualization matching the MITRE ATT&CK Navigator style"""
    # Load MITRE ATT&CK data
    sorted_tactics, techniques_by_tactic, all_techniques = load_mitre_data()
    
    if not sorted_tactics:
        return "<div>Error loading MITRE ATT&CK data</div>"
    
    # Create mapping of technique IDs to their count
    max_count = max(techniques_count.values()) if techniques_count else 1
    
    # Start building the HTML for the matrix
    html_content = """
    <style>
        .attack-matrix {
            display: table;
            width: 100%;
            border-collapse: collapse;
            font-family: Arial, sans-serif;
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
            width: 110px;
            height: 70px;
            margin: 4px;
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
        }
        .color-legend {
            display: flex;
            margin-top: 20px;
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
        .matrix-header {
            font-weight: bold;
            font-size: 16px;
            margin-bottom: 10px;
            text-align: center;
        }
    </style>
    <div class="matrix-header">MITRE ATT&CK Heat Map</div>
    <div class="attack-matrix">
    """
    
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
            <div class="technique-cell" style="background-color: {color};">
                <div class="technique-id">{tech_id}</div>
                <div class="technique-name">{html.escape(tech_name)}</div>
                {f'<div class="technique-count">{count}</div>' if count > 0 else ''}
            </div>
            """
        
        html_content += '</div></div>'
    
    # Add a color legend
    html_content += """
    </div>
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
    """
    
    return html_content

def display_attack_matrix(techniques_count):
    """Display the MITRE ATT&CK matrix in Streamlit"""
    matrix_html = render_attack_matrix(techniques_count)
    st.components.v1.html(matrix_html, height=900, scrolling=True)
