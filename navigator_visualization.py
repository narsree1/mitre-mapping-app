# navigator_visualization.py
# Save this as a separate file in your project directory

import streamlit as st
import json
import html
from collections import defaultdict

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
