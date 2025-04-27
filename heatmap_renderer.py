# heatmap_renderer.py
# Save this as a separate file in your project directory

import streamlit as st
import json
import html
import requests

def load_mitre_tactics():
    """Load MITRE tactics data for the heatmap"""
    try:
        response = requests.get("https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json")
        attack_data = response.json()
        tactics_list = []

        # Extract tactics first to build the ordered list
        for obj in attack_data['objects']:
            if obj.get('type') == 'x-mitre-tactic':
                tactic_id = obj.get('external_references', [{}])[0].get('external_id', 'N/A')
                tactic_name = obj.get('name', 'N/A')
                # Store tactics with their order in the kill chain
                order = obj.get('x_mitre_shortname', '')
                tactics_list.append({
                    'id': tactic_id, 
                    'name': tactic_name,
                    'shortname': order
                })
        
        # Sort tactics by their kill chain order
        tactics_list = sorted(tactics_list, key=lambda x: x['shortname'])
        return tactics_list
    except Exception as e:
        st.error(f"Error loading MITRE tactics data: {e}")
        return []

def load_techniques_by_tactic():
    """Get a mapping of techniques by tactic"""
    try:
        response = requests.get("https://raw.githubusercontent.com/mitre-attack/attack-stix-data/master/enterprise-attack/enterprise-attack.json")
        attack_data = response.json()
        
        techniques_by_tactic = {}
        techniques_list = []
        
        # First collect all techniques
        for obj in attack_data['objects']:
            if obj.get('type') == 'attack-pattern':
                tech_id = obj.get('external_references', [{}])[0].get('external_id', 'N/A')
                if '.' in tech_id:
                    continue  # Skip sub-techniques for simplified view
                    
                technique = {
                    'id': tech_id,
                    'name': obj.get('name', 'N/A'),
                    'tactics_list': [phase['phase_name'] for phase in obj.get('kill_chain_phases', [])]
                }
                techniques_list.append(technique)
                
                # Add to techniques by tactic mapping
                for tactic_name in technique['tactics_list']:
                    if tactic_name not in techniques_by_tactic:
                        techniques_by_tactic[tactic_name] = []
                    techniques_by_tactic[tactic_name].append(technique)
        
        return techniques_by_tactic, techniques_list
    except Exception as e:
        st.error(f"Error loading MITRE techniques data: {e}")
        return {}, []

def render_mitre_heatmap(techniques_count):
    """Create an HTML heatmap visualization similar to MITRE ATT&CK Navigator"""
    
    tactics_list = load_mitre_tactics()
    techniques_by_tactic, all_techniques = load_techniques_by_tactic()
    
    # Mapping of technique IDs to the complete technique object
    tech_map = {tech['id']: tech for tech in all_techniques}
    
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
            width: 150px;
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
        if tactic_name in techniques_by_tactic:
            for tech in techniques_by_tactic[tactic_name]:
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

def display_heatmap(techniques_count):
    """Display the MITRE ATT&CK heat map"""
    heat_map_html = render_mitre_heatmap(techniques_count)
    st.components.v1.html(heat_map_html, height=800, scrolling=True)
