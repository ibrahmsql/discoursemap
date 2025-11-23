"""
Report Styles Module

Contains CSS styles for HTML reports.
"""

def get_css_styles() -> str:
    """Get CSS styles for the HTML report"""
    
    return """
    body {
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        line-height: 1.6;
        margin: 0;
        padding: 0;
        background-color: #f5f5f5;
    }
    
    .container {
        max-width: 1200px;
        margin: 0 auto;
        padding: 20px;
        background-color: white;
        box-shadow: 0 0 10px rgba(0,0,0,0.1);
    }
    
    .report-header {
        border-bottom: 3px solid #2c3e50;
        padding-bottom: 20px;
        margin-bottom: 30px;
    }
    
    .report-header h1 {
        color: #2c3e50;
        margin: 0;
        font-size: 2.5em;
    }
    
    .report-info {
        margin-top: 15px;
        color: #666;
    }
    
    .executive-summary {
        background-color: #ecf0f1;
        padding: 20px;
        border-radius: 8px;
        margin-bottom: 30px;
    }
    
    .risk-level {
        display: inline-block;
        padding: 8px 16px;
        border-radius: 4px;
        font-weight: bold;
        text-transform: uppercase;
    }
    
    .risk-critical { background-color: #e74c3c; color: white; }
    .risk-high { background-color: #e67e22; color: white; }
    .risk-medium { background-color: #f39c12; color: white; }
    .risk-low { background-color: #27ae60; color: white; }
    .risk-minimal { background-color: #95a5a6; color: white; }
    
    .vulnerability-stats {
        display: grid;
        grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
        gap: 15px;
        margin: 20px 0;
    }
    
    .stat-card {
        background: white;
        padding: 15px;
        border-radius: 6px;
        border-left: 4px solid #3498db;
        box-shadow: 0 2px 4px rgba(0,0,0,0.1);
    }
    
    .stat-number {
        font-size: 2em;
        font-weight: bold;
        color: #2c3e50;
    }
    
    .stat-label {
        color: #666;
        text-transform: uppercase;
        font-size: 0.9em;
    }
    
    .module-section {
        margin-bottom: 30px;
        border: 1px solid #ddd;
        border-radius: 6px;
        overflow: hidden;
    }
    
    .module-header {
        background-color: #34495e;
        color: white;
        padding: 15px;
        font-weight: bold;
    }
    
    .module-content {
        padding: 20px;
    }
    
    .vulnerability {
        background-color: #fff5f5;
        border-left: 4px solid #e74c3c;
        padding: 15px;
        margin: 10px 0;
        border-radius: 4px;
    }
    
    .vulnerability.medium {
        background-color: #fffbf0;
        border-left-color: #f39c12;
    }
    
    .vulnerability.low {
        background-color: #f0fff4;
        border-left-color: #27ae60;
    }
    
    .recommendation {
        background-color: #f8f9fa;
        border-left: 4px solid #17a2b8;
        padding: 15px;
        margin: 10px 0;
        border-radius: 4px;
    }
    
    .report-footer {
        text-align: center;
        margin-top: 40px;
        padding-top: 20px;
        border-top: 1px solid #ddd;
        color: #666;
    }
    
    table {
        width: 100%;
        border-collapse: collapse;
        margin: 15px 0;
    }
    
    th, td {
        padding: 12px;
        text-align: left;
        border-bottom: 1px solid #ddd;
    }
    
    th {
        background-color: #f8f9fa;
        font-weight: bold;
    }
    """
