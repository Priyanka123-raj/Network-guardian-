import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
import joblib
import os
from datetime import datetime
from email_config import EmailAlert

class ThreatAnalyzer:
    def __init__(self):
        self.model = None
        self.model_path = 'threat_model.pkl'
        self.email_alert = EmailAlert()
        
        if os.path.exists(self.model_path):
            self.model = joblib.load(self.model_path)
        else:
            self.train_model()
    
    def train_model(self):
        # Training data: [requests, cpu, memory, failed_logins, threat_type]
        data = pd.DataFrame([
            # Normal traffic (threat_type = 0)
            [50, 30, 40, 2, 0],
            [80, 45, 55, 3, 0],
            [100, 48, 52, 4, 0],
            [70, 35, 45, 1, 0],
            [90, 42, 58, 2, 0],
            [60, 32, 42, 0, 0],
            [110, 50, 60, 3, 0],
            [45, 28, 38, 1, 0],
            [85, 40, 50, 2, 0],
            [95, 46, 56, 4, 0],
            
            # DDoS Attack (threat_type = 1)
            [500, 85, 90, 5, 1],
            [800, 92, 95, 8, 1],
            [1000, 98, 99, 15, 1],
            [1200, 99, 98, 20, 1],
            [600, 88, 92, 6, 1],
            [900, 95, 96, 12, 1],
            [700, 90, 93, 10, 1],
            [1100, 97, 98, 18, 1],
            [550, 86, 89, 7, 1],
            [950, 96, 97, 14, 1],
            
            # Brute Force Attack (threat_type = 2)
            [150, 65, 70, 25, 2],
            [180, 68, 72, 35, 2],
            [200, 72, 75, 45, 2],
            [220, 75, 78, 55, 2],
            [160, 66, 71, 30, 2],
            [190, 70, 73, 40, 2],
            [210, 74, 76, 50, 2],
            [170, 67, 72, 32, 2],
            [230, 76, 79, 60, 2],
            [140, 64, 69, 28, 2],
        ], columns=['requests', 'cpu', 'memory', 'failed_logins', 'threat'])
        
        X = data[['requests', 'cpu', 'memory', 'failed_logins']]
        y = data['threat']
        
        self.model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.model.fit(X, y)
        joblib.dump(self.model, self.model_path)
        print("✅ AI Model trained!")
    
    def analyze_threat(self, device_data, device_name=None):
        features = [[
            device_data.get('requests', 50),
            device_data.get('cpu', 50),
            device_data.get('memory', 50),
            device_data.get('failed_logins', 0)
        ]]
        
        threat_type = self.model.predict(features)[0]
        probability = self.model.predict_proba(features)[0].max()
        
        result = self.get_analysis(threat_type, device_data, probability)
        
        # Send email only if threat is HIGH
        if threat_type != 0 and device_name and result['severity'] == 'HIGH':
            self.email_alert.send_alert(
                device_name=device_name,
                threat_type=result['threat_type'],
                root_cause=result['root_cause'],
                severity=result['severity'],
                traffic=f"{device_data.get('requests', 0)} req/sec"
            )
        
        return result
    
    def get_analysis(self, threat_type, data, probability):
        if threat_type == 1:
            return {
                'threat_type': 'DDoS Attack',
                'confidence': round(probability * 100, 2),
                'root_cause': f"Traffic spike: {data.get('requests', 0)} req/sec (Normal: <100)",
                'recommendation': 'Block source IP, Enable rate limiting, Contact ISP',
                'severity': 'HIGH',
                'action': 'block'
            }
        elif threat_type == 2:
            return {
                'threat_type': 'Brute Force Attack',
                'confidence': round(probability * 100, 2),
                'root_cause': f"Failed login attempts: {data.get('failed_logins', 0)} (Normal: <5)",
                'recommendation': 'Enable CAPTCHA, Temporarily block IP, Force password reset',
                'severity': 'MEDIUM',
                'action': 'monitor'
            }
        else:
            return {
                'threat_type': 'Normal Traffic',
                'confidence': round(probability * 100, 2),
                'root_cause': 'No threat detected - Normal operation',
                'recommendation': 'Continue monitoring',
                'severity': 'LOW',
                'action': 'none'
            }

analyzer = ThreatAnalyzer()
