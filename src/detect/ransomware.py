"""
Ransomware detection using machine learning.
"""

import torch
import torch.nn as nn
from typing import Dict, List
import numpy as np


class RansomwareDetector(nn.Module):
    """Ransomware detection model."""

    def __init__(self, input_dim: int = 100, hidden_dim: int = 128, num_classes: int = 2):
        super().__init__()
        self.encoder = nn.Sequential(
            nn.Linear(input_dim, hidden_dim),
            nn.ReLU(),
            nn.Dropout(0.3),
            nn.Linear(hidden_dim, hidden_dim),
            nn.ReLU(),
            nn.Dropout(0.3),
        )
        self.classifier = nn.Linear(hidden_dim, num_classes)

    def forward(self, x):
        features = self.encoder(x)
        return self.classifier(features)


class BehavioralDetector:
    """Detect ransomware based on behavioral features."""

    FEATURES = [
        'file_extension_changes',
        'encryption_api_calls',
        'file_overwrite_ratio',
        'size_change_rate',
        'deletion_attempts',
        'shadow_copy_delete',
        'master_boot_record_write',
        'process_hollowing',
        'suspicious_network',
        'ransom_note_created',
    ]

    def extract_features(self, behavior_log: Dict) -> np.ndarray:
        """Extract behavioral features."""
        features = []
        for feature_name in self.FEATURES:
            value = behavior_log.get(feature_name, 0)
            features.append(value)
        return np.array(features)

    def predict(self, model, features: np.ndarray) -> Dict:
        """Predict ransomware probability."""
        model.eval()
        with torch.no_grad():
            x = torch.tensor(features, dtype=torch.float32).unsqueeze(0)
            output = model(x)
            probs = torch.softmax(output, dim=1)

        return {
            'is_ransomware': bool(probs[0, 1] > 0.5),
            'confidence': float(probs[0, 1]),
            'probabilities': probs[0].tolist(),
        }


class EarlyDetector:
    """Early-stage ransomware detection."""

    def __init__(self, model: nn.Module, threshold: float = 0.3):
        self.model = model
        self.threshold = threshold

    def detect_early(self, features: np.ndarray, time_window: int = 10) -> Dict:
        """Detect ransomware in early stages.

        Args:
            features: Behavioral features over time
            time_window: Number of time steps to consider

        Returns:
            Detection result with warning level
        """
        model.eval()
        warnings = []

        # Check key indicators
        if features[6] > 0.5:  # Shadow copy deletion
            warnings.append('CRITICAL: Shadow copies being deleted')

        if features[4] > 0.7:  # High deletion attempts
            warnings.append('HIGH: Many file deletion attempts')

        if features[9] > 0.5:  # Ransom note
            warnings.append('CRITICAL: Ransom note detected')

        # Model prediction
        with torch.no_grad():
            x = torch.tensor(features, dtype=torch.float32).unsqueeze(0)
            output = self.model(x)
            probs = torch.softmax(output, dim=1)

        risk_level = 'LOW'
        if probs[0, 1] > 0.7 or len(warnings) >= 2:
            risk_level = 'HIGH'
        elif probs[0, 1] > self.threshold:
            risk_level = 'MEDIUM'

        return {
            'risk_level': risk_level,
            'ransomware_probability': float(probs[0, 1]),
            'warnings': warnings,
            'recommendation': self._get_recommendation(risk_level),
        }

    def _get_recommendation(self, risk_level: str) -> str:
        """Get security recommendation."""
        recommendations = {
            'LOW': 'Continue monitoring',
            'MEDIUM': 'Alert security team, isolate affected system',
            'HIGH': 'Immediate action: isolate system, block network, backup critical data',
        }
        return recommendations.get(risk_level, 'Unknown')


def create_detector(model_path: str = None) -> RansomwareDetector:
    """Create ransomware detector."""
    model = RansomwareDetector()
    if model_path:
        model.load_state_dict(torch.load(model_path))
    return model
