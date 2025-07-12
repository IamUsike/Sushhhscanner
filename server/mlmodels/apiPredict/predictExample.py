import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from urllib.parse import urlparse
import re

class SimpleEndpointPredictor:
    def __init__(self):
        self.model = RandomForestClassifier(n_estimators=10, random_state=42)
        self.is_trained = False
    
    def extract_simple_features(self, url):
        """Extract simple features that humans can understand"""
        path = urlparse(url).path.lower()
        
        features = {
            'has_api': 1 if 'api' in path else 0,
            'has_admin': 1 if 'admin' in path else 0,
            'has_auth': 1 if 'auth' in path else 0,
            'has_user': 1 if 'user' in path else 0,
            'has_config': 1 if 'config' in path else 0,
            'has_debug': 1 if 'debug' in path else 0,
            'path_length': len(path),
            'path_depth': len(path.split('/')) - 1,
            'has_numbers': 1 if re.search(r'\d', path) else 0,
            'has_version': 1 if re.search(r'v\d', path) else 0,
        }
        
        return features

    def demonstrate_training(self):
        """Show exactly what happens during training"""
        print("=== DEMONSTRATION: How ML Model Learns ===\n")
        
        # STEP 1: Your crawler found these real endpoints
        real_urls = [
            "https://api.example.com/v1/users",
            "https://api.example.com/v1/auth/login", 
            "https://api.example.com/admin/config",
            "https://api.example.com/api/debug/logs",
            "https://example.com/user/profile",
        ]
        
        # STEP 2: Generate fake endpoints that probably don't exist
        fake_urls = [
            "https://api.example.com/v1/nonexistent",
            "https://api.example.com/fake/endpoint",
            "https://api.example.com/random/stuff",
            "https://example.com/impossible/path",
            "https://api.example.com/xyz/abc",
        ]
        
        print("REAL ENDPOINTS (from your crawler):")
        for url in real_urls:
            print(f"  ✅ {url}")
        
        print("\nFAKE ENDPOINTS (generated):")
        for url in fake_urls:
            print(f"  ❌ {url}")
        
        # STEP 3: Convert URLs to features
        print("\n=== FEATURE EXTRACTION ===")
        all_urls = real_urls + fake_urls
        all_features = []
        all_labels = []
        
        for i, url in enumerate(all_urls):
            features = self.extract_simple_features(url)
            all_features.append(features)
            
            # Label: 1 for real, 0 for fake
            label = 1 if i < len(real_urls) else 0
            all_labels.append(label)
            
            print(f"{url}")
            print(f"  Features: {features}")
            print(f"  Label: {label} ({'REAL' if label == 1 else 'FAKE'})")
            print()
        
        # STEP 4: Train the model
        print("=== TRAINING THE MODEL ===")
        features_df = pd.DataFrame(all_features)
        labels = np.array(all_labels)
        
        print("Features DataFrame:")
        print(features_df)
        print(f"\nLabels: {labels}")
        
        # Actually train the model
        self.model.fit(features_df, labels)
        self.is_trained = True
        
        print("\n✅ Model trained!")
        
        # STEP 5: Show what the model learned
        print("\n=== WHAT THE MODEL LEARNED ===")
        feature_importance = self.model.feature_importances_
        feature_names = features_df.columns
        
        print("Feature importance (what the model thinks is important):")
        for name, importance in zip(feature_names, feature_importance):
            print(f"  {name}: {importance:.3f}")
        
        return features_df, labels
    
    def demonstrate_prediction(self):
        """Show exactly how predictions work"""
        if not self.is_trained:
            print("Model not trained yet!")
            return
        
        print("\n=== DEMONSTRATION: How Predictions Work ===\n")
        
        # Test with new URLs
        test_urls = [
            "https://api.example.com/v1/orders",      # Should be HIGH probability
            "https://api.example.com/admin/users",    # Should be HIGH probability  
            "https://api.example.com/random/xyz",     # Should be LOW probability
            "https://example.com/completely/random",  # Should be LOW probability
        ]
        
        print("PREDICTING NEW ENDPOINTS:")
        for url in test_urls:
            # Extract features
            features = self.extract_simple_features(url)
            features_df = pd.DataFrame([features])
            
            # Get prediction
            probability = self.model.predict_proba(features_df)[0][1]  # Probability it's real
            prediction = "LIKELY EXISTS" if probability > 0.5 else "PROBABLY FAKE"
            
            print(f"\n🔍 {url}")
            print(f"   Features: {features}")
            print(f"   Probability: {probability:.3f}")
            print(f"   Prediction: {prediction}")
    
    def explain_decision_making(self):
        """Explain how the model makes decisions"""
        print("\n=== HOW THE MODEL MAKES DECISIONS ===\n")
        
        print("The Random Forest model creates many 'decision trees'.")
        print("Each tree asks questions like:")
        print("  - Does the URL contain 'api'? → If YES, more likely to be real")
        print("  - Does the URL contain 'admin'? → If YES, more likely to be real")
        print("  - Is the path very long? → If YES, might be fake")
        print("  - Does it have version numbers? → If YES, more likely to be real")
        print("")
        print("The model combines all these 'votes' to make a final prediction.")
        print("")
        print("🧠 KEY INSIGHT: The model learns PATTERNS from your real data!")
        print("   If your crawler found lots of '/api/v1/*' endpoints,")
        print("   the model learns that '/api/v1/*' patterns are probably real.")

# Run the demonstration
if __name__ == "__main__":
    predictor = SimpleEndpointPredictor()
    
    # Show the training process
    features_df, labels = predictor.demonstrate_training()
    
    # Show how predictions work
    predictor.demonstrate_prediction()
    
    # Explain decision making
    predictor.explain_decision_making()
    
    print("\n" + "="*60)
    print("SUMMARY:")
    print("1. Model learns from your REAL crawler data")
    print("2. Model learns patterns that distinguish real vs fake URLs")
    print("3. Model uses these patterns to predict new endpoints")
    print("4. Higher probability = more likely to be a real endpoint")
    print("="*60)
