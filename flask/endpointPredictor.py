import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import StandardScaler
import joblib
import json
import os
import re
import math
from datetime import datetime
from typing import List, Dict, Tuple, Optional
import sqlite3
from urllib.parse import urlparse, urljoin
import requests
from flask import Flask, request, jsonify
import threading
import time
from collections import Counter

class EnhancedAPIPredictor:
    def __init__(self, model_path="api_predictor.pkl", data_path="api_training.db"):
        self.model_path = model_path
        self.data_path = data_path
        self.scaler = StandardScaler()
        self.models = {
            'rf': RandomForestClassifier(n_estimators=200, max_depth=10, random_state=42),
            'gb': GradientBoostingClassifier(n_estimators=100, max_depth=6, random_state=42),
            'lr': LogisticRegression(random_state=42, max_iter=1000)
        }
        self.best_model = None
        self.best_model_name = None
        self.feature_names = []
        
        # API endpoint patterns for better prediction
        self.api_patterns = [
            r'/api/v\d+/',
            r'/rest/',
            r'/graphql',
            r'/webhook',
            r'/oauth',
            r'/auth',
            r'/login',
            r'/admin',
            r'/dashboard',
            r'/health',
            r'/status',
            r'/metrics',
            r'/docs',
            r'/swagger',
            r'/openapi'
        ]
        
        self.common_resources = [
            'users', 'user', 'accounts', 'account', 'products', 'product',
            'orders', 'order', 'items', 'item', 'posts', 'post',
            'comments', 'comment', 'files', 'file', 'images', 'image',
            'config', 'settings', 'preferences', 'profile', 'search',
            'notifications', 'messages', 'reports', 'analytics'
        ]
        
        self.init_database()
        self.load_model_if_exists()
    
    def init_database(self):
        """Initialize SQLite database with enhanced schema"""
        conn = sqlite3.connect(self.data_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS training_endpoints (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT UNIQUE,
                domain TEXT,
                path TEXT,
                label INTEGER,
                source TEXT,
                confidence REAL,
                status_code INTEGER,
                response_time REAL,
                content_type TEXT,
                date_added TEXT,
                last_validated TEXT,
                validation_count INTEGER DEFAULT 0
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS model_performance (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                model_name TEXT,
                training_date TEXT,
                accuracy REAL,
                precision REAL,
                recall REAL,
                f1_score REAL,
                total_samples INTEGER,
                cross_val_score REAL
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS prediction_history (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                url TEXT,
                predicted_probability REAL,
                actual_result INTEGER,
                prediction_date TEXT,
                validated BOOLEAN DEFAULT FALSE
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def calculate_entropy(self, text: str) -> float:
        """Calculate entropy of text (measure of randomness)"""
        if not text:
            return 0
        
        counts = Counter(text)
        total = len(text)
        entropy = 0
        
        for count in counts.values():
            p = count / total
            if p > 0:
                entropy -= p * math.log2(p)
        
        return entropy
    
    def extract_enhanced_features(self, url: str) -> Dict:
        """Extract comprehensive features from URL"""
        parsed = urlparse(url)
        path = parsed.path.lower()
        domain = parsed.netloc.lower()
        
        # Basic features
        features = {
            'path_length': len(path),
            'path_depth': len([p for p in path.split('/') if p]),
            'domain_length': len(domain),
            'has_port': 1 if parsed.port else 0,
            'is_https': 1 if parsed.scheme == 'https' else 0,
            'subdomain_count': len(domain.split('.')) - 2,
        }
        
        # Pattern matching features
        for i, pattern in enumerate(self.api_patterns):
            features[f'pattern_{i}'] = 1 if re.search(pattern, path) else 0
        
        # Resource detection
        for resource in self.common_resources:
            features[f'has_{resource}'] = 1 if resource in path else 0
        
        # Advanced features
        features.update({
            'path_entropy': self.calculate_entropy(path),
            'has_numbers': 1 if any(c.isdigit() for c in path) else 0,
            'has_underscore': 1 if '_' in path else 0,
            'has_dash': 1 if '-' in path else 0,
            'segment_count': len(path.split('/')),
            'avg_segment_length': np.mean([len(seg) for seg in path.split('/') if seg]) if path != '/' else 0,
            'has_extension': 1 if '.' in path.split('/')[-1] else 0,
            'has_query': 1 if parsed.query else 0,
            'has_fragment': 1 if parsed.fragment else 0,
        })
        
        # Linguistic features
        words = re.findall(r'\b\w+\b', path)
        features.update({
            'word_count': len(words),
            'avg_word_length': np.mean([len(word) for word in words]) if words else 0,
            'has_crud_words': 1 if any(word in path for word in ['create', 'read', 'update', 'delete', 'get', 'post', 'put', 'patch']) else 0,
        })
        
        return features
    
    def generate_smart_synthetic_data(self, real_urls: List[str], ratio: float = 0.5) -> List[str]:
        """Generate intelligent synthetic negative examples"""
        synthetic = []
        domains = list(set(urlparse(url).netloc for url in real_urls))
        
        for domain in domains:
            base = f"https://{domain}"
            
            # Generate variations of real endpoints
            for real_url in real_urls[:5]:  # Use first 5 real URLs as templates
                parsed = urlparse(real_url)
                path_parts = [p for p in parsed.path.split('/') if p]
                
                if len(path_parts) >= 2:
                    # Create similar but fake paths
                    synthetic.extend([
                        f"{base}/{path_parts[0]}/nonexistent",
                        f"{base}/{path_parts[0]}/fake_{path_parts[1]}" if len(path_parts) > 1 else f"{base}/{path_parts[0]}/fake",
                        f"{base}/{path_parts[0]}/v99/{path_parts[1]}" if 'v' in path_parts[0] and len(path_parts) > 1 else f"{base}/fake/endpoint",
                        f"{base}/{path_parts[0]}/{path_parts[1]}_deprecated" if len(path_parts) > 1 else f"{base}/deprecated/endpoint",
                    ])
            
            # Add common fake patterns
            synthetic.extend([
                f"{base}/api/v1/nonexistent",
                f"{base}/api/v99/fake",
                f"{base}/admin/fake_section",
                f"{base}/debug/nonexistent",
                f"{base}/test/fake_endpoint",
                f"{base}/internal/fake_api",
                f"{base}/hidden/secret_endpoint",
                f"{base}/backup/old_api",
                f"{base}/temp/test_endpoint",
                f"{base}/dev/fake_service",
            ])
        
        return list(set(synthetic))[:int(len(real_urls) * ratio)]
    
    def add_training_data(self, urls: List[str], labels: List[int], source: str = "crawler", 
                         metadata: Optional[List[Dict]] = None):
        """Add training data with enhanced metadata"""
        conn = sqlite3.connect(self.data_path)
        cursor = conn.cursor()
        
        new_data_count = 0
        current_time = datetime.now().isoformat()
        
        for i, (url, label) in enumerate(zip(urls, labels)):
            parsed = urlparse(url)
            meta = metadata[i] if metadata and i < len(metadata) else {}
            
            try:
                cursor.execute('''
                    INSERT INTO training_endpoints 
                    (url, domain, path, label, source, confidence, status_code, 
                     response_time, content_type, date_added, last_validated)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ''', (
                    url, parsed.netloc, parsed.path, label, source, 
                    meta.get('confidence', 1.0), meta.get('status_code'),
                    meta.get('response_time'), meta.get('content_type'),
                    current_time, current_time
                ))
                new_data_count += 1
            except sqlite3.IntegrityError:
                # Update existing record
                cursor.execute('''
                    UPDATE training_endpoints 
                    SET last_validated = ?, validation_count = validation_count + 1,
                        status_code = ?, response_time = ?, content_type = ?
                    WHERE url = ?
                ''', (current_time, meta.get('status_code'), 
                      meta.get('response_time'), meta.get('content_type'), url))
        
        conn.commit()
        conn.close()
        
        print(f"✅ Added {new_data_count} new URLs to training data")
        
        if new_data_count > 0:
            self.retrain_model()
    
    def retrain_model(self):
        """Retrain all models and select the best one"""
        print("🔄 Retraining models...")
        
        conn = sqlite3.connect(self.data_path)
        df = pd.read_sql_query('SELECT * FROM training_endpoints', conn)
        conn.close()
        
        if len(df) < 50:
            print("⚠️  Not enough data to retrain (need at least 50 samples)")
            return
        
        # Extract features
        features = []
        for url in df['url']:
            features.append(self.extract_enhanced_features(url))
        
        X = pd.DataFrame(features)
        y = df['label'].values
        
        # Store feature names
        self.feature_names = X.columns.tolist()
        
        # Scale features
        X_scaled = self.scaler.fit_transform(X)
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X_scaled, y, test_size=0.2, random_state=42, stratify=y
        )
        
        best_score = 0
        best_model = None
        best_name = None
        
        # Train and evaluate each model
        for name, model in self.models.items():
            print(f"  Training {name}...")
            
            # Cross-validation
            cv_scores = cross_val_score(model, X_train, y_train, cv=5, scoring='accuracy')
            cv_mean = cv_scores.mean()
            
            # Fit model
            model.fit(X_train, y_train)
            
            # Test accuracy
            test_score = model.score(X_test, y_test)
            
            print(f"    CV Score: {cv_mean:.3f} ± {cv_scores.std():.3f}")
            print(f"    Test Score: {test_score:.3f}")
            
            # Select best model
            if cv_mean > best_score:
                best_score = cv_mean
                best_model = model
                best_name = name
        
        self.best_model = best_model
        self.best_model_name = best_name
        
        # Save performance
        self.save_performance_metrics(best_name, best_score, test_score, len(df))
        self.save_model()
        
        print(f"✅ Best model: {best_name} with CV score: {best_score:.3f}")
    
    def predict_with_confidence(self, urls: List[str]) -> List[Dict]:
        """Make predictions with detailed confidence scores"""
        if not self.best_model:
            print("⚠️  No trained model available!")
            return []
        
        predictions = []
        
        for url in urls:
            try:
                features = self.extract_enhanced_features(url)
                X = pd.DataFrame([features])
                X_scaled = self.scaler.transform(X)
                
                # Get prediction probability
                if hasattr(self.best_model, 'predict_proba'):
                    prob = self.best_model.predict_proba(X_scaled)[0][1]
                else:
                    prob = self.best_model.decision_function(X_scaled)[0]
                    prob = 1 / (1 + np.exp(-prob))  # Sigmoid transformation
                
                confidence_level = (
                    'very_high' if prob > 0.9 else
                    'high' if prob > 0.7 else
                    'medium' if prob > 0.5 else
                    'low' if prob > 0.3 else
                    'very_low'
                )
                
                predictions.append({
                    'url': url,
                    'probability': float(prob),
                    'confidence_level': confidence_level,
                    'model_used': self.best_model_name,
                    'features': features
                })
                
            except Exception as e:
                print(f"Error predicting {url}: {str(e)}")
                predictions.append({
                    'url': url,
                    'probability': 0.0,
                    'confidence_level': 'error',
                    'error': str(e)
                })
        
        return sorted(predictions, key=lambda x: x['probability'], reverse=True)
    
    def validate_predictions(self, predictions: List[Dict], timeout: int = 5) -> List[Dict]:
        """Validate predictions by testing endpoints"""
        print(f"🔍 Validating top {min(20, len(predictions))} predictions...")
        
        validated_urls = []
        validated_labels = []
        validation_metadata = []
        
        for pred in predictions[:20]:
            url = pred['url']
            start_time = time.time()
            
            try:
                response = requests.head(url, timeout=timeout, allow_redirects=True)
                response_time = time.time() - start_time
                exists = response.status_code < 400
                
                pred.update({
                    'validated': True,
                    'status_code': response.status_code,
                    'exists': exists,
                    'response_time': response_time,
                    'content_type': response.headers.get('content-type', ''),
                    'validation_date': datetime.now().isoformat()
                })
                
                validated_urls.append(url)
                validated_labels.append(1 if exists else 0)
                validation_metadata.append({
                    'status_code': response.status_code,
                    'response_time': response_time,
                    'content_type': response.headers.get('content-type', ''),
                    'confidence': pred['probability']
                })
                
                print(f"  {'✅' if exists else '❌'} {url} → {response.status_code}")
                
            except Exception as e:
                pred.update({
                    'validated': False,
                    'exists': False,
                    'error': str(e),
                    'validation_date': datetime.now().isoformat()
                })
                
                validated_urls.append(url)
                validated_labels.append(0)
                validation_metadata.append({
                    'status_code': None,
                    'response_time': None,
                    'content_type': None,
                    'confidence': pred['probability']
                })
                
                print(f"  ❌ {url} → Error: {str(e)[:50]}")
        
        # Add validation results to training data
        if validated_urls:
            self.add_training_data(validated_urls, validated_labels, 
                                 source="validation", metadata=validation_metadata)
        
        return predictions
    
    def generate_candidates(self, base_urls: List[str], max_per_domain: int = 50) -> List[str]:
        """Generate candidate endpoints for testing"""
        candidates = []
        
        for base_url in base_urls:
            parsed = urlparse(base_url)
            domain_base = f"{parsed.scheme}://{parsed.netloc}"
            
            # API endpoints
            api_candidates = [
                f"{domain_base}/api/v1/users",
                f"{domain_base}/api/v1/auth",
                f"{domain_base}/api/v1/config",
                f"{domain_base}/api/v1/admin",
                f"{domain_base}/api/v1/health",
                f"{domain_base}/api/v1/status",
                f"{domain_base}/api/v1/metrics",
                f"{domain_base}/api/v1/docs",
                f"{domain_base}/api/v2/users",
                f"{domain_base}/api/v2/auth",
                f"{domain_base}/rest/users",
                f"{domain_base}/rest/auth",
                f"{domain_base}/graphql",
                f"{domain_base}/graphiql",
            ]
            
            # Admin endpoints
            admin_candidates = [
                f"{domain_base}/admin",
                f"{domain_base}/admin/dashboard",
                f"{domain_base}/admin/users",
                f"{domain_base}/admin/config",
                f"{domain_base}/admin/settings",
                f"{domain_base}/admin/logs",
                f"{domain_base}/administrator",
                f"{domain_base}/wp-admin",
                f"{domain_base}/phpmyadmin",
            ]
            
            # Debug/monitoring endpoints
            debug_candidates = [
                f"{domain_base}/debug",
                f"{domain_base}/debug/info",
                f"{domain_base}/health",
                f"{domain_base}/healthz",
                f"{domain_base}/status",
                f"{domain_base}/metrics",
                f"{domain_base}/stats",
                f"{domain_base}/monitor",
                f"{domain_base}/ping",
                f"{domain_base}/version",
            ]
            
            # Documentation endpoints
            docs_candidates = [
                f"{domain_base}/docs",
                f"{domain_base}/documentation",
                f"{domain_base}/api-docs",
                f"{domain_base}/swagger",
                f"{domain_base}/swagger-ui",
                f"{domain_base}/openapi",
                f"{domain_base}/redoc",
            ]
            
            domain_candidates = (api_candidates + admin_candidates + 
                               debug_candidates + docs_candidates)
            candidates.extend(domain_candidates[:max_per_domain])
        
        return list(set(candidates))
    
    def save_model(self):
        """Save the trained model and scaler"""
        model_data = {
            'best_model': self.best_model,
            'best_model_name': self.best_model_name,
            'scaler': self.scaler,
            'feature_names': self.feature_names
        }
        joblib.dump(model_data, self.model_path)
        print(f"💾 Model saved to {self.model_path}")
    
    def load_model_if_exists(self):
        """Load existing model if available"""
        if os.path.exists(self.model_path):
            try:
                model_data = joblib.load(self.model_path)
                self.best_model = model_data['best_model']
                self.best_model_name = model_data['best_model_name']
                self.scaler = model_data['scaler']
                self.feature_names = model_data['feature_names']
                print(f"📁 Loaded existing model: {self.best_model_name}")
            except Exception as e:
                print(f"⚠️  Could not load model: {str(e)}")
    
    def save_performance_metrics(self, model_name: str, cv_score: float, 
                               test_score: float, total_samples: int):
        """Save performance metrics"""
        conn = sqlite3.connect(self.data_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            INSERT INTO model_performance 
            (model_name, training_date, accuracy, cross_val_score, total_samples)
            VALUES (?, ?, ?, ?, ?)
        ''', (model_name, datetime.now().isoformat(), test_score, cv_score, total_samples))
        
        conn.commit()
        conn.close()
    
    def get_statistics(self) -> Dict:
        """Get comprehensive statistics"""
        conn = sqlite3.connect(self.data_path)
        
        # Training data stats
        training_stats = pd.read_sql_query('''
            SELECT 
                COUNT(*) as total_samples,
                SUM(CASE WHEN label = 1 THEN 1 ELSE 0 END) as real_endpoints,
                SUM(CASE WHEN label = 0 THEN 1 ELSE 0 END) as fake_endpoints,
                source,
                COUNT(*) as count
            FROM training_endpoints 
            GROUP BY source
        ''', conn)
        
        # Performance history
        performance_history = pd.read_sql_query('''
            SELECT * FROM model_performance 
            ORDER BY training_date DESC
        ''', conn)
        
        conn.close()
        
        return {
            'training_stats': training_stats.to_dict('records'),
            'performance_history': performance_history.to_dict('records'),
            'current_model': self.best_model_name,
            'feature_count': len(self.feature_names) if self.feature_names else 0
        }

# Flask API for integration
app = Flask(__name__)
predictor = EnhancedAPIPredictor()

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'model_loaded': predictor.best_model is not None,
        'current_model': predictor.best_model_name
    })

@app.route('/add_crawl_data', methods=['POST'])
def add_crawl_data():
    """Add crawl results to training data"""
    try:
        data = request.json
        print("📥 Received:", data)
        print(request)
        urls = data.get('urls', [])
        metadata = data.get('metadata', [])
        
        if not urls:
            return jsonify({'error': 'No URLs provided'}), 400
        
        # All crawled URLs are real (positive examples)
        labels = [1] * len(urls)
        
        # Generate synthetic negatives
        synthetic_urls = predictor.generate_smart_synthetic_data(urls)
        synthetic_labels = [0] * len(synthetic_urls)
        
        # Add real data
        predictor.add_training_data(urls, labels, source="crawler", metadata=metadata)
        
        # Add synthetic data
        predictor.add_training_data(synthetic_urls, synthetic_labels, source="synthetic")
        
        return jsonify({
            'status': 'success',
            'real_urls_added': len(urls),
            'synthetic_urls_added': len(synthetic_urls),
            'model_retrained': True
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/predict', methods=['POST'])
def predict_endpoints():
    """Predict potential endpoints"""
    try:
        data = request.json
        base_urls = data.get('base_urls', [])
        validate = data.get('validate', False)
        max_candidates = data.get('max_candidates', 50)
        
        if not base_urls:
            return jsonify({'error': 'No base URLs provided'}), 400
        
        # Generate candidates
        candidates = predictor.generate_candidates(base_urls, max_candidates)
        
        # Make predictions
        predictions = predictor.predict_with_confidence(candidates)
        
        # Validate if requested
        if validate:
            predictions = predictor.validate_predictions(predictions)
        
        return jsonify({
            'status': 'success',
            'predictions': predictions,
            'total_candidates': len(candidates),
            'model_used': predictor.best_model_name
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/stats', methods=['GET'])
def get_stats():
    """Get model statistics"""
    try:
        stats = predictor.get_statistics()
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/retrain', methods=['POST'])
def manual_retrain():
    """Manually trigger model retraining"""
    try:
        predictor.retrain_model()
        return jsonify({'status': 'success', 'model': predictor.best_model_name})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    print("🚀 Starting Enhanced API Predictor Service...")
    print("📊 Available endpoints:")
    print("  GET  /health - Health check")
    print("  POST /add_crawl_data - Add crawl results")
    print("  POST /predict - Predict endpoints")
    print("  GET  /stats - Get statistics")
    print("  POST /retrain - Manual retrain")
    
    app.run(host='0.0.0.0', port=5000, debug=True)


