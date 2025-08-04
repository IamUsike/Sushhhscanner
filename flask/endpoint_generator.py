import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.cluster import KMeans
import joblib
import json
import os
import re
import math
from datetime import datetime
from typing import List, Dict, Tuple, Optional, Set
import sqlite3
from urllib.parse import urlparse
import requests
from flask import Flask, request, jsonify
import threading
import time
from collections import Counter, defaultdict
import random
from itertools import combinations, permutations

class EndpointGenerator:
    def __init__(self, model_path="endpoint_generator.pkl", data_path="endpoint_training.db"):
        self.model_path = model_path
        self.data_path = data_path
        self.scaler = StandardScaler()
        self.tfidf_vectorizer = TfidfVectorizer(max_features=1000, ngram_range=(1, 3))
        self.pattern_model = RandomForestClassifier(n_estimators=100, random_state=42)
        self.kmeans_clusterer = KMeans(n_clusters=10, random_state=42)
        
        # Pattern libraries learned from training data
        self.learned_patterns = {
            'api_versions': set(),
            'resource_names': set(),
            'crud_operations': set(),
            'path_structures': set(),
            'common_parameters': set(),
            'admin_paths': set(),
            'auth_paths': set(),
            'doc_paths': set()
        }
        
        # Enhanced pattern templates
        self.generation_templates = {
            'api_rest': [
                '/api/v{version}/{resource}',
                '/api/v{version}/{resource}/{id}',
                '/api/v{version}/{resource}/{id}/{sub_resource}',
                '/api/v{version}/{resource}/search',
                '/api/v{version}/{resource}/bulk',
                '/api/v{version}/{resource}/export',
                '/api/v{version}/{resource}/import',
                '/api/v{version}/{resource}/stats',
                '/api/v{version}/{resource}/metadata'
            ],
            'admin': [
                '/admin/{resource}',
                '/admin/{resource}/manage',
                '/admin/{resource}/config',
                '/admin/{resource}/stats',
                '/admin/{resource}/logs',
                '/admin/dashboard/{resource}',
                '/admin/settings/{resource}',
                '/administrator/{resource}'
            ],
            'auth': [
                '/auth/{operation}',
                '/auth/v{version}/{operation}',
                '/oauth/{operation}',
                '/oauth/v{version}/{operation}',
                '/login/{operation}',
                '/sso/{operation}',
                '/token/{operation}'
            ],
            'docs': [
                '/docs/{resource}',
                '/documentation/{resource}',
                '/api-docs/{resource}',
                '/swagger/{resource}',
                '/openapi/{resource}',
                '/spec/{resource}'
            ],
            'monitoring': [
                '/health/{resource}',
                '/status/{resource}',
                '/metrics/{resource}',
                '/debug/{resource}',
                '/logs/{resource}',
                '/monitor/{resource}',
                '/ping/{resource}'
            ],
            'webhooks': [
                '/webhook/{resource}',
                '/webhooks/{resource}',
                '/callback/{resource}',
                '/notify/{resource}',
                '/events/{resource}'
            ]
        }
        
        # Common patterns for ML-based generation
        self.ml_features = [
            'path_segments', 'resource_types', 'operations', 'versions',
            'parameters', 'extensions', 'prefixes', 'suffixes'
        ]
        
        self.init_database()
        self.load_model_if_exists()
    
    def init_database(self):
        """Initialize database for endpoint patterns"""
        conn = sqlite3.connect(self.data_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS endpoint_patterns (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                original_url TEXT,
                domain TEXT,
                path_pattern TEXT,
                resource_type TEXT,
                operation_type TEXT,
                version TEXT,
                depth INTEGER,
                segments TEXT,
                date_added TEXT,
                frequency INTEGER DEFAULT 1
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS generated_endpoints (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                generated_url TEXT,
                base_domain TEXT,
                generation_method TEXT,
                confidence_score REAL,
                pattern_template TEXT,
                date_generated TEXT,
                validated BOOLEAN DEFAULT FALSE,
                endpoint_exists BOOLEAN DEFAULT FALSE
            )
        ''')
        
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS pattern_clusters (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cluster_id INTEGER,
                pattern TEXT,
                frequency INTEGER,
                example_urls TEXT
            )
        ''')
        
        conn.commit()
        conn.close()
    
    def extract_patterns_from_url(self, url: str) -> Dict:
        """Extract detailed patterns from a URL for ML training"""
        parsed = urlparse(url)
        path = parsed.path.lower().strip('/')
        
        if not path:
            return {}
        
        segments = [seg for seg in path.split('/') if seg]
        
        patterns = {
            'domain': parsed.netloc,
            'full_path': path,
            'segments': segments,
            'depth': len(segments),
            'first_segment': segments[0] if segments else '',
            'last_segment': segments[-1] if segments else '',
            'has_api': 'api' in path,
            'has_version': bool(re.search(r'v\d+', path)),
            'version': self._extract_version(path),
            'resource_type': self._identify_resource_type(segments),
            'operation_type': self._identify_operation_type(segments),
            'has_id': self._has_id_pattern(segments),
            'has_admin': any(word in path for word in ['admin', 'administrator', 'manage']),
            'has_auth': any(word in path for word in ['auth', 'login', 'oauth', 'token']),
            'has_docs': any(word in path for word in ['docs', 'documentation', 'swagger', 'openapi']),
            'pattern_signature': self._generate_pattern_signature(segments)
        }
        
        return patterns
    
    def _extract_version(self, path: str) -> str:
        """Extract version from path"""
        version_match = re.search(r'v(\d+(?:\.\d+)?)', path)
        return version_match.group(1) if version_match else ''
    
    def _identify_resource_type(self, segments: List[str]) -> str:
        """Identify the main resource type from segments"""
        resource_indicators = [
            'users', 'user', 'accounts', 'account', 'products', 'product',
            'orders', 'order', 'items', 'item', 'posts', 'post', 'files',
            'images', 'documents', 'messages', 'notifications', 'settings',
            'config', 'profile', 'dashboard', 'reports', 'analytics', 'logs'
        ]
        
        for segment in segments:
            if segment in resource_indicators:
                return segment
            # Check for plural/singular variations
            if segment.endswith('s') and segment[:-1] in resource_indicators:
                return segment
        
        return 'unknown'
    
    def _identify_operation_type(self, segments: List[str]) -> str:
        """Identify operation type (CRUD, etc.)"""
        operations = {
            'create': ['create', 'new', 'add'],
            'read': ['get', 'list', 'view', 'show', 'fetch'],
            'update': ['update', 'edit', 'modify', 'patch'],
            'delete': ['delete', 'remove', 'destroy'],
            'search': ['search', 'find', 'query'],
            'bulk': ['bulk', 'batch', 'mass'],
            'export': ['export', 'download', 'backup'],
            'import': ['import', 'upload', 'restore'],
            'stats': ['stats', 'statistics', 'analytics', 'metrics'],
            'admin': ['admin', 'manage', 'control']
        }
        
        for segment in segments:
            for op_type, keywords in operations.items():
                if segment in keywords:
                    return op_type
        
        return 'unknown'
    
    def _has_id_pattern(self, segments: List[str]) -> bool:
        """Check if URL has ID patterns"""
        for segment in segments:
            if (segment.isdigit() or 
                re.match(r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$', segment) or
                re.match(r'^[a-f0-9]{24}$', segment)):
                return True
        return False
    
    def _generate_pattern_signature(self, segments: List[str]) -> str:
        """Generate a pattern signature for clustering"""
        signature = []
        for segment in segments:
            if segment.isdigit():
                signature.append('{id}')
            elif re.match(r'^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$', segment):
                signature.append('{uuid}')
            elif re.match(r'^[a-f0-9]{24}$', segment):
                signature.append('{objectid}')
            elif re.match(r'^v\d+$', segment):
                signature.append('{version}')
            else:
                signature.append(segment)
        
        return '/' + '/'.join(signature)
    
    def train_pattern_model(self, urls: List[str]):
        """Train ML model on endpoint patterns"""
        print("🔄 Training pattern recognition model...")
        
        # Extract patterns from all URLs
        patterns_data = []
        for url in urls:
            patterns = self.extract_patterns_from_url(url)
            if patterns:
                patterns_data.append(patterns)
        
        if not patterns_data:
            print("⚠️  No valid patterns found in training data")
            return
        
        # Store patterns in database
        self._store_patterns(patterns_data)
        
        # Update learned patterns
        self._update_learned_patterns(patterns_data)
        
        # Create feature vectors for clustering
        self._cluster_patterns(patterns_data)
        
        print(f"✅ Trained on {len(patterns_data)} endpoint patterns")
    
    def _store_patterns(self, patterns_data: List[Dict]):
        """Store extracted patterns in database"""
        conn = sqlite3.connect(self.data_path)
        cursor = conn.cursor()
        
        current_time = datetime.now().isoformat()
        
        for pattern in patterns_data:
            cursor.execute('''
                INSERT OR REPLACE INTO endpoint_patterns
                (original_url, domain, path_pattern, resource_type, operation_type, 
                 version, depth, segments, date_added, frequency)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            ''', (
                pattern.get('domain', '') + pattern.get('full_path', ''),
                pattern.get('domain', ''),
                pattern.get('pattern_signature', ''),
                pattern.get('resource_type', ''),
                pattern.get('operation_type', ''),
                pattern.get('version', ''),
                pattern.get('depth', 0),
                json.dumps(pattern.get('segments', [])),
                current_time,
                1
            ))
        
        conn.commit()
        conn.close()
    
    def _update_learned_patterns(self, patterns_data: List[Dict]):
        """Update learned patterns from training data"""
        for pattern in patterns_data:
            if pattern.get('version'):
                self.learned_patterns['api_versions'].add(pattern['version'])
            
            if pattern.get('resource_type') != 'unknown':
                self.learned_patterns['resource_names'].add(pattern['resource_type'])
            
            if pattern.get('operation_type') != 'unknown':
                self.learned_patterns['crud_operations'].add(pattern['operation_type'])
            
            if pattern.get('pattern_signature'):
                self.learned_patterns['path_structures'].add(pattern['pattern_signature'])
    
    def _cluster_patterns(self, patterns_data: List[Dict]):
        """Cluster similar patterns using ML"""
        # Create feature vectors from patterns
        feature_vectors = []
        pattern_texts = []
        
        for pattern in patterns_data:
            # Convert pattern to text for TF-IDF
            text_features = []
            text_features.extend(pattern.get('segments', []))
            text_features.append(pattern.get('resource_type', ''))
            text_features.append(pattern.get('operation_type', ''))
            
            pattern_text = ' '.join(text_features)
            pattern_texts.append(pattern_text)
        
        if len(pattern_texts) > 10:  # Need enough data for clustering
            # Vectorize patterns
            tfidf_matrix = self.tfidf_vectorizer.fit_transform(pattern_texts)
            
            # Cluster patterns
            n_clusters = min(10, len(pattern_texts) // 2)
            self.kmeans_clusterer.n_clusters = n_clusters
            cluster_labels = self.kmeans_clusterer.fit_predict(tfidf_matrix)
            
            # Store cluster information
            self._store_clusters(patterns_data, cluster_labels)
    
    def _store_clusters(self, patterns_data: List[Dict], cluster_labels: List[int]):
        """Store pattern clusters in database"""
        conn = sqlite3.connect(self.data_path)
        cursor = conn.cursor()
        
        cluster_info = defaultdict(list)
        for pattern, cluster_id in zip(patterns_data, cluster_labels):
            cluster_info[cluster_id].append(pattern)
        
        for cluster_id, patterns in cluster_info.items():
            most_common_pattern = max(patterns, key=lambda p: len(p.get('segments', [])))
            example_urls = [p.get('domain', '') + p.get('full_path', '') for p in patterns[:5]]
            
            cursor.execute('''
                INSERT OR REPLACE INTO pattern_clusters
                (cluster_id, pattern, frequency, example_urls)
                VALUES (?, ?, ?, ?)
            ''', (
                cluster_id,
                most_common_pattern.get('pattern_signature', ''),
                len(patterns),
                json.dumps(example_urls)
            ))
        
        conn.commit()
        conn.close()
    
    def generate_endpoints(self, base_urls: List[str], max_per_domain: int = 50) -> List[Dict]:
        """Generate new endpoints using ML-based pattern recognition"""
        print(f"🎯 Generating endpoints for {len(base_urls)} domains...")
        
        all_generated = []
        
        for base_url in base_urls:
            parsed = urlparse(base_url)
            domain = parsed.netloc
            base_domain = f"{parsed.scheme}://{domain}"
            
            # Generate using different methods
            template_generated = self._generate_from_templates(base_domain)
            pattern_generated = self._generate_from_learned_patterns(base_domain)
            cluster_generated = self._generate_from_clusters(base_domain)
            mutation_generated = self._generate_mutations(base_domain)
            
            # Combine and score all generated endpoints
            domain_endpoints = (template_generated + pattern_generated + 
                              cluster_generated + mutation_generated)
            
            # Remove duplicates and score
            unique_endpoints = {}
            for endpoint in domain_endpoints:
                url = endpoint['url']
                if url not in unique_endpoints:
                    unique_endpoints[url] = endpoint
                else:
                    # Merge confidence scores
                    existing = unique_endpoints[url]
                    existing['confidence_score'] = max(
                        existing['confidence_score'], 
                        endpoint['confidence_score']
                    )
                    existing['generation_methods'].append(endpoint['generation_method'])
            
            # Sort by confidence and limit
            domain_results = sorted(
                unique_endpoints.values(),
                key=lambda x: x['confidence_score'],
                reverse=True
            )[:max_per_domain]
            
            all_generated.extend(domain_results)
        
        # Store generated endpoints
        self._store_generated_endpoints(all_generated)
        
        return all_generated
    
    def _generate_from_templates(self, base_domain: str) -> List[Dict]:
        """Generate endpoints using predefined templates"""
        generated = []
        
        for category, templates in self.generation_templates.items():
            for template in templates:
                variations = self._fill_template_variations(template, base_domain)
                
                for variation in variations:
                    confidence = self._calculate_template_confidence(template, category)
                    
                    generated.append({
                        'url': variation,
                        'base_domain': base_domain,
                        'generation_method': f'template_{category}',
                        'generation_methods': [f'template_{category}'],
                        'confidence_score': confidence,
                        'pattern_template': template,
                        'date_generated': datetime.now().isoformat()
                    })
        
        return generated
    
    def _fill_template_variations(self, template: str, base_domain: str) -> List[str]:
        """Fill template with learned variations"""
        variations = []
        
        # Replace placeholders with learned values
        if '{version}' in template:
            versions = list(self.learned_patterns['api_versions']) or ['1', '2']
            for version in versions:
                filled = template.replace('{version}', version)
                variations.extend(self._fill_template_variations(filled, base_domain))
        elif '{resource}' in template:
            resources = list(self.learned_patterns['resource_names']) or [
                'users', 'accounts', 'products', 'orders', 'files', 'settings'
            ]
            for resource in resources:
                filled = template.replace('{resource}', resource)
                variations.extend(self._fill_template_variations(filled, base_domain))
        elif '{operation}' in template:
            operations = list(self.learned_patterns['crud_operations']) or [
                'login', 'logout', 'token', 'refresh', 'validate'
            ]
            for operation in operations:
                filled = template.replace('{operation}', operation)
                variations.extend(self._fill_template_variations(filled, base_domain))
        elif '{id}' in template:
            # Generate with common ID patterns
            id_patterns = ['123', 'me', 'current', '1']
            for id_pattern in id_patterns:
                filled = template.replace('{id}', id_pattern)
                variations.extend(self._fill_template_variations(filled, base_domain))
        else:
            # No more placeholders, add full URL
            variations.append(base_domain + template)
        
        return variations
    
    def _calculate_template_confidence(self, template: str, category: str) -> float:
        """Calculate confidence score for template-based generation"""
        base_confidence = {
            'api_rest': 0.8,
            'admin': 0.7,
            'auth': 0.75,
            'docs': 0.6,
            'monitoring': 0.65,
            'webhooks': 0.55
        }
        
        return base_confidence.get(category, 0.5)
    
    def _generate_from_learned_patterns(self, base_domain: str) -> List[Dict]:
        """Generate endpoints based on learned patterns"""
        generated = []
        
        # Get patterns from database
        conn = sqlite3.connect(self.data_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT path_pattern, resource_type, operation_type, frequency
            FROM endpoint_patterns
            WHERE frequency > 1
            ORDER BY frequency DESC
            LIMIT 50
        ''')
        
        patterns = cursor.fetchall()
        conn.close()
        
        for pattern_row in patterns:
            pattern, resource, operation, frequency = pattern_row
            
            # Generate variations of this pattern
            variations = self._create_pattern_variations(pattern, base_domain)
            
            for variation in variations:
                confidence = min(0.9, frequency / 10.0)  # Scale frequency to confidence
                
                generated.append({
                    'url': variation,
                    'base_domain': base_domain,
                    'generation_method': 'learned_pattern',
                    'generation_methods': ['learned_pattern'],
                    'confidence_score': confidence,
                    'pattern_template': pattern,
                    'date_generated': datetime.now().isoformat()
                })
        
        return generated
    
    def _create_pattern_variations(self, pattern: str, base_domain: str) -> List[str]:
        """Create variations of a learned pattern"""
        variations = []
        
        # Replace placeholders with different values
        if '{id}' in pattern:
            for id_val in ['123', 'me', 'current']:
                varied = pattern.replace('{id}', id_val)
                variations.extend(self._create_pattern_variations(varied, base_domain))
        elif '{version}' in pattern:
            for version in ['1', '2', '3']:
                varied = pattern.replace('{version}', version)
                variations.extend(self._create_pattern_variations(varied, base_domain))
        else:
            variations.append(base_domain + pattern)
        
        return variations
    
    def _generate_from_clusters(self, base_domain: str) -> List[Dict]:
        """Generate endpoints based on pattern clusters"""
        generated = []
        
        conn = sqlite3.connect(self.data_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT pattern, frequency FROM pattern_clusters
            ORDER BY frequency DESC
            LIMIT 20
        ''')
        
        clusters = cursor.fetchall()
        conn.close()
        
        for pattern, frequency in clusters:
            variations = self._create_pattern_variations(pattern, base_domain)
            
            for variation in variations:
                confidence = min(0.85, frequency / 15.0)
                
                generated.append({
                    'url': variation,
                    'base_domain': base_domain,
                    'generation_method': 'cluster_pattern',
                    'generation_methods': ['cluster_pattern'],
                    'confidence_score': confidence,
                    'pattern_template': pattern,
                    'date_generated': datetime.now().isoformat()
                })
        
        return generated
    
    def _generate_mutations(self, base_domain: str) -> List[Dict]:
        """Generate mutations of successful patterns"""
        generated = []
        
        # Get most successful patterns
        conn = sqlite3.connect(self.data_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT g.generated_url, g.pattern_template, g.confidence_score
            FROM generated_endpoints g
            WHERE g.base_domain = ? AND g.exists = 1
            ORDER BY g.confidence_score DESC
            LIMIT 10
        ''', (base_domain,))
        
        successful_patterns = cursor.fetchall()
        conn.close()
        
        for url, template, confidence in successful_patterns:
            # Create mutations of successful patterns
            mutations = self._mutate_successful_pattern(url, base_domain)
            
            for mutation in mutations:
                generated.append({
                    'url': mutation,
                    'base_domain': base_domain,
                    'generation_method': 'mutation',
                    'generation_methods': ['mutation'],
                    'confidence_score': confidence * 0.7,  # Lower confidence for mutations
                    'pattern_template': template,
                    'date_generated': datetime.now().isoformat()
                })
        
        return generated
    
    def _mutate_successful_pattern(self, successful_url: str, base_domain: str) -> List[str]:
        """Create mutations of a successful pattern"""
        mutations = []
        parsed = urlparse(successful_url)
        path = parsed.path
        
        segments = [seg for seg in path.split('/') if seg]
        
        if len(segments) >= 2:
            # Try different versions
            for version in ['v1', 'v2', 'v3']:
                if 'v' in segments[0]:
                    new_segments = segments.copy()
                    new_segments[0] = version
                    mutations.append(base_domain + '/' + '/'.join(new_segments))
            
            # Try different resources
            for resource in ['users', 'accounts', 'items', 'files']:
                if len(segments) > 1:
                    new_segments = segments.copy()
                    new_segments[-1] = resource
                    mutations.append(base_domain + '/' + '/'.join(new_segments))
            
            # Try adding operations
            for operation in ['search', 'bulk', 'export', 'stats']:
                new_path = path + '/' + operation
                mutations.append(base_domain + new_path)
        
        return mutations
    
    def _store_generated_endpoints(self, endpoints: List[Dict]):
        """Store generated endpoints in database"""
        conn = sqlite3.connect(self.data_path)
        cursor = conn.cursor()
        
        for endpoint in endpoints:
            cursor.execute('''
                INSERT OR REPLACE INTO generated_endpoints
                (generated_url, base_domain, generation_method, confidence_score,
                 pattern_template, date_generated)
                VALUES (?, ?, ?, ?, ?, ?)
            ''', (
                endpoint['url'],
                endpoint['base_domain'],
                endpoint['generation_method'],
                endpoint['confidence_score'],
                endpoint['pattern_template'],
                endpoint['date_generated']
            ))
        
        conn.commit()
        conn.close()
    
    def validate_generated_endpoints(self, endpoints: List[Dict], timeout: int = 3) -> List[Dict]:
        """Validate generated endpoints"""
        print(f"🔍 Validating top {min(30, len(endpoints))} generated endpoints...")
        
        for i, endpoint in enumerate(endpoints[:30]):
            try:
                response = requests.head(endpoint['url'], timeout=timeout, allow_redirects=True)
                exists = response.status_code < 400
                
                endpoint.update({
                    'validated': True,
                    'exists': exists,
                    'status_code': response.status_code,
                    'validation_date': datetime.now().isoformat()
                })
                
                # Update database
                self._update_validation_result(endpoint['url'], exists, response.status_code)
                
                print(f"  {'✅' if exists else '❌'} {endpoint['url']} → {response.status_code}")
                
            except Exception as e:
                endpoint.update({
                    'validated': False,
                    'exists': False,
                    'error': str(e),
                    'validation_date': datetime.now().isoformat()
                })
                
                self._update_validation_result(endpoint['url'], False, None)
                print(f"  ❌ {endpoint['url']} → Error: {str(e)[:30]}")
        
        return endpoints
    
    def _update_validation_result(self, url: str, exists: bool, status_code: int):
        """Update validation result in database"""
        conn = sqlite3.connect(self.data_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            UPDATE generated_endpoints
            SET validated = 1, endpoint_exists = ?
            WHERE generated_url = ?
        ''', (exists, url))
        
        conn.commit()
        conn.close()
    
    def get_generation_stats(self) -> Dict:
        """Get statistics about endpoint generation"""
        conn = sqlite3.connect(self.data_path)
        
        # Generation stats
        cursor = conn.cursor()
        cursor.execute('''
            SELECT 
                generation_method,
                COUNT(*) as total_generated,
                SUM(CASE WHEN endpoint_exists = 1 THEN 1 ELSE 0 END) as successful,
                AVG(confidence_score) as avg_confidence
            FROM generated_endpoints
            WHERE validated = 1
            GROUP BY generation_method
        ''')
        
        generation_stats = cursor.fetchall()
        
        # Pattern stats
        cursor.execute('''
            SELECT COUNT(*) as total_patterns,
                   AVG(frequency) as avg_frequency
            FROM endpoint_patterns
        ''')
        
        pattern_stats = cursor.fetchone()
        
        conn.close()
        
        return {
            'generation_methods': [
                {
                    'method': row[0],
                    'total_generated': row[1],
                    'successful': row[2],
                    'success_rate': row[2] / row[1] if row[1] > 0 else 0,
                    'avg_confidence': row[3]
                }
                for row in generation_stats
            ],
            'pattern_stats': {
                'total_patterns': pattern_stats[0] if pattern_stats else 0,
                'avg_frequency': pattern_stats[1] if pattern_stats else 0
            },
            'learned_patterns': {
                'api_versions': len(self.learned_patterns['api_versions']),
                'resource_names': len(self.learned_patterns['resource_names']),
                'crud_operations': len(self.learned_patterns['crud_operations']),
                'path_structures': len(self.learned_patterns['path_structures'])
            }
        }
    
    def save_model(self):
        """Save the trained model"""
        model_data = {
            'learned_patterns': self.learned_patterns,
            'tfidf_vectorizer': self.tfidf_vectorizer,
            'kmeans_clusterer': self.kmeans_clusterer,
            'generation_templates': self.generation_templates
        }
        joblib.dump(model_data, self.model_path)
        print(f"💾 Model saved to {self.model_path}")
    
    def load_model_if_exists(self):
        """Load existing model if available"""
        if os.path.exists(self.model_path):
            try:
                model_data = joblib.load(self.model_path)
                self.learned_patterns = model_data.get('learned_patterns', self.learned_patterns)
                self.tfidf_vectorizer = model_data.get('tfidf_vectorizer', self.tfidf_vectorizer)
                self.kmeans_clusterer = model_data.get('kmeans_clusterer', self.kmeans_clusterer)
                print("📁 Loaded existing endpoint generation model")
            except Exception as e:
                print(f"⚠️  Could not load model: {str(e)}")

# Flask API
app = Flask(__name__)
generator = EndpointGenerator()

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({
        'status': 'healthy',
        'model_loaded': True,
        'patterns_learned': len(generator.learned_patterns['resource_names'])
    })

@app.route('/train', methods=['POST'])
def train_model():
    """Train the endpoint generation model with crawled URLs"""
    try:
        data = request.json
        urls = data.get('urls', [])
        
        if not urls:
            return jsonify({'error': 'No URLs provided for training'}), 400
        
        print(f"📥 Training model with {len(urls)} URLs...")
        
        # Train the pattern recognition model
        generator.train_pattern_model(urls)
        
        # Save the trained model
        generator.save_model()
        
        return jsonify({
            'status': 'success',
            'message': f'Model trained on {len(urls)} URLs',
            'patterns_learned': {
                'api_versions': len(generator.learned_patterns['api_versions']),
                'resource_names': len(generator.learned_patterns['resource_names']),
                'crud_operations': len(generator.learned_patterns['crud_operations']),
                'path_structures': len(generator.learned_patterns['path_structures'])
            }
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/generate', methods=['POST'])
def generate_endpoints():
    """Generate new endpoints based on learned patterns"""
    try:
        data = request.json
        base_urls = data.get('base_urls', [])
        max_per_domain = data.get('max_per_domain', 50)
        validate = data.get('validate', False)
        
        if not base_urls:
            return jsonify({'error': 'No base URLs provided'}), 400
        
        print(f"🎯 Generating endpoints for {len(base_urls)} domains...")
        
        # Generate new endpoints
        generated_endpoints = generator.generate_endpoints(base_urls, max_per_domain)
        
        # Validate if requested
        if validate:
            generated_endpoints = generator.validate_generated_endpoints(generated_endpoints)
        
        # Filter by confidence threshold
        confidence_threshold = data.get('min_confidence', 0.5)
        filtered_endpoints = [
            ep for ep in generated_endpoints 
            if ep['confidence_score'] >= confidence_threshold
        ]
        
        return jsonify({
            'status': 'success',
            'total_generated': len(generated_endpoints),
            'filtered_count': len(filtered_endpoints),
            'endpoints': filtered_endpoints,
            'generation_summary': {
                'total_domains': len(base_urls),
                'avg_per_domain': len(filtered_endpoints) / len(base_urls) if base_urls else 0,
                'confidence_threshold': confidence_threshold
            }
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/validate', methods=['POST'])
def validate_endpoints():
    """Validate a list of generated endpoints"""
    try:
        data = request.json
        endpoints = data.get('endpoints', [])
        timeout = data.get('timeout', 3)
        
        if not endpoints:
            return jsonify({'error': 'No endpoints provided for validation'}), 400
        
        # Convert simple URL list to endpoint format if needed
        if isinstance(endpoints[0], str):
            endpoints = [{'url': url, 'confidence_score': 0.5} for url in endpoints]
        
        validated_endpoints = generator.validate_generated_endpoints(endpoints, timeout)
        
        # Count successful validations
        successful = sum(1 for ep in validated_endpoints if ep.get('exists', False))
        
        return jsonify({
            'status': 'success',
            'total_validated': len(validated_endpoints),
            'successful_endpoints': successful,
            'success_rate': successful / len(validated_endpoints) if validated_endpoints else 0,
            'validated_endpoints': validated_endpoints
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/stats', methods=['GET'])
def get_statistics():
    """Get endpoint generation statistics"""
    try:
        stats = generator.get_generation_stats()
        return jsonify(stats)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/patterns', methods=['GET'])
def get_learned_patterns():
    """Get currently learned patterns"""
    try:
        return jsonify({
            'learned_patterns': {
                'api_versions': list(generator.learned_patterns['api_versions']),
                'resource_names': list(generator.learned_patterns['resource_names']),
                'crud_operations': list(generator.learned_patterns['crud_operations']),
                'path_structures': list(generator.learned_patterns['path_structures'])[:20]  # Limit for readability
            },
            'generation_templates': generator.generation_templates
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/smart_generate', methods=['POST'])
def smart_generate():
    """Smart endpoint generation with advanced ML techniques"""
    try:
        data = request.json
        base_urls = data.get('base_urls', [])
        focus_areas = data.get('focus_areas', ['api', 'admin', 'auth'])  # Areas to focus on
        creativity_level = data.get('creativity_level', 'medium')  # low, medium, high
        max_per_domain = data.get('max_per_domain', 30)
        
        if not base_urls:
            return jsonify({'error': 'No base URLs provided'}), 400
        
        print(f"🧠 Smart generation for {len(base_urls)} domains with focus on {focus_areas}")
        
        smart_endpoints = []
        
        for base_url in base_urls:
            parsed = urlparse(base_url)
            base_domain = f"{parsed.scheme}://{parsed.netloc}"
            
            domain_endpoints = []
            
            # Generate based on focus areas
            for area in focus_areas:
                if area in generator.generation_templates:
                    templates = generator.generation_templates[area]
                    
                    for template in templates:
                        variations = generator._fill_template_variations(template, base_domain)
                        
                        for variation in variations:
                            confidence = generator._calculate_template_confidence(template, area)
                            
                            # Adjust confidence based on creativity level
                            if creativity_level == 'high':
                                confidence *= 0.8  # Lower confidence for more creative attempts
                            elif creativity_level == 'low':
                                confidence *= 1.2  # Higher confidence for conservative attempts
                            
                            domain_endpoints.append({
                                'url': variation,
                                'base_domain': base_domain,
                                'generation_method': f'smart_{area}',
                                'confidence_score': min(1.0, confidence),
                                'focus_area': area,
                                'creativity_level': creativity_level,
                                'pattern_template': template,
                                'date_generated': datetime.now().isoformat()
                            })
            
            # Sort by confidence and limit
            domain_endpoints.sort(key=lambda x: x['confidence_score'], reverse=True)
            smart_endpoints.extend(domain_endpoints[:max_per_domain])
        
        # Remove duplicates
        unique_endpoints = {}
        for endpoint in smart_endpoints:
            url = endpoint['url']
            if url not in unique_endpoints or endpoint['confidence_score'] > unique_endpoints[url]['confidence_score']:
                unique_endpoints[url] = endpoint
        
        final_endpoints = list(unique_endpoints.values())
        final_endpoints.sort(key=lambda x: x['confidence_score'], reverse=True)
        
        return jsonify({
            'status': 'success',
            'total_generated': len(final_endpoints),
            'focus_areas': focus_areas,
            'creativity_level': creativity_level,
            'endpoints': final_endpoints,
            'generation_summary': {
                'domains_processed': len(base_urls),
                'avg_per_domain': len(final_endpoints) / len(base_urls) if base_urls else 0,
                'focus_distribution': {
                    area: len([ep for ep in final_endpoints if ep.get('focus_area') == area])
                    for area in focus_areas
                }
            }
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/export_results', methods=['GET'])
def export_results():
    """Export generated endpoints as JSON"""
    try:
        # Get all generated endpoints from database
        conn = sqlite3.connect(generator.data_path)
        cursor = conn.cursor()
        
        cursor.execute('''
            SELECT generated_url, base_domain, generation_method, confidence_score,
                   pattern_template, date_generated, validated, endpoint_exists
            FROM generated_endpoints
            ORDER BY confidence_score DESC
        ''')
        
        results = cursor.fetchall()
        conn.close()
        
        exported_data = []
        for row in results:
            exported_data.append({
                'url': row[0],
                'base_domain': row[1],
                'generation_method': row[2],
                'confidence_score': row[3],
                'pattern_template': row[4],
                'date_generated': row[5],
                'validated': bool(row[6]),
                'exists': bool(row[7])
            })
        
        return jsonify({
            'status': 'success',
            'total_endpoints': len(exported_data),
            'export_date': datetime.now().isoformat(),
            'endpoints': exported_data
        })
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    print("🚀 Starting ML-Based Endpoint Generator Service...")
    print("🎯 Available endpoints:")
    print("  GET  /health - Health check")
    print("  POST /train - Train model with crawled URLs")
    print("  POST /generate - Generate new endpoints")
    print("  POST /validate - Validate generated endpoints")
    print("  POST /smart_generate - Smart generation with focus areas")
    print("  GET  /stats - Get generation statistics")
    print("  GET  /patterns - Get learned patterns")
    print("  GET  /export_results - Export all results")
    print()
    print("📋 Usage Example:")
    print("  1. Train: POST /train with {'urls': ['https://api.example.com/v1/users', ...]}")
    print("  2. Generate: POST /generate with {'base_urls': ['https://example.com'], 'validate': true}")
    print("  3. Smart Generate: POST /smart_generate with {'base_urls': [...], 'focus_areas': ['api', 'admin']}")
    print()
    
    app.run(host='0.0.0.0', port=5000, debug=True)
