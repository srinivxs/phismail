# PhisMail — ML Pipeline Design

## Overview

The ML pipeline provides a pluggable classifier for phishing detection, wrapping a rule-based scorer that can be swapped with a trained model without code changes.

## Architecture

```
[Feature Store (DB)] → [Feature Loader] → [Classifier] → [Prediction]
                                              ↓
                                    [SHAP Explainer] → [Top Contributors]
```

## Current Implementation

- **Classifier**: Rule-based weighted scoring engine
- **Features**: ~80 features across 12 categories from the feature engineering matrix
- **Explainability**: Top-10 feature attribution via contribution analysis

## Future Model Training

### Training Pipeline
1. Load labeled feature vectors from `FeatureVector` table
2. Split train/test (stratified, fixed seed for reproducibility)
3. Train RandomForest + XGBoost ensemble
4. Evaluate precision, recall, F1, AUC-ROC
5. Serialize model via `joblib` to `MLModel` registry
6. Generate SHAP values for explainability

### Model Registry
- `MLModel` table stores model metadata (name, version, path, accuracy, feature columns)
- Classifier auto-loads latest model from `ML_MODEL_PATH` on startup
- Fallback to rule-based scorer if no trained model exists

## Feature Store

- All analysis features persisted to `FeatureVector` table with category labels
- Enables retraining without re-running analysis pipeline
- Schema: `(analysis_id, feature_name, feature_value, feature_category)`
