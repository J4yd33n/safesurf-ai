# ML Model Training Pipeline

This folder contains the training pipeline for the PhishGuard Random Forest
classifier whose exported weights live in `src/lib/phishing-analyzer.ts`
(`ML_WEIGHTS` block).

## Why retrain?

Default weights are derived from the UCI Phishing Websites Dataset
(Mohammad et al., 2015) and PhishTank samples. Retrain when you collect a
larger or more current dataset.

## Pipeline

1. Collect labeled URLs (`1` = phishing, `0` = legit).
   - PhishTank: https://phishtank.org/developer_info.php
   - Tranco top 1M (legit baseline): https://tranco-list.eu/
   - Kaggle "Phishing Site URLs"

2. Run feature extraction matching the 12 indicators in the analyzer.

3. Train `RandomForestClassifier(n_estimators=100, max_depth=10)` with sklearn.

4. Export logistic-regression coefficients (used for fast in-browser inference)
   or export the full RF via `m2cgen` / `sklearn-porter` to JS.

## Quick start

```bash
pip install scikit-learn pandas numpy
python train_random_forest.py --input urls_labeled.csv --output weights.json
```

## Evaluation metrics to report

- Accuracy, Precision, Recall, F1
- Confusion matrix
- ROC-AUC

Literature baseline: F1 >= 0.94 with this 12-feature setup.