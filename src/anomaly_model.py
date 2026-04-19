import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier, IsolationForest
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score
import matplotlib.pyplot as plt
import seaborn as sns

# ─────────────────────────────────────────
# STEP 1 — Load your dataset
# ─────────────────────────────────────────
df = pd.read_csv('cowrie/logs/cowrie_sessions.csv')

print("Dataset shape:", df.shape)
print("\nLabel distribution:")
print(df['bot_label'].value_counts())

# ─────────────────────────────────────────
# STEP 2 — Define features and label
# ─────────────────────────────────────────
# Drop session_id — it is just an identifier, not a feature
feature_cols = [
    'commands_count',
    'unique_commands',
    'failed_logins',
    'success_login',
    'usernames_count',
    'passwords_count',
    'duration_proxy'
]

X = df[feature_cols]
y = df['bot_label']   # 0 = normal, 1 = bot

# ─────────────────────────────────────────
# STEP 3 — Split FIRST before anything else
# 80% for training, 20% for testing
# stratify=y keeps the same bot ratio in both parts
# ─────────────────────────────────────────
X_train, X_test, y_train, y_test = train_test_split(
    X, y,
    test_size=0.2,
    random_state=42,
    stratify=y
)

print(f"\nTraining rows : {len(X_train)}")
print(f"Testing rows  : {len(X_test)}")

# ─────────────────────────────────────────
# STEP 4 — Scale features
# Fit ONLY on training data, then apply to both
# ─────────────────────────────────────────
scaler = StandardScaler()
X_train_scaled = scaler.fit_transform(X_train)   # learns mean/std from train
X_test_scaled  = scaler.transform(X_test)         # applies same mean/std to test

# ─────────────────────────────────────────
# STEP 5 — RandomForest (supervised)
# Learns from labels during training
# ─────────────────────────────────────────
print("\n" + "="*50)
print("RANDOM FOREST (supervised)")
print("="*50)

rf = RandomForestClassifier(
    n_estimators=100,
    class_weight='balanced',   # handles imbalanced bot/normal ratio
    random_state=42
)
rf.fit(X_train_scaled, y_train)   # trains using features + labels

rf_preds = rf.predict(X_test_scaled)   # predicts on rows it never saw

print("\nClassification Report:")
print(classification_report(y_test, rf_preds, target_names=['normal', 'bot']))

print("Confusion Matrix:")
print(confusion_matrix(y_test, rf_preds))

rf_auc = roc_auc_score(y_test, rf.predict_proba(X_test_scaled)[:, 1])
print(f"\nROC-AUC Score: {rf_auc:.4f}")

# ─────────────────────────────────────────
# STEP 6 — IsolationForest (unsupervised)
# Does NOT use labels during training at all
# ─────────────────────────────────────────
print("\n" + "="*50)
print("ISOLATION FOREST (unsupervised)")
print("="*50)

# Set contamination = expected fraction of bots in your data
bot_ratio = y_train.mean()
print(f"\nBot ratio in training set: {bot_ratio:.2f}")

iso = IsolationForest(
    contamination=bot_ratio,
    n_estimators=100,
    random_state=42
)
iso.fit(X_train_scaled)   # NO labels here — unsupervised

# predict() returns: +1 = normal, -1 = anomaly (bot)
iso_raw = iso.predict(X_test_scaled)

# Convert to your convention: 0 = normal, 1 = bot
iso_preds = (iso_raw == -1).astype(int)

print("\nClassification Report:")
print(classification_report(y_test, iso_preds, target_names=['normal', 'bot']))

print("Confusion Matrix:")
print(confusion_matrix(y_test, iso_preds))

# For ROC-AUC: lower score_samples = more anomalous, so negate it
iso_auc = roc_auc_score(y_test, -iso.score_samples(X_test_scaled))
print(f"\nROC-AUC Score: {iso_auc:.4f}")

# ─────────────────────────────────────────
# STEP 7 — Compare both models
# ─────────────────────────────────────────
print("\n" + "="*50)
print("MODEL COMPARISON")
print("="*50)
print(f"RandomForest  ROC-AUC : {rf_auc:.4f}")
print(f"IsolationForest ROC-AUC: {iso_auc:.4f}")

# ─────────────────────────────────────────
# STEP 8 — Feature importance (RandomForest)
# Check which features matter most
# If the top features are ones you used to BUILD bot_label,
# that is a sign of data leakage
# ─────────────────────────────────────────
print("\n" + "="*50)
print("FEATURE IMPORTANCE (RandomForest)")
print("="*50)
importances = pd.Series(rf.feature_importances_, index=feature_cols)
importances = importances.sort_values(ascending=False)
print(importances)

# ─────────────────────────────────────────
# STEP 9 — Leakage check
# Shuffle labels and retest — a real model should drop significantly
# ─────────────────────────────────────────
print("\n" + "="*50)
print("LEAKAGE CHECK")
print("="*50)
y_shuffled = np.random.permutation(y_test)
rf_shuffled_acc = (rf.predict(X_test_scaled) == y_shuffled).mean()
print(f"Accuracy with real labels   : {(rf_preds == y_test).mean():.4f}")
print(f"Accuracy with shuffled labels: {rf_shuffled_acc:.4f}")
print("If both are near 1.0 → likely data leakage")
print("If shuffled drops to ~0.5  → model is learning real patterns")

# ─────────────────────────────────────────
# STEP 10 — Plot confusion matrices
# ─────────────────────────────────────────
fig, axes = plt.subplots(1, 2, figsize=(12, 4))

for ax, preds, title in zip(
    axes,
    [rf_preds, iso_preds],
    ['RandomForest', 'IsolationForest']
):
    cm = confusion_matrix(y_test, preds)
    sns.heatmap(cm, annot=True, fmt='d', ax=ax, cmap='Blues',
                xticklabels=['normal', 'bot'],
                yticklabels=['normal', 'bot'])
    ax.set_title(title)
    ax.set_ylabel('Actual')
    ax.set_xlabel('Predicted')

plt.tight_layout()
plt.savefig('confusion_matrices.png', dpi=150)
print("\nConfusion matrix plot saved to confusion_matrices.png")