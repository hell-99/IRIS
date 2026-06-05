"""
ML Pipeline  -  Feature extraction + XGBoost classifier
Trains on logged tool call events to detect benign/suspicious/malicious behavior.
"""
import json
import sqlite3
import numpy as np
import pandas as pd
from pathlib import Path
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, confusion_matrix
from sklearn.cluster import DBSCAN
from xgboost import XGBClassifier
import pickle
from rich.console import Console
from rich.table import Table

console = Console()
DB_PATH  = Path("data/logs/agentguard.db")
MODEL_PATH = Path("data/models/iris_xgb.pkl")
MODEL_PATH.parent.mkdir(parents=True, exist_ok=True)

# Feature extraction
ROLE_MAP = {"admin": 2, "analyst": 1, "reader": 0}
TOOL_MAP = {
    "read_file": 0, "write_file": 1, "execute_command": 2,
    "query_db": 3, "call_api": 4, "list_users": 5, "modify_permissions": 6
}
SENSITIVE_PATHS    = ["private", "credentials", "admin", "config", "secret", "password"]
SENSITIVE_QUERIES  = ["password", "secret", "DROP", "DELETE", "*", "admin"]
SENSITIVE_ENDPOINTS = ["/api/secrets", "/admin", "/internal", "/root"]

def extract_features(row: dict) -> dict:
    """Extract ML features from a single tool call event."""
    role     = row.get("agent_role", "reader")
    tool     = row.get("tool_name", "read_file")
    args_str = row.get("args", "{}")
    allowed  = int(row.get("allowed", 1))

    try: args = json.loads(args_str)
    except: args = {}

    # Path sensitivity
    path           = str(args.get("path", ""))
    path_sensitive = int(any(s in path.lower() for s in SENSITIVE_PATHS))
    path_depth     = path.count("/")
    path_traversal = int(".." in path)

    # Query sensitivity
    query           = str(args.get("query", ""))
    query_sensitive = int(any(s in query for s in SENSITIVE_QUERIES))
    query_wildcard  = int("*" in query)

    # Endpoint sensitivity
    endpoint           = str(args.get("endpoint", ""))
    endpoint_sensitive = int(any(s in endpoint for s in SENSITIVE_ENDPOINTS))

    # Tool + role mismatch
    role_num = ROLE_MAP.get(role, 0)
    tool_num = TOOL_MAP.get(tool, 0)
    from agents.tools import TOOL_SENSITIVITY
    tool_sensitivity = TOOL_SENSITIVITY.get(tool, 3)

    # Permission mismatch
    from config import AGENT_ROLES
    role_obj         = AGENT_ROLES.get(role)
    allowed_tools    = role_obj.allowed_tools if role_obj else []
    permission_mismatch = int(tool not in allowed_tools)

    return {
        "role_num": role_num,
        "tool_num": tool_num,
        "tool_sensitivity": tool_sensitivity,
        "allowed": allowed,
        "permission_mismatch": permission_mismatch,
        "path_sensitive": path_sensitive,
        "path_depth": path_depth,
        "path_traversal": path_traversal,
        "query_sensitive": query_sensitive,
        "query_wildcard": query_wildcard,
        "endpoint_sensitive": endpoint_sensitive,
        "risk_score": float(row.get("risk_score", 0)),
        "latency_ms": float(row.get("latency_ms", 0)),
    }


# Load data from DB
def load_data() -> pd.DataFrame:
    """Load all tool call events from SQLite."""
    con  = sqlite3.connect(DB_PATH)
    df   = pd.read_sql("SELECT * FROM tool_calls", con)
    con.close()
    console.print(f"[green]Loaded {len(df)} events from DB[/green]")
    return df


# Train XGBoost classifier
def train_classifier(df: pd.DataFrame) -> dict:
    """Train XGBoost on extracted features. Returns metrics."""
    console.print("\n[bold]Training XGBoost classifier...[/bold]")

    # Extract features
    features = [extract_features(row) for _, row in df.iterrows()]
    X = pd.DataFrame(features)

    # Encode labels
    label_map = {"benign": 0, "suspicious": 1, "malicious": 2}
    y = df["label"].map(label_map).fillna(0).astype(int)

    console.print(f"Features: {list(X.columns)}")
    console.print(f"Label distribution: {dict(df['label'].value_counts())}")

    # Train/test split
    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.2, random_state=42, stratify=y if len(y.unique()) > 1 else None
    )

    # Train XGBoost
    clf = XGBClassifier(
        n_estimators=100,
        max_depth=4,
        learning_rate=0.1,
        use_label_encoder=False,
        eval_metric="mlogloss",
        random_state=42,
    )
    clf.fit(X_train, y_train)

    # Evaluate
    y_pred   = clf.predict(X_test)
    report   = classification_report(y_test, y_pred,
                                      output_dict=True, zero_division=0)

    # Save model
    with open(MODEL_PATH, "wb") as f:
        pickle.dump({"model": clf, "feature_names": list(X.columns)}, f)
    console.print(f"[green]Model saved to {MODEL_PATH}[/green]")

    return {
        "accuracy": report.get("accuracy", 0),
        "report": report,
        "train_size": len(X_train),
        "test_size": len(X_test),
        "model": clf,
        "feature_names": list(X.columns),
    }


# DBSCAN behavioral clustering
def cluster_sessions() -> dict:
    """
    Use DBSCAN to cluster agent sessions by behavior.
    Anomalous sessions = outliers (label -1).
    """
    console.print("\n[bold]Running DBSCAN behavioral clustering...[/bold]")

    con = sqlite3.connect(DB_PATH)
    sessions = pd.read_sql("""
        SELECT session_id, agent_role,
               COUNT(*) as total_calls,
               SUM(CASE WHEN allowed=0 THEN 1 ELSE 0 END) as blocked_calls,
               AVG(risk_score) as avg_risk,
               MAX(risk_score) as max_risk,
               COUNT(DISTINCT tool_name) as unique_tools
        FROM tool_calls
        GROUP BY session_id
    """, con)
    con.close()

    if len(sessions) < 3:
        console.print("[yellow]Not enough sessions for clustering yet[/yellow]")
        return {}

    features = sessions[["total_calls", "blocked_calls", "avg_risk",
                           "max_risk", "unique_tools"]].fillna(0)

    # Normalize
    from sklearn.preprocessing import StandardScaler
    scaler   = StandardScaler()
    X_scaled = scaler.fit_transform(features)

    # DBSCAN
    db      = DBSCAN(eps=1.5, min_samples=2)
    labels  = db.fit_predict(X_scaled)
    sessions["cluster"] = labels

    n_clusters  = len(set(labels)) - (1 if -1 in labels else 0)
    n_anomalies = list(labels).count(-1)

    console.print(f"Sessions: {len(sessions)} | Clusters: {n_clusters} | Anomalies: {n_anomalies}")

    # Print anomalous sessions
    anomalies = sessions[sessions["cluster"] == -1]
    if len(anomalies) > 0:
        t = Table(show_header=True, header_style="bold red")
        for col in ["session_id", "agent_role", "blocked_calls", "avg_risk", "cluster"]:
            t.add_column(col)
        for _, row in anomalies.iterrows():
            t.add_row(
                row["session_id"][:12],
                row["agent_role"],
                str(int(row["blocked_calls"])),
                f"{row['avg_risk']:.1f}",
                str(row["cluster"])
            )
        console.print(t)

    return {"n_clusters": n_clusters, "n_anomalies": n_anomalies, "sessions": sessions}


# Real-time prediction
def predict_live(agent_role: str, tool_name: str,
                 args: dict, risk_score: float) -> dict:
    """
    Given a live tool call, predict if it's benign/suspicious/malicious.
    Used by the interceptor in real time.
    """
    if not MODEL_PATH.exists():
        return {"label": "unknown", "confidence": 0.0, "reason": "model not trained yet"}

    with open(MODEL_PATH, "rb") as f:
        saved = pickle.load(f)
    clf           = saved["model"]
    feature_names = saved["feature_names"]

    row = {
        "agent_role": agent_role,
        "tool_name": tool_name,
        "args": json.dumps(args),
        "allowed": 1,
        "risk_score": risk_score,
        "latency_ms": 0,
    }
    features = extract_features(row)
    X = pd.DataFrame([features])[feature_names]

    pred       = clf.predict(X)[0]
    proba      = clf.predict_proba(X)[0]
    label_map  = {0: "benign", 1: "suspicious", 2: "malicious"}

    return {
        "label": label_map[pred],
        "confidence": float(max(proba)),
        "probas": {label_map[i]: float(p) for i, p in enumerate(proba)},
    }


if __name__ == "__main__":
    console.print("[bold cyan]IRIS ML Pipeline[/bold cyan]\n")
    df      = load_data()
    metrics = train_classifier(df)
    clusters = cluster_sessions()

    console.print(f"\n[bold green]Accuracy: {metrics['accuracy']:.2%}[/bold green]")
    console.print(f"Train: {metrics['train_size']} | Test: {metrics['test_size']}")
