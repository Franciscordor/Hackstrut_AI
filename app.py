from scapy.all import sniff
from transformers import pipeline
import warnings
warnings.filterwarnings("ignore")

# Load sentiment-based classifier (demo)
classifier = pipeline("sentiment-analysis", model="distilbert-base-uncased-finetuned-sst-2-english")

# Packet capture without L3RawSocket
def capture_packets(count=50):
    packets = sniff(count=count)
    return [pkt.summary() for pkt in packets]

# Classify logs
def classify_logs(logs):
    results = []
    for log in logs:
        result = classifier(log)[0]
        label = result['label']
        score = result['score']

        threat_status = "THREAT" if label == "NEGATIVE" else "SAFE"
        results.append({
            "log": log,
            "label": label,
            "score": round(score, 2),
            "status": threat_status
        })
    return results

if __name__ == "__main__":
    print("Capturing packets...")
    logs = capture_packets(10)

    print("\nLogs Captured:")
    for log in logs:
        print(" -", log)

    print("\nRunning Classification...")
    predictions = classify_logs(logs)

    print("\nThreat Analysis:")
    for p in predictions:
        print(f"[{p['status']}] ({p['label']} - {p['score']}) >> {p['log']}")
