#!/usr/bin/env python3

from dataclasses import asdict
import pandas as pd
import os 
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
from pcap_parser import PcapParser
from skl2onnx import convert_sklearn
from skl2onnx.common.data_types import FloatTensorType
from skl2onnx import get_latest_tested_opset_version
from onnxmltools.utils import save_model


PCAP_DIR = os.path.expanduser("./pcaps")
TUNNEL_NET = "10.66.0."
WINDOW_SIZE = 40

X, y = PcapParser.parse(PCAP_DIR, TUNNEL_NET, WINDOW_SIZE)


df = pd.DataFrame(X)
Xtr, Xte, ytr, yte = train_test_split(df, y, test_size=0.3, random_state=42, stratify=y)
# depends on the dataset, it can be class_weight='balance'
clf = RandomForestClassifier(n_estimators=100, random_state=42, class_weight={'bulk':1, 'video':1, 'voip':3, 'web':3})
clf.fit(Xtr, ytr)

pred = clf.predict(Xte)
print("\nConfusion matrix:\n", confusion_matrix(yte, pred))
print("\n", classification_report(yte, pred))

os.makedirs(os.path.expanduser("./model"), exist_ok=True)
# pickle.dump({"model": clf, "cols": list(df.columns)},
#             open(os.path.expanduser("./model/model.pkl"), "wb"))
# print("Saved model.pkl")

target_opset = get_latest_tested_opset_version()
df = pd.DataFrame([asdict(f) for f in X]) 
n_features = df.shape[1]

onnx_clf = convert_sklearn(
    clf,
    "gbdt_model",
    initial_types=[("input", FloatTensorType([None, n_features]))],
    target_opset={"": target_opset, "ai.onnx.ml": 2}
)
save_model(onnx_clf, "./model/model.onnx")