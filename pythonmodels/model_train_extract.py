import time
import torch
import torch.nn as nn
import xgboost as xgb
import numpy as np
from sklearn.metrics import accuracy_score, f1_score, confusion_matrix
from sklearn.model_selection import train_test_split

class FlowFeatureExtractor(nn.Module):
    def __init__(self, num_features=6, hidden_dim=64):
        super(FlowFeatureExtractor, self).__init__()
        self.conv1 = nn.Conv1d(in_channels=num_features, out_channels=32, kernel_size=3, padding=1)
        self.relu = nn.ReLU()
        self.lstm = nn.LSTM(input_size=32, hidden_size=hidden_dim, batch_first=True)
        
    def forward(self, x):
        x = x.transpose(1, 2) 
        c = self.relu(self.conv1(x))
        c = c.transpose(1, 2) 
        lstm_out, (hn, cn) = self.lstm(c)
        return hn[-1]

if __name__ == "__main__":
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")
    print(f"Training on device: {device}")

    print("\nLoading Friday dataset from disk (X_friday.npy, y_friday.npy)")
    try:
        X = np.load("X_friday.npy")
        y = np.load("y_friday.npy")
    except FileNotFoundError:
        print("Error: Could not find .npy files. Run the PCAP extraction script first")
        exit(1)

    print(f"Loaded {len(X):,} total flows.")
    
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

    model = FlowFeatureExtractor().to(device)
    optimizer = torch.optim.Adam(model.parameters(), lr=0.001)
    criterion = nn.BCEWithLogitsLoss()
    classifier = nn.Linear(64, 1).to(device) 

    print("\nTraining CNN-LSTM Feature Extractor")
    model.train()
    batch_size = 256
    
    for epoch in range(100):
        epoch_loss = 0
        for i in range(0, len(X_train), batch_size):
            inputs = torch.tensor(X_train[i:i+batch_size]).to(device)
            labels = torch.tensor(y_train[i:i+batch_size], dtype=torch.float32).unsqueeze(1).to(device)
            
            optimizer.zero_grad()
            embeddings = model(inputs)
            outputs = classifier(embeddings)
            loss = criterion(outputs, labels)
            loss.backward()
            optimizer.step()
            epoch_loss += loss.item()
        print(f"Epoch {epoch+1} Loss: {epoch_loss/len(X_train):.6f}")

    model.eval()
    model.eval()
    with torch.no_grad():
        print("\nExtracting embeddings for XGBoost (in batches to save VRAM)...")
        
        def extract_in_batches(data_array, batch_sz=2048):
            emb_list = []
            for i in range(0, len(data_array), batch_sz):
                batch_tensor = torch.tensor(data_array[i:i+batch_sz]).to(device)
                emb = model(batch_tensor).cpu().numpy()
                emb_list.append(emb)
            return np.concatenate(emb_list, axis=0)

        train_embeddings = extract_in_batches(X_train)
        test_embeddings = extract_in_batches(X_test)

    print("Training XGBoost Classifier...")
    xgb_model = xgb.XGBClassifier(
        n_estimators=150, 
        max_depth=5, 
        learning_rate=0.1, 
        eval_metric='logloss',
        tree_method='hist',
        device='cuda'       
    )
    xgb_model.fit(train_embeddings, y_train)

    print("Model Performance Statistics")
    
    start_time = time.perf_counter()
    y_pred = xgb_model.predict(test_embeddings)
    inference_time = time.perf_counter() - start_time

    acc = accuracy_score(y_test, y_pred)
    f1 = f1_score(y_test, y_pred)
    cm = confusion_matrix(y_test, y_pred)

    print(f"Accuracy:         {acc:.4f}")
    print(f"F1 Score:         {f1:.4f}")
    print(f"Confusion Matrix:\n{cm}")
    print(f"Total Infer Time: {inference_time:.4f} seconds (for {len(X_test):,} flows)")
    print(f"Time per flow:    {(inference_time/len(X_test))*1000000:.2f} microseconds")

    print("Exporting models...")
    model.to('cpu') 
    model.eval()

    dummy_input = torch.randn(1, 10, 6) 
    
    torch.onnx.export(
        model, 
        dummy_input, 
        "cnn_lstm.onnx", 
        export_params=True,
        opset_version=17, 
        do_constant_folding=True, 
        input_names=['input_sequence'], 
        output_names=['embedding']
    )

    xgb_model.save_model("xgboost_nips.json")
    print("Export Complete: Static cnn_lstm.onnx generated successfully.")