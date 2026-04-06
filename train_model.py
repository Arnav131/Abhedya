import torch
import torch.nn as nn
import torch.optim as optim
from torch.utils.data import DataLoader, TensorDataset
import string
import random
import os
from tqdm import tqdm

# ==========================================
# 1. Configuration & Vocabulary
# ==========================================
VOCAB = list(string.printable)
CHAR_TO_IDX = {char: idx + 1 for idx, char in enumerate(VOCAB)} 
VOCAB_SIZE = len(VOCAB) + 1
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")

# REGULATE BATCH SIZE: By pushing passwords through in batches of 512, 
# PyTorch runs significantly faster on your RTX 5070 than 1-by-1 processing!
BATCH_SIZE = 32 

# ==========================================
# 2. Dataset Loader (Crawls the nested folders)
# ==========================================
def load_real_passwords(base_dir, max_passwords=50000):
    """
    Crawls the nested RockYou dataset directory and loads passwords into memory.
    Caps at max_passwords to prevent Out-Of-Memory (OOM) crashes.
    """
    print(f"Crawling dataset directory: {base_dir}")
    passwords = []
    
    for root, dirs, files in os.walk(base_dir):
        for file in files:
            if file.endswith('.txt'):
                file_path = os.path.join(root, file)
                try:
                    with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
                        for line in f:
                            pw = line.strip()
                            if 4 <= len(pw) <= 32: 
                                passwords.append(pw)
                                if len(passwords) >= max_passwords:
                                    print(f"Reached cap of {max_passwords} real passwords.")
                                    return passwords
                except Exception:
                    pass

    print(f"Loaded {len(passwords)} real passwords.")
    return passwords

# ==========================================
# 3. The BiLSTM Architecture (ADDED REGULARIZATION)
# ==========================================
class PasswordPredictorBiLSTM(nn.Module):
    def __init__(self, embed_size=32, hidden_size=64, num_layers=2, dropout_prob=0.3):
        super(PasswordPredictorBiLSTM, self).__init__()
        self.embedding = nn.Embedding(num_embeddings=VOCAB_SIZE, embedding_dim=embed_size, padding_idx=0)
        
        # REGULARIZATION: Added `dropout` to the LSTM cells. This forces the network to not rely 
        # on highly specific character patterns, thus generalizing better to unseen passwords.
        self.lstm = nn.LSTM(input_size=embed_size, hidden_size=hidden_size, num_layers=num_layers, 
                            batch_first=True, bidirectional=True, 
                            dropout=dropout_prob if num_layers > 1 else 0.0)
        
        # REGULARIZATION: Added Dropout before the final classification head
        self.dropout = nn.Dropout(dropout_prob)
        self.fc = nn.Linear(hidden_size * 2, 1)
        self.sigmoid = nn.Sigmoid()

    def forward(self, x):
        embedded = self.embedding(x)
        lstm_out, _ = self.lstm(embedded)
        
        # Apply dropout to the last timestep output
        out = self.dropout(lstm_out[:, -1, :])
        return self.sigmoid(self.fc(out))

# ==========================================
# 4. Helper Functions
# ==========================================
def encode_password(password, max_len=32):
    encoded = [CHAR_TO_IDX.get(c, 0) for c in password[:max_len]]
    encoded += [0] * (max_len - len(encoded))
    return encoded # Returning generic list to easily build TensorDataset

def generate_random_password(length):
    return ''.join(random.choices(string.ascii_letters + string.digits + string.punctuation, k=length))

# ==========================================
# 5. Training Loop
# ==========================================
def train_mvp_model():
    # Regularized model with 40% dropout
    model = PasswordPredictorBiLSTM(dropout_prob=0.4).to(DEVICE)
    criterion = nn.BCELoss() 
    
    # REGULARIZATION: Added `weight_decay=1e-4` (L2 Weight Penalty). This prevents weights 
    # from growing too large, drastically mitigating overfitting.
    optimizer = optim.Adam(model.parameters(), lr=0.002, weight_decay=1e-4)

    dataset_path = os.path.join("dataset", "strong-passwords-in-rockyou2024-txt")
    rockyou_subset = load_real_passwords(dataset_path, max_passwords=50000)
    
    if not rockyou_subset:
        print("❌ ERROR: No passwords found. Check your dataset path.")
        return None

    print("Generating AI targets & Compiling Batches...")
    all_inputs = []
    all_targets = []
    
    for pw in rockyou_subset:
        all_inputs.append(encode_password(pw))
        all_targets.append([1.0])
        
    for _ in range(len(rockyou_subset)):
        secure_pw = generate_random_password(random.randint(8, 20))
        all_inputs.append(encode_password(secure_pw))
        all_targets.append([0.0])
        
    # Convert lists into efficient batched PyTorch Tensors
    inputs_tensor = torch.tensor(all_inputs, dtype=torch.long)
    targets_tensor = torch.tensor(all_targets, dtype=torch.float32)
    
    # Create DataLoader which securely handles grouping our objects into chunks of 512!
    dataset = TensorDataset(inputs_tensor, targets_tensor)
    train_loader = DataLoader(dataset, batch_size=BATCH_SIZE, shuffle=True)

    print(f"Starting training on {DEVICE} | Batch Size: {BATCH_SIZE}...")
    epochs = 20 
    
    for epoch in range(epochs):
        model.train() # Make sure to inform PyTorch we are training so DropOut applies!
        
        batch_iterator = tqdm(train_loader, desc=f"Epoch {epoch+1:02d}/{epochs}", unit="batch")
        total_loss = 0
        total_items = 0
        
        for batch_inputs, batch_targets in batch_iterator:
            batch_inputs, batch_targets = batch_inputs.to(DEVICE), batch_targets.to(DEVICE)
            
            optimizer.zero_grad()
            outputs = model(batch_inputs)
            loss = criterion(outputs, batch_targets)
            loss.backward()
            optimizer.step()
            
            total_loss += loss.item() * batch_inputs.size(0)
            total_items += batch_inputs.size(0)
            
            # Display current average loss
            batch_iterator.set_postfix(loss=f"{total_loss / total_items:.4f}")
            
    torch.save(model.state_dict(), "bilstm_password_weights.pth")
    print("\n✅ Training complete. Brain saved to bilstm_password_weights.pth")
    return model

if __name__ == "__main__":
    train_mvp_model()