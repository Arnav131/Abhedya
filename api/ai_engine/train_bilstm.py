import torch
import torch.nn as nn
import torch.optim as optim
import string
import random
from tqdm import tqdm

# ==========================================
# 1. Configuration & Vocabulary
# ==========================================
# We use all standard printable characters. 
VOCAB = list(string.printable)
CHAR_TO_IDX = {char: idx + 1 for idx, char in enumerate(VOCAB)} # 0 is reserved for padding
VOCAB_SIZE = len(VOCAB) + 1

# Check for RTX 5070 (CUDA)
DEVICE = torch.device("cuda" if torch.cuda.is_available() else "cpu")
print(f"Running on: {DEVICE}")

# ==========================================
# 2. The BiLSTM Architecture
# ==========================================
class PasswordPredictorBiLSTM(nn.Module):
    def __init__(self, embed_size=32, hidden_size=64, num_layers=2):
        super(PasswordPredictorBiLSTM, self).__init__()
        
        # Converts character indices into dense vectors
        self.embedding = nn.Embedding(num_embeddings=VOCAB_SIZE, embedding_dim=embed_size, padding_idx=0)
        
        # The BiLSTM reads forwards and backwards
        self.lstm = nn.LSTM(input_size=embed_size, 
                            hidden_size=hidden_size, 
                            num_layers=num_layers,
                            batch_first=True, 
                            bidirectional=True)
        
        # Fully connected layer maps the BiLSTM output to a single number
        # Multiply hidden_size by 2 because it's bidirectional
        self.fc = nn.Linear(hidden_size * 2, 1)
        
        # Squashes the final output between 0.0 and 1.0
        self.sigmoid = nn.Sigmoid()

    def forward(self, x):
        embedded = self.embedding(x)
        lstm_out, _ = self.lstm(embedded)
        
        # We only care about the network's state at the very last character
        last_time_step = lstm_out[:, -1, :] 
        
        out = self.fc(last_time_step)
        return self.sigmoid(out)

# ==========================================
# 3. Helper Functions
# ==========================================
def encode_password(password, max_len=32):
    """Converts a string password into a tensor of integers."""
    encoded = [CHAR_TO_IDX.get(c, 0) for c in password[:max_len]]
    # Pad with 0s if it's shorter than max_len
    encoded += [0] * (max_len - len(encoded))
    return torch.tensor(encoded, dtype=torch.long)

def generate_random_password(length):
    """Creates a mathematically secure '0.0' label password."""
    return ''.join(random.choices(string.ascii_letters + string.digits + string.punctuation, k=length))

# ==========================================
# 4. MVP Training Loop
# ==========================================
def train_mvp_model():
    model = PasswordPredictorBiLSTM().to(DEVICE)
    criterion = nn.BCELoss() 
    optimizer = optim.Adam(model.parameters(), lr=0.005)

    print("Generating training data...")
    rockyou_subset = ["password123", "qwerty", "iloveyou", "admin", "123456", "Summer2023!", "johndoe1", "letmein123"]
    
    training_data = []
    for pw in rockyou_subset:
        training_data.append((encode_password(pw), torch.tensor([1.0])))
    for _ in range(len(rockyou_subset)):
        secure_pw = generate_random_password(random.randint(8, 16))
        training_data.append((encode_password(secure_pw), torch.tensor([0.0])))
        
    random.shuffle(training_data)

    print(f"Training model on {DEVICE}...")
    model.train()
    epochs = 15
    
    # Outer loop for epochs
    for epoch in range(epochs):
        total_loss = 0
        
        # Inner loop wrapped in tqdm for a sleek progress bar
        batch_iterator = tqdm(training_data, desc=f"Epoch {epoch+1:02d}/{epochs}", unit="pw", leave=True)
        
        for inputs, targets in batch_iterator:
            inputs, targets = inputs.unsqueeze(0).to(DEVICE), targets.unsqueeze(0).to(DEVICE)
            
            optimizer.zero_grad()
            outputs = model(inputs)
            loss = criterion(outputs, targets)
            loss.backward()
            optimizer.step()
            
            total_loss += loss.item()
            
            # Live-update the progress bar with the current loss
            batch_iterator.set_postfix(loss=f"{loss.item():.4f}")
            
    # Save the trained weights
    torch.save(model.state_dict(), "bilstm_password_weights.pth")
    print("\n✅ Training complete. Weights saved to bilstm_password_weights.pth")
    return model

# ==========================================
# 5. Inference (How Django will use it)
# ==========================================
def predict_score(model, password):
    model.eval()
    with torch.no_grad():
        inputs = encode_password(password).unsqueeze(0).to(DEVICE)
        score = model(inputs).item()
        
    print(f"\nPassword: '{password}'")
    print(f"Predictability Score: {score:.4f} ", end="")
    if score > 0.7:
        print("❌ (Highly Predictable - Hacker bait)")
    elif score > 0.3:
        print("⚠️ (Moderate - Regex might pass, but AI caught it)")
    else:
        print("✅ (Secure - Looks like statistical noise)")

# --- Run the Script ---
if __name__ == "__main__":
    trained_model = train_mvp_model()
    
    # Let's test it against things the model has never seen
    predict_score(trained_model, "Winter2024!") # Human pattern
    predict_score(trained_model, "qK3$zP9x!Lw2") # Mathematically random