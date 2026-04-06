"""
SecureVault — Password Predictability Engine
=============================================
Character-level RNN (LSTM) that estimates the statistical probability of a
password being guessed by a human or a pattern-based attacker.

Architecture
------------
  Input chars  →  Embedding  →  Bi-LSTM (2 layers, dropout)  →  FC  →  Sigmoid

Output
------
  A float in [0, 1] called the *predictability score*.
      0.0  =  virtually impossible to guess  (strong)
      1.0  =  trivially guessable            (weak)

Security
--------
  • No password is ever written to disk, logged, or transmitted.
  • All inference happens in-memory; tensors are deleted after use.
  • The module makes zero external network calls.

Django integration
------------------
    from ai_engine.pytorch_model import predict_strength, classify_strength

    score = predict_strength("MyP@ssw0rd!")   # 0.0 – 1.0
    label = classify_strength("MyP@ssw0rd!")  # "strong" | "medium" | "weak"
"""

from __future__ import annotations

import gc
import logging
import math
import os
import random
import re
import string
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple

import torch
import torch.nn as nn
from torch.nn.utils.rnn import pad_sequence
from torch.utils.data import DataLoader, Dataset, random_split

# ---------------------------------------------------------------------------
# Logging — never emit password content
# ---------------------------------------------------------------------------
logger = logging.getLogger("securevault.ai_engine")
logger.setLevel(logging.INFO)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
# Printable ASCII characters used as the model vocabulary.
# Index 0 is reserved for <PAD>.
VOCAB_CHARS: str = string.printable  # 100 printable ASCII characters
CHAR_TO_IDX: dict[str, int] = {ch: idx + 1 for idx, ch in enumerate(VOCAB_CHARS)}
IDX_TO_CHAR: dict[int, str] = {idx + 1: ch for idx, ch in enumerate(VOCAB_CHARS)}
VOCAB_SIZE: int = len(VOCAB_CHARS) + 1  # +1 for <PAD> at index 0
PAD_IDX: int = 0

# Maximum password length the model will process (chars beyond this are
# truncated — this is already an indicator of a strong password).
MAX_SEQ_LEN: int = 128

# Default thresholds for the classification helper.
WEAK_THRESHOLD: float = 0.60
MEDIUM_THRESHOLD: float = 0.30

# Default model weights path (relative to this file's directory).
DEFAULT_WEIGHTS_DIR: Path = Path(__file__).resolve().parent / "weights"
DEFAULT_WEIGHTS_PATH: Path = DEFAULT_WEIGHTS_DIR / "password_rnn.pt"
WEIGHTS_ENV_VAR: str = "SECUREVAULT_PASSWORD_MODEL_WEIGHTS"
PROJECT_ROOT: Path = Path(__file__).resolve().parents[2]
LEGACY_BILSTM_WEIGHTS_PATH: Path = PROJECT_ROOT / "bilstm_password_weights.pth"
BILSTM_COMPAT_SEQ_LEN: int = 32


# ---------------------------------------------------------------------------
# Hyperparameter container
# ---------------------------------------------------------------------------
@dataclass
class HyperParams:
    """All tuneable knobs in one place."""

    embed_dim: int = 64
    hidden_dim: int = 128
    num_layers: int = 2
    dropout: float = 0.3
    bidirectional: bool = True
    learning_rate: float = 1e-3
    batch_size: int = 256
    epochs: int = 10
    val_split: float = 0.15
    max_seq_len: int = MAX_SEQ_LEN
    device: str = field(default_factory=lambda: "cuda" if torch.cuda.is_available() else "cpu")


# ============================================================================
#  1. TOKENIZER
# ============================================================================

def tokenize(password: str, max_len: int = MAX_SEQ_LEN) -> torch.Tensor:
    """Convert a password string to a tensor of integer indices.

    Unknown characters are silently skipped (they add no predictable
    pattern information).  The tensor is truncated to *max_len*.
    """
    indices = [CHAR_TO_IDX[ch] for ch in password[:max_len] if ch in CHAR_TO_IDX]
    if not indices:
        # Edge-case: empty or fully-unknown input → single PAD token.
        indices = [PAD_IDX]
    return torch.tensor(indices, dtype=torch.long)


def tokenize_fixed(password: str, max_len: int = BILSTM_COMPAT_SEQ_LEN) -> torch.Tensor:
    """Fixed-length tokenization for legacy BiLSTM checkpoints.

    This mirrors the encoding scheme used by `train_bilstm.py` where:
        - unknown chars map to PAD(0)
        - sequence is right-padded/truncated to fixed max_len
    """
    encoded = [CHAR_TO_IDX.get(ch, PAD_IDX) for ch in password[:max_len]]
    encoded += [PAD_IDX] * (max_len - len(encoded))
    return torch.tensor(encoded, dtype=torch.long)


def collate_batch(
    batch: List[Tuple[torch.Tensor, float]],
) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
    """Custom collate: pad sequences, return (padded_seqs, lengths, labels)."""
    sequences, labels = zip(*batch)
    lengths = torch.tensor([len(s) for s in sequences], dtype=torch.long)
    padded = pad_sequence(sequences, batch_first=True, padding_value=PAD_IDX)
    labels_t = torch.tensor(labels, dtype=torch.float32)
    return padded, lengths, labels_t


# ============================================================================
#  2. DATASET — Simulated password corpus
# ============================================================================

class PasswordDataset(Dataset):
    """Labeled password dataset.

    Accepts either:
      • a list of ``(password_str, label_float)`` pairs, or
      • a path to a file with lines of ``password<TAB>label``.

    If neither is provided, a synthetic dataset is generated that simulates
    the distribution found in public breach corpora (e.g. rockyou).
    """

    def __init__(
        self,
        pairs: Optional[List[Tuple[str, float]]] = None,
        filepath: Optional[str] = None,
        max_len: int = MAX_SEQ_LEN,
        synthetic_size: int = 50_000,
    ) -> None:
        self.max_len = max_len
        self.data: List[Tuple[torch.Tensor, float]] = []

        if pairs is not None:
            for pw, label in pairs:
                self.data.append((tokenize(pw, max_len), float(label)))
        elif filepath is not None:
            self._load_file(filepath)
        else:
            self._generate_synthetic(synthetic_size)

    # ------------------------------------------------------------------
    def _load_file(self, filepath: str) -> None:
        """Load tab-separated ``password<TAB>label`` file."""
        with open(filepath, "r", encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                line = line.strip()
                if "\t" not in line:
                    continue
                pw, label_str = line.rsplit("\t", 1)
                try:
                    label = float(label_str)
                except ValueError:
                    continue
                self.data.append((tokenize(pw, self.max_len), label))

    # ------------------------------------------------------------------
    # Synthetic data generators
    # ------------------------------------------------------------------
    @staticmethod
    def _random_weak_password() -> str:
        """Generates a password that mimics common weak patterns."""
        patterns = [
            # Dictionary words / names
            lambda: random.choice([
                "password", "letmein", "welcome", "monkey", "dragon",
                "master", "qwerty", "login", "princess", "football",
                "shadow", "sunshine", "trustno1", "iloveyou", "batman",
                "access", "hello", "charlie", "donald", "admin",
                "passw0rd", "p@ssword", "password1", "password123",
            ]),
            # Simple numeric sequences
            lambda: "".join([str(d) for d in range(1, random.randint(5, 9))]),
            # Repeated characters
            lambda: random.choice(string.ascii_lowercase) * random.randint(4, 10),
            # Keyboard walks
            lambda: random.choice([
                "qwerty", "asdfgh", "zxcvbn", "qwertyuiop", "1qaz2wsx",
                "qazwsx", "1234qwer", "asdf1234",
            ]),
            # Name + year
            lambda: random.choice([
                "john", "mike", "anna", "sara", "david", "emma", "chris",
            ]) + str(random.randint(1970, 2010)),
            # Common substitution patterns
            lambda: random.choice([
                "p@ss", "adm1n", "r00t", "l0gin", "w3lcome",
            ]) + str(random.randint(0, 999)),
        ]
        return random.choice(patterns)()

    @staticmethod
    def _random_strong_password(min_len: int = 12, max_len: int = 32) -> str:
        """Generates a cryptographically-style random password."""
        length = random.randint(min_len, max_len)
        alphabet = string.ascii_letters + string.digits + string.punctuation
        return "".join(random.choices(alphabet, k=length))

    @staticmethod
    def _random_medium_password() -> str:
        """Generates a password that has *some* complexity but predictable structure."""
        base_words = [
            "Summer", "Winter", "Spring", "Autumn", "Monday", "Friday",
            "Happy", "Lucky", "Super", "Mega", "Blue", "Red", "Green",
            "Coffee", "Music", "River", "Storm", "Light", "Night", "Star",
        ]
        word = random.choice(base_words)
        suffix = str(random.randint(10, 9999))
        symbol = random.choice("!@#$%^&*")
        parts = [word, suffix, symbol]
        random.shuffle(parts)
        return "".join(parts)

    def _generate_synthetic(self, size: int) -> None:
        """Build a balanced synthetic dataset.

        Distribution:
            40 %  weak       (label = 0.85 – 1.0)
            25 %  medium     (label = 0.35 – 0.65)
            35 %  strong     (label = 0.0 – 0.15)
        """
        counts = {
            "weak": int(size * 0.40),
            "medium": int(size * 0.25),
            "strong": size - int(size * 0.40) - int(size * 0.25),
        }

        for _ in range(counts["weak"]):
            pw = self._random_weak_password()
            label = random.uniform(0.85, 1.0)
            self.data.append((tokenize(pw, self.max_len), label))

        for _ in range(counts["medium"]):
            pw = self._random_medium_password()
            label = random.uniform(0.35, 0.65)
            self.data.append((tokenize(pw, self.max_len), label))

        for _ in range(counts["strong"]):
            pw = self._random_strong_password()
            label = random.uniform(0.0, 0.15)
            self.data.append((tokenize(pw, self.max_len), label))

        random.shuffle(self.data)
        logger.info(
            "Synthetic dataset created — %d weak, %d medium, %d strong (total %d)",
            counts["weak"], counts["medium"], counts["strong"], len(self.data),
        )

    # ------------------------------------------------------------------
    def __len__(self) -> int:
        return len(self.data)

    def __getitem__(self, idx: int) -> Tuple[torch.Tensor, float]:
        return self.data[idx]


# ============================================================================
#  3. MODEL
# ============================================================================

class PasswordRNN(nn.Module):
    """Character-level Bi-LSTM for password predictability scoring.

    Forward pass returns a scalar in [0, 1] per sample.
    """

    def __init__(
        self,
        vocab_size: int = VOCAB_SIZE,
        embed_dim: int = 64,
        hidden_dim: int = 128,
        num_layers: int = 2,
        dropout: float = 0.3,
        bidirectional: bool = True,
        pad_idx: int = PAD_IDX,
    ) -> None:
        super().__init__()
        self.hidden_dim = hidden_dim
        self.num_layers = num_layers
        self.bidirectional = bidirectional
        self.num_directions = 2 if bidirectional else 1

        # Character embedding (PAD index is zeroed out).
        self.embedding = nn.Embedding(
            num_embeddings=vocab_size,
            embedding_dim=embed_dim,
            padding_idx=pad_idx,
        )

        # Recurrent backbone.
        self.lstm = nn.LSTM(
            input_size=embed_dim,
            hidden_size=hidden_dim,
            num_layers=num_layers,
            batch_first=True,
            dropout=dropout if num_layers > 1 else 0.0,
            bidirectional=bidirectional,
        )

        # Classifier head.
        fc_input_dim = hidden_dim * self.num_directions
        self.classifier = nn.Sequential(
            nn.Dropout(dropout),
            nn.Linear(fc_input_dim, fc_input_dim // 2),
            nn.ReLU(),
            nn.Dropout(dropout / 2),
            nn.Linear(fc_input_dim // 2, 1),
            nn.Sigmoid(),
        )

    def forward(
        self,
        x: torch.Tensor,
        lengths: Optional[torch.Tensor] = None,
    ) -> torch.Tensor:
        """
        Parameters
        ----------
        x : Tensor  (batch, seq_len)  — padded token indices
        lengths : Tensor  (batch,)    — original sequence lengths

        Returns
        -------
        Tensor (batch,) — predictability scores in [0, 1]
        """
        embedded = self.embedding(x)  # (B, L, E)

        if lengths is not None:
            # Pack for efficient computation over variable-length sequences.
            packed = nn.utils.rnn.pack_padded_sequence(
                embedded,
                lengths.cpu().clamp(min=1),
                batch_first=True,
                enforce_sorted=False,
            )
            output, (hidden, _) = self.lstm(packed)
        else:
            _, (hidden, _) = self.lstm(embedded)

        # Concatenate the final hidden states from both directions.
        # hidden shape: (num_layers * num_directions, B, H)
        if self.bidirectional:
            # Take the last layer's forward and backward hidden states.
            h_fwd = hidden[-2]  # (B, H)
            h_bwd = hidden[-1]  # (B, H)
            h_cat = torch.cat([h_fwd, h_bwd], dim=1)  # (B, 2H)
        else:
            h_cat = hidden[-1]  # (B, H)

        score = self.classifier(h_cat).squeeze(-1)  # (B,)
        return score


class PasswordBiLSTMCompat(nn.Module):
    """Compatibility model for `bilstm_password_weights.pth` checkpoints."""

    def __init__(
        self,
        vocab_size: int = VOCAB_SIZE,
        embed_dim: int = 32,
        hidden_dim: int = 64,
        num_layers: int = 2,
        pad_idx: int = PAD_IDX,
    ) -> None:
        super().__init__()
        self.embedding = nn.Embedding(
            num_embeddings=vocab_size,
            embedding_dim=embed_dim,
            padding_idx=pad_idx,
        )
        self.lstm = nn.LSTM(
            input_size=embed_dim,
            hidden_size=hidden_dim,
            num_layers=num_layers,
            batch_first=True,
            bidirectional=True,
        )
        self.fc = nn.Linear(hidden_dim * 2, 1)
        self.sigmoid = nn.Sigmoid()

    def forward(
        self,
        x: torch.Tensor,
        lengths: Optional[torch.Tensor] = None,
    ) -> torch.Tensor:
        del lengths
        embedded = self.embedding(x)
        lstm_out, _ = self.lstm(embedded)
        last_time_step = lstm_out[:, -1, :]
        out = self.fc(last_time_step)
        return self.sigmoid(out).squeeze(-1)


# ============================================================================
#  4. TRAINING ENGINE
# ============================================================================

class Trainer:
    """End-to-end training and validation loop with CUDA support."""

    def __init__(self, hp: Optional[HyperParams] = None) -> None:
        self.hp = hp or HyperParams()
        self.device = torch.device(self.hp.device)
        self.model = self._build_model().to(self.device)
        self.criterion = nn.BCELoss()
        self.optimizer = torch.optim.Adam(
            self.model.parameters(), lr=self.hp.learning_rate
        )
        self.history: dict[str, list[float]] = {"train_loss": [], "val_loss": []}

    def _build_model(self) -> PasswordRNN:
        return PasswordRNN(
            vocab_size=VOCAB_SIZE,
            embed_dim=self.hp.embed_dim,
            hidden_dim=self.hp.hidden_dim,
            num_layers=self.hp.num_layers,
            dropout=self.hp.dropout,
            bidirectional=self.hp.bidirectional,
        )

    # ------------------------------------------------------------------
    def fit(self, dataset: Optional[PasswordDataset] = None) -> dict[str, list[float]]:
        """Train the model.  Uses a synthetic dataset if none is provided.

        Returns the training history dict.
        """
        if dataset is None:
            dataset = PasswordDataset()

        # Train / validation split.
        val_size = int(len(dataset) * self.hp.val_split)
        train_size = len(dataset) - val_size
        train_ds, val_ds = random_split(dataset, [train_size, val_size])

        train_loader = DataLoader(
            train_ds,
            batch_size=self.hp.batch_size,
            shuffle=True,
            collate_fn=collate_batch,
            num_workers=0,
            pin_memory=self.device.type == "cuda",
        )
        val_loader = DataLoader(
            val_ds,
            batch_size=self.hp.batch_size,
            shuffle=False,
            collate_fn=collate_batch,
            num_workers=0,
            pin_memory=self.device.type == "cuda",
        )

        logger.info(
            "Training on %s  |  train=%d  val=%d  epochs=%d",
            self.device, train_size, val_size, self.hp.epochs,
        )

        for epoch in range(1, self.hp.epochs + 1):
            train_loss = self._train_epoch(train_loader)
            val_loss = self._validate(val_loader)
            self.history["train_loss"].append(train_loss)
            self.history["val_loss"].append(val_loss)
            logger.info(
                "Epoch %02d/%02d  —  train_loss=%.5f  val_loss=%.5f",
                epoch, self.hp.epochs, train_loss, val_loss,
            )

        return self.history

    # ------------------------------------------------------------------
    def _train_epoch(self, loader: DataLoader) -> float:
        self.model.train()
        total_loss = 0.0
        n_batches = 0
        for seqs, lengths, labels in loader:
            seqs = seqs.to(self.device)
            lengths = lengths.to(self.device)
            labels = labels.to(self.device)

            self.optimizer.zero_grad()
            preds = self.model(seqs, lengths)
            loss = self.criterion(preds, labels)
            loss.backward()
            # Gradient clipping to stabilise LSTM training.
            nn.utils.clip_grad_norm_(self.model.parameters(), max_norm=5.0)
            self.optimizer.step()

            total_loss += loss.item()
            n_batches += 1

        return total_loss / max(n_batches, 1)

    # ------------------------------------------------------------------
    @torch.no_grad()
    def _validate(self, loader: DataLoader) -> float:
        self.model.eval()
        total_loss = 0.0
        n_batches = 0
        for seqs, lengths, labels in loader:
            seqs = seqs.to(self.device)
            lengths = lengths.to(self.device)
            labels = labels.to(self.device)

            preds = self.model(seqs, lengths)
            loss = self.criterion(preds, labels)
            total_loss += loss.item()
            n_batches += 1

        return total_loss / max(n_batches, 1)

    # ------------------------------------------------------------------
    def save_weights(self, path: Optional[str] = None) -> Path:
        """Persist model weights to disk.

        Creates the parent directory if it doesn't exist.
        """
        save_path = Path(path) if path else DEFAULT_WEIGHTS_PATH
        save_path.parent.mkdir(parents=True, exist_ok=True)
        torch.save(self.model.state_dict(), save_path)
        logger.info("Model weights saved to %s", save_path)
        return save_path


# ============================================================================
#  5. ENTROPY-BASED FALLBACK
# ============================================================================

def _entropy_score(password: str) -> float:
    """Shannon entropy of the password, normalised to [0, 1].

    Used as a quick fallback when the neural model is unavailable.
    Higher entropy → lower predictability → lower returned score.
    """
    if not password:
        return 1.0  # Empty = maximally predictable

    freq: dict[str, int] = {}
    for ch in password:
        freq[ch] = freq.get(ch, 0) + 1

    length = len(password)
    entropy = -sum(
        (count / length) * math.log2(count / length) for count in freq.values()
    )

    # Determine the theoretical max entropy for this character set.
    charset_size = 0
    if any(c in string.ascii_lowercase for c in password):
        charset_size += 26
    if any(c in string.ascii_uppercase for c in password):
        charset_size += 26
    if any(c in string.digits for c in password):
        charset_size += 10
    if any(c in string.punctuation for c in password):
        charset_size += 32

    max_entropy = math.log2(charset_size) if charset_size > 1 else 1.0

    # Normalise: high entropy → low predictability.
    normalised = min(entropy / max_entropy, 1.0) if max_entropy > 0 else 0.0

    # Also penalise short passwords.
    length_factor = min(length / 16.0, 1.0)  # Passwords ≥ 16 chars get full credit.

    combined = normalised * 0.7 + length_factor * 0.3

    # Invert: the caller expects 0 = strong, 1 = weak.
    return round(1.0 - combined, 4)


# ============================================================================
#  6. GLOBAL MODEL SINGLETON (lazy-loaded)
# ============================================================================

_model_instance: Optional[nn.Module] = None
_model_device: Optional[torch.device] = None
_model_kind: str = "password_rnn"


def _get_device() -> torch.device:
    """Return the best available device (CUDA preferred)."""
    if torch.cuda.is_available():
        return torch.device("cuda")
    return torch.device("cpu")


def _extract_state_dict(payload: object) -> dict[str, torch.Tensor]:
    """Extract state_dict from raw torch checkpoint payload."""
    if isinstance(payload, dict):
        if payload and all(isinstance(v, torch.Tensor) for v in payload.values()):
            return payload  # plain state_dict

        for key in ("state_dict", "model_state_dict"):
            nested = payload.get(key)
            if isinstance(nested, dict) and nested and all(
                isinstance(v, torch.Tensor) for v in nested.values()
            ):
                return nested

    raise ValueError("Unsupported checkpoint format: expected state_dict-like payload")


def _infer_checkpoint_kind(state: dict[str, torch.Tensor]) -> str:
    keys = set(state.keys())
    if any(k.startswith("classifier.") for k in keys):
        return "password_rnn"
    if "fc.weight" in keys and "lstm.weight_ih_l0" in keys:
        return "bilstm_compat"
    return "password_rnn"


def _infer_bilstm_compat_hparams(
    state: dict[str, torch.Tensor],
) -> tuple[int, int, int]:
    embed_dim = int(state["embedding.weight"].shape[1])
    hidden_dim = int(state["lstm.weight_hh_l0"].shape[1])

    layer_indices: list[int] = []
    pattern = re.compile(r"lstm\.weight_ih_l(\d+)(?:_reverse)?$")
    for key in state.keys():
        match = pattern.match(key)
        if match:
            layer_indices.append(int(match.group(1)))

    num_layers = (max(layer_indices) + 1) if layer_indices else 2
    return embed_dim, hidden_dim, num_layers


def _resolve_weights_path(weights_path: Optional[str]) -> Path:
    if weights_path:
        return Path(weights_path)

    env_weights = os.getenv(WEIGHTS_ENV_VAR)
    env_path = Path(env_weights) if env_weights else None

    if LEGACY_BILSTM_WEIGHTS_PATH.exists():
        if env_path is None:
            return LEGACY_BILSTM_WEIGHTS_PATH

        # If env is still pointing at the old default RNN checkpoint,
        # prefer the user-provided BiLSTM weights automatically.
        try:
            if env_path.resolve() == DEFAULT_WEIGHTS_PATH.resolve():
                return LEGACY_BILSTM_WEIGHTS_PATH
        except OSError:
            if str(env_path) == str(DEFAULT_WEIGHTS_PATH):
                return LEGACY_BILSTM_WEIGHTS_PATH

    if env_path:
        return env_path

    return DEFAULT_WEIGHTS_PATH


def load_model(
    weights_path: Optional[str] = None,
    device: Optional[str] = None,
    hp: Optional[HyperParams] = None,
) -> nn.Module:
    """Load (or reload) the global model singleton.

    Parameters
    ----------
    weights_path : path to saved state_dict.  Falls back to the default
                   path if omitted.
    device : "cuda", "cpu", or ``None`` (auto-detect).
    hp : hyperparameters used to construct the model architecture.

    Returns the loaded model (also cached globally for ``predict_strength``).
    """
    global _model_instance, _model_device, _model_kind

    hp = hp or HyperParams()
    _model_device = torch.device(device) if device else _get_device()

    resolved_path = _resolve_weights_path(weights_path)

    model: nn.Module
    checkpoint_kind = "password_rnn"
    if resolved_path.exists():
        try:
            raw = torch.load(resolved_path, map_location=_model_device, weights_only=True)
        except TypeError:
            raw = torch.load(resolved_path, map_location=_model_device)

        state = _extract_state_dict(raw)
        checkpoint_kind = _infer_checkpoint_kind(state)

        if checkpoint_kind == "bilstm_compat":
            embed_dim, hidden_dim, num_layers = _infer_bilstm_compat_hparams(state)
            model = PasswordBiLSTMCompat(
                vocab_size=VOCAB_SIZE,
                embed_dim=embed_dim,
                hidden_dim=hidden_dim,
                num_layers=num_layers,
            )
        else:
            model = PasswordRNN(
                vocab_size=VOCAB_SIZE,
                embed_dim=hp.embed_dim,
                hidden_dim=hp.hidden_dim,
                num_layers=hp.num_layers,
                dropout=hp.dropout,
                bidirectional=hp.bidirectional,
            )

        model.load_state_dict(state, strict=True)
        logger.info(
            "Loaded %s weights from %s onto %s",
            checkpoint_kind,
            resolved_path,
            _model_device,
        )
    else:
        model = PasswordRNN(
            vocab_size=VOCAB_SIZE,
            embed_dim=hp.embed_dim,
            hidden_dim=hp.hidden_dim,
            num_layers=hp.num_layers,
            dropout=hp.dropout,
            bidirectional=hp.bidirectional,
        )
        logger.warning(
            "No weights found at %s — model is uninitialised.  "
            "Call `train_model()` first or supply a valid path via argument or %s.",
            resolved_path,
            WEIGHTS_ENV_VAR,
        )

    model.to(_model_device)
    model.eval()
    _model_instance = model
    _model_kind = checkpoint_kind
    return model


# ============================================================================
#  7. PUBLIC API — Inference
# ============================================================================

@torch.no_grad()
def predict_strength(password: str) -> float:
    """Return the predictability score for *password*.

    Score range: **0.0** (virtually unguessable) to **1.0** (trivially guessable).

    If the neural model is not available (no weights / CUDA failure),
    the function transparently falls back to an entropy heuristic.

    Security: the raw password is never logged, stored, or transmitted.
    """
    global _model_instance, _model_device, _model_kind

    # ---- Fallback path ----
    if _model_instance is None:
        try:
            load_model()
        except Exception:
            logger.warning("Neural model unavailable — using entropy fallback.")
            return _entropy_score(password)

    if _model_instance is None:
        return _entropy_score(password)

    try:
        if _model_kind == "bilstm_compat":
            tokens = tokenize_fixed(password, max_len=BILSTM_COMPAT_SEQ_LEN).unsqueeze(0).to(_model_device)
            score = _model_instance(tokens).item()
            del tokens
        else:
            tokens = tokenize(password).unsqueeze(0).to(_model_device)  # (1, L)
            length = torch.tensor([tokens.size(1)], dtype=torch.long).to(_model_device)
            score = _model_instance(tokens, length).item()
            del tokens, length

        if _model_device and _model_device.type == "cuda":
            torch.cuda.empty_cache()

        return round(score, 4)
    except Exception as exc:
        logger.error("Inference failed (%s) — falling back to entropy.", exc)
        return _entropy_score(password)
    finally:
        gc.collect()


def classify_strength(
    password: str,
    weak_threshold: float = WEAK_THRESHOLD,
    medium_threshold: float = MEDIUM_THRESHOLD,
) -> str:
    """Return a human-readable strength label.

    Labels:
        "weak"    — score >= weak_threshold
        "medium"  — medium_threshold <= score < weak_threshold
        "strong"  — score < medium_threshold
    """
    score = predict_strength(password)
    if score >= weak_threshold:
        return "weak"
    if score >= medium_threshold:
        return "medium"
    return "strong"


def predict_strength_detailed(password: str) -> dict:
    """Return a detailed analysis dict suitable for API responses.

    Keys:
        score   — float, 0-1 predictability score
        label   — str, "weak" / "medium" / "strong"
        entropy — float, 0-1 entropy-based fallback score
    """
    score = predict_strength(password)
    entropy = _entropy_score(password)

    if score >= WEAK_THRESHOLD:
        label = "weak"
    elif score >= MEDIUM_THRESHOLD:
        label = "medium"
    else:
        label = "strong"

    return {
        "score": score,
        "label": label,
        "entropy_score": entropy,
    }


# ============================================================================
#  8. CONVENIENCE — Train & persist from scratch
# ============================================================================

def train_model(
    hp: Optional[HyperParams] = None,
    dataset: Optional[PasswordDataset] = None,
    save_path: Optional[str] = None,
) -> dict[str, list[float]]:
    """One-call training: builds, trains, saves, and loads the model.

    Useful for initial setup or periodic retraining.

    Returns the training history dict.
    """
    trainer = Trainer(hp=hp)
    history = trainer.fit(dataset=dataset)
    saved = trainer.save_weights(path=save_path)

    # Promote the freshly trained model to the global singleton.
    load_model(weights_path=str(saved), device=trainer.hp.device, hp=trainer.hp)

    return history


# ============================================================================
#  9. CLI ENTRY POINT (for standalone testing / training)
# ============================================================================

if __name__ == "__main__":
    import argparse
    import sys

    parser = argparse.ArgumentParser(
        description="SecureVault Password Predictability Engine"
    )
    sub = parser.add_subparsers(dest="command")

    # -- train --
    train_parser = sub.add_parser("train", help="Train the model from scratch")
    train_parser.add_argument("--epochs", type=int, default=10)
    train_parser.add_argument("--batch-size", type=int, default=256)
    train_parser.add_argument("--lr", type=float, default=1e-3)
    train_parser.add_argument("--hidden-dim", type=int, default=128)
    train_parser.add_argument("--embed-dim", type=int, default=64)
    train_parser.add_argument("--dataset-size", type=int, default=50_000)
    train_parser.add_argument("--save-path", type=str, default=None)

    # -- predict --
    predict_parser = sub.add_parser("predict", help="Score a password")
    predict_parser.add_argument("password", type=str, help="Password to analyse")

    # -- benchmark --
    bench_parser = sub.add_parser("benchmark", help="Run a quick benchmark")

    args = parser.parse_args()

    if args.command == "train":
        logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")
        hp = HyperParams(
            epochs=args.epochs,
            batch_size=args.batch_size,
            learning_rate=args.lr,
            hidden_dim=args.hidden_dim,
            embed_dim=args.embed_dim,
        )
        ds = PasswordDataset(synthetic_size=args.dataset_size)
        history = train_model(hp=hp, dataset=ds, save_path=args.save_path)
        print("\n✅ Training complete.")
        print(f"   Final train loss: {history['train_loss'][-1]:.5f}")
        print(f"   Final val   loss: {history['val_loss'][-1]:.5f}")

    elif args.command == "predict":
        logging.basicConfig(level=logging.WARNING)
        score = predict_strength(args.password)
        label = classify_strength(args.password)
        print(f"Score: {score:.4f}  |  Strength: {label}")

    elif args.command == "benchmark":
        logging.basicConfig(level=logging.INFO, format="%(levelname)s | %(message)s")
        test_passwords = [
            ("password", "Common dictionary word"),
            ("123456", "Numeric sequence"),
            ("qwerty", "Keyboard walk"),
            ("aaaaaa", "Repeated character"),
            ("john1990", "Name + year"),
            ("Summer2023!", "Medium — word + year + symbol"),
            ("Tr0ub4dor&3", "Classic XKCD-style"),
            ("kj#9Fz!mQ2p@Lx8&", "Random strong"),
            ("H3!!o_W0r1d_#2024_$ecure", "Long with substitution"),
            ("", "Empty string"),
        ]
        print("\n" + "=" * 70)
        print(f"{'Password':<30} {'Score':>7}  {'Label':<8}  Description")
        print("=" * 70)
        for pw, desc in test_passwords:
            detail = predict_strength_detailed(pw)
            display = pw if len(pw) <= 28 else pw[:25] + "..."
            print(
                f"{display:<30} {detail['score']:>7.4f}  {detail['label']:<8}  {desc}"
            )
        print("=" * 70)

    else:
        parser.print_help()
        sys.exit(1)
