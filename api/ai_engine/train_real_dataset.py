from __future__ import annotations

import argparse
import os
import random
from collections import Counter
from pathlib import Path
from typing import List, Tuple

import torch
import torch.nn as nn
from torch.utils.data import DataLoader, Dataset, random_split
from tqdm import tqdm


PROJECT_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_DATASET_DIR = PROJECT_ROOT / "dataset" / "strong-passwords-in-rockyou2024-txt"
DEFAULT_SAVE_PATH = PROJECT_ROOT / "api" / "ai_engine" / "weights" / "password_rnn.pt"

PAD_IDX = 0
UNK_IDX = 1
VOCAB_CHARS = [chr(i) for i in range(32, 127)]  # printable ASCII
STOI = {ch: i + 2 for i, ch in enumerate(VOCAB_CHARS)}
VOCAB_SIZE = len(STOI) + 2


def clip01(x: float) -> float:
    return max(0.0, min(1.0, float(x)))


def count_lines(path: Path) -> int:
    with path.open("rb") as fh:
        return sum(1 for _ in fh)


def collect_dataset_files(path: Path) -> List[Path]:
    if path.is_file():
        return [path]

    if not path.is_dir():
        raise FileNotFoundError(f"Dataset not found: {path}")

    files = [
        p
        for p in sorted(path.rglob("*"))
        if p.is_file() and p.suffix.lower() in {".txt", ".log", ".list"}
    ]
    if not files:
        raise ValueError(f"No text dataset files found under: {path}")
    return files


def heuristic_label(password: str) -> float:
    # Higher label => easier to predict.
    if not password:
        return 1.0

    length = len(password)
    length_risk = 1.0 - min(length / 16.0, 1.0)

    has_lower = any("a" <= c <= "z" for c in password)
    has_upper = any("A" <= c <= "Z" for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_symbol = any(not c.isalnum() for c in password)
    class_count = int(has_lower) + int(has_upper) + int(has_digit) + int(has_symbol)
    class_risk = 1.0 - (class_count / 4.0)

    rep_ratio = max(Counter(password).values()) / max(length, 1)

    return clip01(0.45 * length_risk + 0.35 * class_risk + 0.20 * rep_ratio)


def reservoir_sample_pairs(files: List[Path], max_samples: int, seed: int) -> List[Tuple[str, float]]:
    rng = random.Random(seed)
    reservoir: List[Tuple[str, float]] = []
    seen_valid = 0

    for file_path in files:
        total = count_lines(file_path)
        with file_path.open("r", encoding="utf-8", errors="ignore") as fh:
            for line in tqdm(fh, total=total, desc=f"Reading {file_path.name}", unit="line"):
                pw = line.strip("\r\n")
                if not pw:
                    continue

                item = (pw, heuristic_label(pw))
                seen_valid += 1

                if len(reservoir) < max_samples:
                    reservoir.append(item)
                else:
                    j = rng.randrange(seen_valid)
                    if j < max_samples:
                        reservoir[j] = item

    if not reservoir:
        raise ValueError("No valid passwords found in dataset.")

    rng.shuffle(reservoir)
    return reservoir


def encode_password(password: str, max_len: int) -> List[int]:
    ids = [STOI.get(ch, UNK_IDX) for ch in password[:max_len]]
    return ids if ids else [UNK_IDX]


class PasswordPairsDataset(Dataset):
    def __init__(self, pairs: List[Tuple[str, float]], max_len: int) -> None:
        self.pairs = pairs
        self.max_len = max_len

    def __len__(self) -> int:
        return len(self.pairs)

    def __getitem__(self, idx: int) -> Tuple[List[int], float]:
        pw, label = self.pairs[idx]
        return encode_password(pw, self.max_len), float(label)


def collate_batch(batch: List[Tuple[List[int], float]]) -> Tuple[torch.Tensor, torch.Tensor, torch.Tensor]:
    seqs, labels = zip(*batch)
    lengths = torch.tensor([len(s) for s in seqs], dtype=torch.long)
    max_len = int(lengths.max().item())

    x = torch.full((len(seqs), max_len), PAD_IDX, dtype=torch.long)
    for i, s in enumerate(seqs):
        x[i, : len(s)] = torch.tensor(s, dtype=torch.long)

    y = torch.tensor(labels, dtype=torch.float32)
    return x, lengths, y


class PasswordRNN(nn.Module):
    def __init__(
        self,
        vocab_size: int,
        embed_dim: int = 64,
        hidden_dim: int = 128,
        num_layers: int = 2,
        dropout: float = 0.2,
    ) -> None:
        super().__init__()
        self.embedding = nn.Embedding(vocab_size, embed_dim, padding_idx=PAD_IDX)
        self.rnn = nn.LSTM(
            embed_dim,
            hidden_dim,
            num_layers=num_layers,
            batch_first=True,
            dropout=dropout if num_layers > 1 else 0.0,
            bidirectional=True,
        )
        self.head = nn.Sequential(
            nn.Linear(hidden_dim * 2, hidden_dim),
            nn.ReLU(),
            nn.Dropout(dropout),
            nn.Linear(hidden_dim, 1),
            nn.Sigmoid(),
        )

    def forward(self, x: torch.Tensor, lengths: torch.Tensor) -> torch.Tensor:
        emb = self.embedding(x)
        packed = nn.utils.rnn.pack_padded_sequence(
            emb,
            lengths.cpu(),
            batch_first=True,
            enforce_sorted=False,
        )
        _, (h_n, _) = self.rnn(packed)
        h = torch.cat((h_n[-2], h_n[-1]), dim=1)  # bidirectional last layer
        return self.head(h).squeeze(1)


class PasswordTransformer(nn.Module):
    def __init__(
        self,
        vocab_size: int,
        max_seq_len: int = 128,
        d_model: int = 128,
        nhead: int = 4,
        num_layers: int = 2,
        dropout: float = 0.1,
    ) -> None:
        super().__init__()
        if d_model % nhead != 0:
            raise ValueError("Transformer d_model must be divisible by nhead.")

        self.max_seq_len = max_seq_len
        self.embedding = nn.Embedding(vocab_size, d_model, padding_idx=PAD_IDX)
        self.pos_embedding = nn.Embedding(max_seq_len, d_model)
        encoder_layer = nn.TransformerEncoderLayer(
            d_model=d_model,
            nhead=nhead,
            dim_feedforward=d_model * 4,
            dropout=dropout,
            activation="gelu",
            batch_first=True,
        )
        self.encoder = nn.TransformerEncoder(encoder_layer, num_layers=num_layers)
        self.norm = nn.LayerNorm(d_model)
        self.head = nn.Sequential(
            nn.Linear(d_model, d_model),
            nn.GELU(),
            nn.Dropout(dropout),
            nn.Linear(d_model, 1),
            nn.Sigmoid(),
        )

    def forward(self, x: torch.Tensor, lengths: torch.Tensor) -> torch.Tensor:
        del lengths  # Transformer uses padding mask directly.

        if x.size(1) > self.max_seq_len:
            x = x[:, : self.max_seq_len]

        batch_size, seq_len = x.shape
        positions = torch.arange(seq_len, device=x.device).unsqueeze(0).expand(batch_size, seq_len)

        h = self.embedding(x) + self.pos_embedding(positions)
        pad_mask = x.eq(PAD_IDX)
        enc = self.encoder(h, src_key_padding_mask=pad_mask)
        enc = self.norm(enc)

        valid_mask = (~pad_mask).unsqueeze(-1)
        summed = (enc * valid_mask).sum(dim=1)
        counts = valid_mask.sum(dim=1).clamp(min=1)
        pooled = summed / counts
        return self.head(pooled).squeeze(1)


def run_epoch(
    model: nn.Module,
    loader: DataLoader,
    device: torch.device,
    criterion: nn.Module,
    optimizer: torch.optim.Optimizer | None,
    epoch: int,
    epochs: int,
    phase: str,
) -> float:
    is_train = optimizer is not None
    model.train(is_train)
    total_loss = 0.0
    steps = 0
    non_blocking = device.type == "cuda"

    pbar = tqdm(loader, desc=f"Epoch {epoch}/{epochs} [{phase}]", unit="batch")
    for x, lengths, y in pbar:
        x = x.to(device, non_blocking=non_blocking)
        lengths = lengths.to(device, non_blocking=non_blocking)
        y = y.to(device, non_blocking=non_blocking)

        preds = model(x, lengths)
        loss = criterion(preds, y)

        if is_train:
            optimizer.zero_grad()
            loss.backward()
            nn.utils.clip_grad_norm_(model.parameters(), max_norm=5.0)
            optimizer.step()

        total_loss += loss.item()
        steps += 1
        pbar.set_postfix(loss=f"{total_loss / steps:.5f}")

    return total_loss / max(1, steps)


def resolve_device_name(device_arg: str) -> str:
    if device_arg == "auto":
        return "cuda" if torch.cuda.is_available() else "cpu"
    return device_arg


def main() -> int:
    parser = argparse.ArgumentParser(description="Simple password model training from scratch.")
    parser.add_argument("--dataset", default=str(DEFAULT_DATASET_DIR), help="Dataset file or folder.")
    parser.add_argument("--max-samples", type=int, default=250000, help="Max sampled rows for training.")
    parser.add_argument("--epochs", type=int, default=10)
    parser.add_argument("--batch-size", type=int, default=256)
    parser.add_argument("--lr", type=float, default=1e-3)
    parser.add_argument("--max-seq-len", type=int, default=128)
    parser.add_argument("--val-split", type=float, default=0.15)
    parser.add_argument("--num-workers", type=int, default=-1, help="-1 auto")
    parser.add_argument("--val-num-workers", type=int, default=-1, help="-1 auto")
    parser.add_argument(
        "--arch",
        choices=["bilstm", "transformer"],
        default="bilstm",
        help="Model architecture to train.",
    )
    parser.add_argument("--tf-d-model", type=int, default=128, help="Transformer embedding dimension.")
    parser.add_argument("--tf-heads", type=int, default=4, help="Transformer attention heads.")
    parser.add_argument("--tf-layers", type=int, default=2, help="Transformer encoder layers.")
    parser.add_argument("--tf-dropout", type=float, default=0.1, help="Transformer dropout.")
    parser.add_argument("--device", choices=["auto", "cpu", "cuda"], default="auto")
    parser.add_argument("--save-path", default=str(DEFAULT_SAVE_PATH))
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    random.seed(args.seed)
    torch.manual_seed(args.seed)

    device_name = resolve_device_name(args.device)
    device = torch.device(device_name)
    if device.type == "cuda":
        torch.backends.cudnn.benchmark = True
        print(f"Using GPU: {torch.cuda.get_device_name(0)}")

    dataset_path = Path(args.dataset).expanduser().resolve()
    files = collect_dataset_files(dataset_path)
    print(f"Found {len(files)} dataset file(s)")

    pairs = reservoir_sample_pairs(files, max_samples=args.max_samples, seed=args.seed)
    print(f"Prepared {len(pairs)} samples")

    ds = PasswordPairsDataset(pairs, max_len=args.max_seq_len)
    val_size = max(1, int(len(ds) * args.val_split))
    train_size = len(ds) - val_size
    if train_size <= 0:
        raise ValueError("Not enough samples after split.")

    train_ds, val_ds = random_split(ds, [train_size, val_size], generator=torch.Generator().manual_seed(args.seed))

    if args.num_workers < 0:
        train_workers = 4 if device.type == "cuda" else 0
    else:
        train_workers = max(0, int(args.num_workers))

    if args.val_num_workers == -1:
        # Windows + CUDA safety to avoid paging-file worker crashes.
        val_workers = 0 if (os.name == "nt" and device.type == "cuda" and train_workers > 0) else train_workers
    else:
        val_workers = max(0, int(args.val_num_workers))

    train_loader_kwargs = {
        "batch_size": args.batch_size,
        "shuffle": True,
        "collate_fn": collate_batch,
        "num_workers": train_workers,
        "pin_memory": device.type == "cuda",
        "persistent_workers": train_workers > 0,
    }
    if train_workers > 0:
        train_loader_kwargs["prefetch_factor"] = 4

    val_loader_kwargs = {
        "batch_size": args.batch_size,
        "shuffle": False,
        "collate_fn": collate_batch,
        "num_workers": val_workers,
        "pin_memory": device.type == "cuda",
        "persistent_workers": False,
    }
    if val_workers > 0:
        val_loader_kwargs["prefetch_factor"] = 4

    train_loader = DataLoader(train_ds, **train_loader_kwargs)
    val_loader = DataLoader(val_ds, **val_loader_kwargs)

    if args.arch == "transformer":
        model = PasswordTransformer(
            vocab_size=VOCAB_SIZE,
            max_seq_len=args.max_seq_len,
            d_model=args.tf_d_model,
            nhead=args.tf_heads,
            num_layers=args.tf_layers,
            dropout=args.tf_dropout,
        ).to(device)
    else:
        model = PasswordRNN(vocab_size=VOCAB_SIZE).to(device)

    print(f"Using architecture: {args.arch}")
    criterion = nn.BCELoss()
    optimizer = torch.optim.Adam(model.parameters(), lr=args.lr)

    for epoch in range(1, args.epochs + 1):
        train_loss = run_epoch(model, train_loader, device, criterion, optimizer, epoch, args.epochs, "train")
        with torch.no_grad():
            val_loss = run_epoch(model, val_loader, device, criterion, None, epoch, args.epochs, "val")
        print(f"Epoch {epoch:02d}/{args.epochs:02d} | train_loss={train_loss:.5f} | val_loss={val_loss:.5f}")

    save_path = Path(args.save_path).expanduser().resolve()
    save_path.parent.mkdir(parents=True, exist_ok=True)
    torch.save(model.state_dict(), save_path)

    print("\nTraining completed.")
    print(f"Weights saved to: {save_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
