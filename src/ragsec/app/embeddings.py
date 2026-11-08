"""Embeddings: BAAI/bge-small-en-v1.5 on CPU (spec §4).

Embeddings are always computed here and passed to Chroma explicitly; Chroma's
default embedding function (which downloads its own model) is never used.
Weights load only from .safetensors with trust_remote_code=False (§8.9); the
integrity check verifies the directory before this class is constructed.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Protocol


class Embedder(Protocol):
    dim: int

    def embed_documents(self, texts: list[str]) -> list[list[float]]: ...

    def embed_query(self, text: str) -> list[float]: ...

    def count_tokens(self, text: str) -> int: ...


class BgeEmbedder:
    def __init__(
        self,
        model_dir: Path,
        *,
        device: str = "cpu",
        batch_size: int = 16,
        max_tokens: int = 512,
        query_instruction: str = "",
    ) -> None:
        import torch
        from transformers import AutoModel, AutoTokenizer

        self._torch = torch
        self.tokenizer: Any = AutoTokenizer.from_pretrained(str(model_dir), local_files_only=True)
        self.model: Any = AutoModel.from_pretrained(
            str(model_dir),
            use_safetensors=True,
            trust_remote_code=False,
            local_files_only=True,
        )
        self.model.eval()
        self.model.to(device)
        self.device = device
        self.batch_size = batch_size
        self.max_tokens = max_tokens
        self.query_instruction = query_instruction
        self.dim = int(self.model.config.hidden_size)

    def count_tokens(self, text: str) -> int:
        """Tokens including [CLS] and [SEP], as the model sees them."""
        return len(self.tokenizer(text, add_special_tokens=True, truncation=False)["input_ids"])

    def _encode(self, texts: list[str]) -> list[list[float]]:
        torch = self._torch
        out: list[list[float]] = []
        with torch.no_grad():
            for i in range(0, len(texts), self.batch_size):
                batch = texts[i : i + self.batch_size]
                enc = self.tokenizer(
                    batch,
                    padding=True,
                    truncation=True,
                    max_length=self.max_tokens,
                    return_tensors="pt",
                ).to(self.device)
                hidden = self.model(**enc).last_hidden_state
                cls = hidden[:, 0]  # BGE uses the [CLS] vector
                cls = torch.nn.functional.normalize(cls, p=2, dim=1)
                out.extend(cls.cpu().tolist())
        return out

    def embed_documents(self, texts: list[str]) -> list[list[float]]:
        return self._encode(texts)

    def embed_query(self, text: str) -> list[float]:
        return self._encode([self.query_instruction + text])[0]
