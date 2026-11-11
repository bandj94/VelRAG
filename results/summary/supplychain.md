| ID | Tampering | Expected catch | Caught | Control that caught it | Error shown |
|---|---|---|---|---|---|
| S1 | Flip one byte in a copy of the classifier's weights | hash check | yes | hash check | [hash check] classifier_fallback: sha256 mismatch for model.safetensors (expected 6521cb8d0ac0…, got 1248ee495951…) |
| S2a | Temporary app.yaml copy points Model A at llama3.1:8b; pin not updated | digest check | yes | digest check | [digest check] model A (llama3.1:8b) digest 46e0c10c039e… does not match the pin 500a1f067a9f… (pinned for qwen3:8b) |
| S2b | Different revision of the embedding model in scratch/hf-cache | revision check | yes | revision check | [revision check] embeddings: pinned revision 5c38ec7c405ec4b44b94cc5a9bb96e735b38267a of BAAI/bge-small-en-v1.5 not found under .\scratch\hf-cache (present: ['35baf7769a878409ff46ec41bf2e8f8ae9cc335a']) |
| S3 | Pickle-format file (plain data only) where weights are expected | safe-loading check | yes | safe-loading check | [safe-loading check] embeddings: model.safetensors is not a valid safetensors file (wrong format or header) |
| S4 | Temporary repo copy: change idna's hash in uv.lock; locked install, empty cache | locked install | yes | locked install (hash verification) | cause: Hash mismatch for `idna==3.20` |

The real gap: pinning cannot catch a model that was already malicious when it was pinned.
