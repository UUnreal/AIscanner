# Laster ned ekte modeller fra Hugging Face til standardlageret (%USERPROFILE%\.cache\huggingface\hub),
# akkurat slik transformers/huggingface-cli gjør. Velger små vektfiler så mange modeller får plass.
# Skriver fasit (repo, filer, format, forfatter) som testlaben sjekker skanneren mot.
import json, os, sys
from huggingface_hub import HfApi, hf_hub_download

antall, maks_mb, ut = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
api = HfApi()
VEKTER = (".safetensors", ".gguf", ".onnx", ".bin", ".pt", ".pth", ".h5", ".keras", ".tflite", ".ckpt", ".msgpack")
# Ekte, mye brukte små modeller fra mange land, pluss mange små testmodeller (tiny-random) i ulike arkitekturer
kjente = ["HuggingFaceTB/SmolLM2-135M-Instruct", "HuggingFaceTB/SmolLM2-135M-Instruct-GGUF" , "Qwen/Qwen2.5-0.5B-Instruct-GGUF",
          "Qwen/Qwen3-0.6B-GGUF", "unsloth/gemma-3-270m-it-GGUF", "bartowski/SmolLM2-135M-Instruct-GGUF", "ggml-org/models",
          "Xenova/all-MiniLM-L6-v2", "sentence-transformers/all-MiniLM-L6-v2", "BAAI/bge-small-en-v1.5", "intfloat/e5-small-v2",
          "onnx-community/Qwen2.5-0.5B-Instruct", "microsoft/Phi-3-mini-4k-instruct-gguf", "TinyLlama/TinyLlama-1.1B-Chat-v1.0",
          "distilbert/distilbert-base-uncased", "google/flan-t5-small", "google-bert/bert-base-uncased", "openai-community/gpt2",
          "facebook/opt-125m", "EleutherAI/pythia-14m", "mistralai/Mistral-7B-Instruct-v0.3", "deepseek-ai/DeepSeek-R1-Distill-Qwen-1.5B",
          "openai/whisper-tiny", "Systran/faster-whisper-tiny", "google/mobilenet_v2_1.0_224", "timm/mobilenetv3_small_100.lamb_in1k",
          "stabilityai/stablelm-2-1_6b", "THUDM/glm-4-9b-chat", "01-ai/Yi-1.5-6B", "tiiuae/falcon-rw-1b", "CohereForAI/aya-23-8B",
          "nomic-ai/nomic-embed-text-v1.5", "jinaai/jina-embeddings-v2-small-en", "Helsinki-NLP/opus-mt-no-en", "NbAiLab/nb-bert-base"]
testmodeller = [m.id for m in api.list_models(author="hf-internal-testing", search="tiny-random", sort="downloads", limit=400)]
fasit, brukt = [], 0
for repo in kjente + testmodeller:
    if len(fasit) >= antall: break
    try:
        info = api.model_info(repo, files_metadata=True)
        filer = [s for s in info.siblings if s.rfilename.lower().endswith(VEKTER) and (s.size or 0) > 0]
        # Minste fil av hvert format, under grensen (store modeller gir bare små filer, ellers hoppes de over)
        valgt = {}
        for s in sorted(filer, key=lambda s: s.size):
            fmt = os.path.splitext(s.rfilename)[1].lower()
            if s.size <= maks_mb * 1024 * 1024 and fmt not in valgt: valgt[fmt] = s
        if not valgt: print(f"hopper over {repo}: ingen vektfil under {maks_mb} MB"); continue
        for s in valgt.values(): hf_hub_download(repo, s.rfilename)
        for navn in ("config.json", "README.md"):
            if any(x.rfilename == navn for x in info.siblings):
                try: hf_hub_download(repo, navn)
                except Exception: pass
        mb = sum(s.size for s in valgt.values()) / 1048576; brukt += mb
        fasit.append({"repo": repo, "forfatter": repo.split("/")[0], "filer": [s.rfilename for s in valgt.values()],
                      "formater": sorted(valgt), "mb": round(mb, 1), "lisens": (info.card_data or {}).get("license") if info.card_data else None,
                      "lastetNed": info.downloads, "flaggetAvHf": getattr(info, "security_repo_status", None)})
        print(f"{len(fasit):3} {repo}: {', '.join(sorted(valgt))} ({mb:.1f} MB)")
    except Exception as e:
        print(f"hopper over {repo}: {type(e).__name__}: {str(e)[:120]}")
json.dump(fasit, open(ut, "w"), indent=1, default=str)
print(f"Lastet ned {len(fasit)} modeller, {brukt:.0f} MB")
