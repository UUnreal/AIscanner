# Laster ned ekte modeller fra Hugging Face til standardlageret (%USERPROFILE%\.cache\huggingface\hub),
# akkurat slik transformers/huggingface-cli gjør. Velger små vektfiler så mange modeller får plass.
# Skriver fasit (repo, filer, format, forfatter) som testlaben sjekker skanneren mot.
import json, os, re, sys
from huggingface_hub import HfApi, hf_hub_download

antall, maks_mb, ut = int(sys.argv[1]), int(sys.argv[2]), sys.argv[3]
# Kinesiske modeller prioriteres (Jørund: kritiske). De får større filer (én liten kvantisering) innenfor et samlet budsjett.
# Russiske modeller (Jørund: samme behandling). Mange er finjusterte Qwen/Llama, så org og navn er beviset.
KINA_MB, KINA_BUDSJETT = 700, 5000
RUSSLAND = re.compile(r"gigachat|ai-sage|ai-forever|sberbank-ai|yandex|t-tech|t-lite|t-pro|cotype|mtsair|vikhr|ruadapt|refalmachine|rugpt|fred-t5", re.I)
RU_ORG = ["ai-sage", "ai-forever", "sberbank-ai", "yandex", "t-tech", "MTSAIR", "Vikhrmodels", "RefalMachine", "AnatoliiPotapov"]
CN_ORG = ["Qwen", "deepseek-ai", "THUDM", "zai-org", "01-ai", "baichuan-inc", "internlm", "openbmb", "MiniMaxAI", "moonshotai", "tencent", "baidu", "BAAI", "stepfun-ai", "Alibaba-NLP", "ByteDance-Seed", "inclusionAI", "rednote-hilab", "XiaomiMiMo"]
# Ekte tall: antall offentlige modeller per organisasjon, og hvor mange som bygger på dem (finjusteringer, kvantiseringer)
telling = {}
for land, orger in (("RU", RU_ORG), ("CN", CN_ORG)):
    for o in orger:
        try:
            mod = list(api.list_models(author=o, limit=5000))
            telling[o] = {"land": land, "modeller": len(mod), "nedlastinger30d": sum(m.downloads or 0 for m in mod)}
        except Exception as e: telling[o] = {"land": land, "feil": str(e)[:80]}
for navn, sok in (("RU-avledede (navn)", "vikhr"), ("RU-avledede (navn)", "gigachat"), ("RU-avledede (navn)", "yandexgpt"), ("CN-avledede (navn)", "qwen"), ("CN-avledede (navn)", "deepseek")):
    try: telling[f"søk:{sok}"] = {"land": navn[:2], "modeller": sum(1 for _ in api.list_models(search=sok, limit=200000))}
    except Exception as e: telling[f"søk:{sok}"] = {"land": navn[:2], "feil": str(e)[:80]}
json.dump(telling, open(os.path.join(os.path.dirname(ut), "opphav-telling.json"), "w"), indent=1)
print(json.dumps(telling, indent=1))
KINA = re.compile(r"qwen|deepseek|glm|chatglm|baichuan|internlm|minicpm|openbmb|yi-|01-ai|hunyuan|tencent|ernie|baidu|minimax|kimi|moonshot|stepfun|baai|thenlper|alibaba|thudm|zai-org|bge-|gte-|iic/|xverse|skywork|seed-", re.I)
api = HfApi()
VEKTER = (".safetensors", ".gguf", ".onnx", ".bin", ".pt", ".pth", ".h5", ".keras", ".tflite", ".ckpt", ".msgpack")
# Ekte, mye brukte små modeller fra mange land, pluss mange små testmodeller (tiny-random) i ulike arkitekturer
kina = ["Qwen/Qwen2.5-0.5B-Instruct-GGUF", "Qwen/Qwen3-0.6B-GGUF", "Qwen/Qwen2.5-Coder-0.5B-Instruct-GGUF", "Qwen/Qwen2.5-0.5B-Instruct",
        "bartowski/DeepSeek-R1-Distill-Qwen-1.5B-GGUF", "unsloth/DeepSeek-R1-Distill-Qwen-1.5B-GGUF", "BAAI/bge-small-zh-v1.5", "BAAI/bge-small-en-v1.5",
        "thenlper/gte-small", "Alibaba-NLP/gte-multilingual-base", "THUDM/glm-edge-1.5b-chat-gguf", "internlm/internlm2_5-1_8b-chat-gguf",
        "openbmb/MiniCPM-S-1B-sft-gguf", "Qwen/Qwen2.5-Math-1.5B-Instruct", "deepseek-ai/deepseek-coder-1.3b-instruct",
        "trl-internal-testing/tiny-Qwen2ForCausalLM-2.5", "trl-internal-testing/tiny-Qwen3ForCausalLM", "trl-internal-testing/tiny-DeepseekV3ForCausalLM",
        "trl-internal-testing/tiny-Qwen2VLForConditionalGeneration", "trl-internal-testing/tiny-GlmForCausalLM"]
kina += ["Vikhrmodels/Vikhr-Qwen-2.5-0.5b-Instruct", "Vikhrmodels/Vikhr-Qwen-2.5-1.5B-Instruct-GGUF", "Vikhrmodels/Vikhr-Llama-3.2-1B-Instruct",
         "MTSAIR/Cotype-Nano", "MTSAIR/Cotype-Nano-GGUF", "ai-forever/rugpt3small_based_on_gpt2", "ai-forever/FRED-T5-large",
         "cointegrated/rubert-tiny2", "deepvk/USER-base", "IlyaGusev/saiga_llama3_8b_gguf", "t-tech/T-lite-it-1.0-Q8_0-GGUF",
         "yandex/YandexGPT-5-Lite-8B-instruct-GGUF", "ai-sage/GigaChat-20B-A3B-instruct-v1.5-GGUF", "RefalMachine/ruadapt_qwen2.5_1.5B_ext_u48_full_lr5e4_peft_mlp_32_32_bs256"]
kina += [m.id for m in api.list_models(search="tiny-random", author="hf-internal-testing", limit=1000) if KINA.search(m.id)]
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
fasit, brukt, kina_brukt, sett = [], 0, 0, set()
for repo in kina + kjente + testmodeller:
    if len(fasit) >= antall: break
    if repo in sett: continue
    sett.add(repo)
    try:
        info = api.model_info(repo, files_metadata=True)
        filer = [s for s in info.siblings if s.rfilename.lower().endswith(VEKTER) and (s.size or 0) > 0]
        # Minste fil av hvert format, under grensen (store modeller gir bare små filer, ellers hoppes de over)
        valgt = {}
        for s in sorted(filer, key=lambda s: s.size):
            fmt = os.path.splitext(s.rfilename)[1].lower()
            grense = KINA_MB if repo in kina and kina_brukt < KINA_BUDSJETT else maks_mb
            if s.size <= grense * 1024 * 1024 and fmt not in valgt: valgt[fmt] = s
        if repo in kina and len(valgt) > 1: valgt = dict([min(valgt.items(), key=lambda x: x[1].size)])
        if not valgt: print(f"hopper over {repo}: ingen vektfil under {maks_mb} MB"); continue
        for s in valgt.values(): hf_hub_download(repo, s.rfilename)
        for navn in ("config.json", "README.md"):
            if any(x.rfilename == navn for x in info.siblings):
                try: hf_hub_download(repo, navn)
                except Exception: pass
        mb = sum(s.size for s in valgt.values()) / 1048576; brukt += mb
        if repo in kina: kina_brukt += mb
        arkitektur = ""
        try: arkitektur = ",".join(json.load(open(hf_hub_download(repo, "config.json"))).get("architectures") or [])
        except Exception: pass
        fasit.append({"repo": repo, "forfatter": repo.split("/")[0], "filer": [s.rfilename for s in valgt.values()],
                      "formater": sorted(valgt), "arkitektur": arkitektur, "kina": bool(KINA.search(repo + " " + arkitektur)) and not RUSSLAND.search(repo), "russland": bool(RUSSLAND.search(repo)), "mb": round(mb, 1), "lisens": (info.card_data or {}).get("license") if info.card_data else None,
                      "lastetNed": info.downloads, "flaggetAvHf": getattr(info, "security_repo_status", None)})
        print(f"{len(fasit):3} {repo}: {', '.join(sorted(valgt))} ({mb:.1f} MB)")
    except Exception as e:
        print(f"hopper over {repo}: {type(e).__name__}: {str(e)[:120]}")
json.dump(fasit, open(ut, "w"), indent=1, default=str)
print(f"Lastet ned {len(fasit)} modeller, {brukt:.0f} MB")
