import os
import traceback
from transformers import pipeline

from app.config import load_config


def load_model():
    try:
        config = load_config()
        hf_config = config.get("huggingface", {})
        model_config = hf_config.get("model", {})

        model_name = model_config.get("name", "bigcode/starpii")
        hf_token = hf_config.get("token") or os.environ.get("HUGGINGFACEHUB_API_TOKEN")

        print(f"Loading model: {model_name}")

        if hf_token:
            print("Using Hugging Face token")
            return pipeline(
                "ner",
                model=model_name,
                aggregation_strategy="simple",
                token=hf_token,
            )

        print("Loading model WITHOUT authentication")
        return pipeline("ner", model=model_name, aggregation_strategy="simple")

    except Exception as e:
        print(f"❌ Error loading NER model: {e}")
        traceback.print_exc()
        return None