# Standard library imports
import asyncio
import logging
import time
from typing import Any, Dict, List, Optional

# Third party imports
import torch
from transformers import (
    AutoModelForSequenceClassification,
    AutoTokenizer,
    TextClassificationPipeline,
)

logger = logging.getLogger(__name__)


class ClinicalAssertionModel:
    """Clinical Assertion Model for real-time inference"""

    def __init__(self) -> None:
        self.model: Optional[AutoModelForSequenceClassification] = None
        self.tokenizer: Optional[AutoTokenizer] = None
        self.pipeline: Optional[TextClassificationPipeline] = None
        self.model_name = "bvanaken/clinical-assertion-negation-bert"
        self.label_mapping = {
            "LABEL_0": "PRESENT",
            "LABEL_1": "ABSENT",
            "LABEL_2": "POSSIBLE",
        }
        self._loaded = False
        self.device = "cuda" if torch.cuda.is_available() else "cpu"

    async def load_model(self) -> None:
        """Load the clinical assertion model"""
        try:
            logger.info(f"Loading model {self.model_name} on device: {self.device}")
            start_time = time.time()

            self.tokenizer = AutoTokenizer.from_pretrained(self.model_name)
            self.model = AutoModelForSequenceClassification.from_pretrained(
                self.model_name
            ).to(self.device)

            if not torch.cuda.is_available():
                self.model = self.model.to(self.device)

            self.pipeline = TextClassificationPipeline(
                model=self.model,
                tokenizer=self.tokenizer,
                device=0 if torch.cuda.is_available() else -1,
                top_k=1,
            )

            self.model.eval()

            load_time = time.time() - start_time
            logger.info(f"Model loaded successfully in {load_time:.2f} seconds")

            self._loaded = True

        except Exception as e:
            logger.error(f"Failed to load model: {str(e)}")
            raise RuntimeError(f"Model loading failed: {str(e)}")

    def is_loaded(self) -> bool:
        """Check if model is loaded"""
        return self._loaded and self.model is not None

    async def predict(self, sentence: str) -> Dict[str, Any]:
        """Predict assertion status for a single sentence"""
        if not self.is_loaded():
            raise RuntimeError("Model is not loaded")

        try:
            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(None, self._predict_sync, sentence)
            return result
        except Exception as e:
            logger.error(f"Prediction error: {str(e)}")
            raise RuntimeError(f"Prediction failed: {str(e)}")

    def _predict_sync(self, sentence: str) -> Dict[str, Any]:
        """Synchronous prediction method"""
        assert self.pipeline is not None, "Pipeline not initialized"
        with torch.no_grad():
            result = self.pipeline(sentence, truncation=True, max_length=512)

        # debug
        if isinstance(result, list):
            if len(result) > 0 and isinstance(result[0], list):
                result = result[0][0]
            else:
                result = result[0]
        else:
            raise RuntimeError(
                f"Unexpected result type: {type(result)}, value: {result}"
            )

        label = result["label"]
        score = result["score"]
        readable_label = self.label_mapping.get(label, label)

        return {"label": readable_label, "score": float(score)}

    async def predict_batch(self, sentences: List[str]) -> List[Dict[str, Any]]:
        """Predict assertion status for multiple sentences"""
        if not self.is_loaded():
            raise RuntimeError("Model is not loaded")

        try:
            loop = asyncio.get_event_loop()
            results = await loop.run_in_executor(
                None, self._predict_batch_sync, sentences
            )
            return results
        except Exception as e:
            logger.error(f"Batch prediction error: {str(e)}")
            raise RuntimeError(f"Batch prediction failed: {str(e)}")

    def _predict_batch_sync(self, sentences: List[str]) -> List[Dict[str, Any]]:
        """Synchronous batch prediction"""
        assert self.pipeline is not None, "Pipeline not initialized"
        with torch.no_grad():
            results = self.pipeline(
                sentences, batch_size=8, truncation=True, max_length=512
            )

        processed_results = []
        for result in results:
            if isinstance(result, list):
                result = result[0]
            label = result["label"]
            score = result["score"]
            readable_label = self.label_mapping.get(label, label)
            processed_results.append({"label": readable_label, "score": float(score)})

        return processed_results

    def get_model_info(self) -> Dict[str, Any]:
        """Get model information"""
        return {
            "model_name": self.model_name,
            "device": self.device,
            "loaded": self._loaded,
            "labels": list(self.label_mapping.values()),
            "cuda_available": torch.cuda.is_available(),
        }
