# Third party imports
import pytest

from app.utils import (
    apply_hybrid_pipeline,
    detect_conditional_phrases,
    detect_uncertainty_phrases,
)


class TestHealthEndpoint:
    def test_health_check_success(self, client, mock_model):
        response = client.get("/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] in ["healthy", "unhealthy"]


class TestPredictionEndpoint:
    def test_predict_success(self, client, mock_model):
        response = client.post(
            "/predict", json={"sentence": "The patient denies chest pain."}
        )
        assert response.status_code == 200
        data = response.json()
        assert "label" in data
        assert "score" in data

    def test_predict_empty_sentence(self, client, mock_model):
        response = client.post("/predict", json={"sentence": ""})
        assert response.status_code == 422

    @pytest.mark.parametrize(
        "sentence",
        [
            "The patient denies chest pain.",
            "He has a history of hypertension.",
            "No signs of pneumonia were observed.",
        ],
    )
    def test_predict_various_sentences(self, client, mock_model, sentence):
        response = client.post("/predict", json={"sentence": sentence})
        assert response.status_code == 200
        data = response.json()
        assert isinstance(data["score"], float)
        assert 0.0 <= data["score"] <= 1.0


class TestBatchPredictionEndpoint:
    def test_batch_predict_success(self, client, mock_model):
        mock_model.predict_batch.return_value = [
            {"label": "ABSENT", "score": 0.9842},
            {"label": "PRESENT", "score": 0.8976},
        ]

        response = client.post(
            "/predict/batch",
            json={"sentences": ["Sentence 1", "Sentence 2"]},
        )
        assert response.status_code == 200
        data = response.json()
        assert len(data["predictions"]) == 2

    def test_batch_predict_empty_list(self, client, mock_model):
        response = client.post("/predict/batch", json={"sentences": []})
        assert response.status_code == 422


class TestRootEndpoint:
    def test_root_endpoint(self, client):
        response = client.get("/")
        assert response.status_code == 200
        data = response.json()
        assert data["name"] == "Clinical BERT Assertion API"
        assert "endpoints" in data


class TestHybridPipeline:
    def test_apply_hybrid_pipeline_conditional(self):
        """Test conditional phrase detection and override"""
        predictions = [{"label": "PRESENT", "score": 0.85}]
        sentences = ["If symptoms persist, call doctor."]

        result = apply_hybrid_pipeline(predictions, sentences)

        assert len(result) == 1
        assert result[0]["label"] == "CONDITIONAL"
        assert result[0]["model_label"] == "PRESENT"
        assert result[0]["rule_applied"] == "conditional_trigger"

    def test_apply_hybrid_pipeline_uncertainty(self):
        """Test uncertainty phrase detection and POSSIBLE override"""
        predictions = [{"label": "PRESENT", "score": 0.90}]
        sentences = ["The patient likely has pneumonia."]

        result = apply_hybrid_pipeline(predictions, sentences)

        assert len(result) == 1
        assert result[0]["label"] == "POSSIBLE"
        assert result[0]["model_label"] == "PRESENT"
        assert result[0]["rule_applied"] == "uncertainty_strengthening"

    def test_apply_hybrid_pipeline_no_rule(self):
        """Test when no rules apply"""
        predictions = [{"label": "ABSENT", "score": 0.95}]
        sentences = ["The patient denies pain."]

        result = apply_hybrid_pipeline(predictions, sentences)

        assert len(result) == 1
        assert result[0]["label"] == "ABSENT"
        assert result[0]["model_label"] == "ABSENT"
        assert result[0]["rule_applied"] is None

    def test_apply_hybrid_pipeline_multiple_sentences(self):
        """Test hybrid pipeline with multiple sentences"""
        predictions = [
            {"label": "PRESENT", "score": 0.85},
            {"label": "PRESENT", "score": 0.90},
            {"label": "ABSENT", "score": 0.95},
        ]
        sentences = [
            "If symptoms persist, call doctor.",
            "The patient likely has pneumonia.",
            "The patient denies pain.",
        ]

        result = apply_hybrid_pipeline(predictions, sentences)

        assert len(result) == 3
        assert result[0]["label"] == "CONDITIONAL"
        assert result[1]["label"] == "POSSIBLE"
        assert result[2]["label"] == "ABSENT"


class TestUtilityFunctions:
    def test_detect_conditional_phrases_positive(self):
        """Test conditional phrase detection - positive cases"""
        assert detect_conditional_phrases("If symptoms worsen, call doctor.") is True
        assert detect_conditional_phrases("Should we increase dosage?") is True
        assert detect_conditional_phrases("Unless contraindicated, proceed.") is True
        assert detect_conditional_phrases("When fever spikes, administer meds.") is True

    def test_detect_conditional_phrases_negative(self):
        """Test conditional phrase detection - negative cases"""
        assert detect_conditional_phrases("The patient has fever.") is False
        assert detect_conditional_phrases("Administer medication.") is False

    def test_detect_uncertainty_phrases_positive(self):
        """Test uncertainty phrase detection - positive cases"""
        assert detect_uncertainty_phrases("The patient may have pneumonia.") is True
        assert detect_uncertainty_phrases("Suspect infection present.") is True
        assert detect_uncertainty_phrases("Appears to be stable.") is True
        assert detect_uncertainty_phrases("Potential complications noted.") is True
        assert detect_uncertainty_phrases("Probably needs antibiotics.") is True

    def test_detect_uncertainty_phrases_negative(self):
        """Test uncertainty phrase detection - negative cases"""
        assert detect_uncertainty_phrases("The patient has pneumonia.") is False
        assert detect_uncertainty_phrases("Administer antibiotics.") is False


class TestEnhancedPredictionEndpoints:
    def test_predict_with_hybrid_pipeline(self, client, mock_model):
        """Test that prediction endpoint applies hybrid rules"""
        # Mock model to return PRESENT for conditional sentence
        mock_model.predict.return_value = {"label": "PRESENT", "score": 0.85}

        response = client.post(
            "/predict",
            json={"sentence": "If symptoms persist, call doctor."},
        )
        assert response.status_code == 200
        data = response.json()
        assert data["label"] == "CONDITIONAL"
        assert data["model_label"] == "PRESENT"
        assert data["rule_applied"] == "conditional_trigger"

    def test_batch_predict_with_hybrid_pipeline(self, client, mock_model):
        """Test that batch prediction applies hybrid rules"""
        mock_model.predict_batch.return_value = [
            {"label": "PRESENT", "score": 0.85},  # Will become CONDITIONAL
            {"label": "PRESENT", "score": 0.90},  # Will become POSSIBLE
        ]

        response = client.post(
            "/predict/batch",
            json={
                "sentences": [
                    "If symptoms persist, call doctor.",
                    "The patient likely has pneumonia.",
                ]
            },
        )
        assert response.status_code == 200
        data = response.json()
        assert len(data["predictions"]) == 2
        assert data["predictions"][0]["label"] == "CONDITIONAL"
        assert data["predictions"][1]["label"] == "POSSIBLE"
