# Standard library imports
from unittest.mock import AsyncMock, Mock, patch

# Third party imports
import pytest

from app.model import ClinicalAssertionModel


class TestClinicalAssertionModel:
    """Test Clinical Assertion Model functionality"""

    @pytest.fixture
    def model(self):
        """Create a model instance for testing"""
        return ClinicalAssertionModel()

    def test_init(self, model):
        """Test model initialization"""
        assert model.model is None
        assert model.tokenizer is None
        assert model.pipeline is None
        assert model.model_name == "bvanaken/clinical-assertion-negation-bert"
        assert model.label_mapping == {
            "LABEL_0": "PRESENT",
            "LABEL_1": "ABSENT",
            "LABEL_2": "POSSIBLE",
        }
        assert model._loaded is False
        assert model.device in ["cuda", "cpu"]

    def test_is_loaded_not_loaded(self, model):
        """Test is_loaded when model is not loaded"""
        assert model.is_loaded() is False

    def test_is_loaded_after_init(self, model):
        """Test is_loaded after manual setup"""
        model._loaded = True
        model.model = Mock()
        assert model.is_loaded() is True

    def test_is_loaded_no_model(self, model):
        """Test is_loaded when loaded flag is set but no model"""
        model._loaded = True
        assert model.is_loaded() is False

    @patch("torch.cuda.is_available")
    def test_device_cuda_available(self, mock_cuda, model):
        """Test device selection when CUDA is available"""
        mock_cuda.return_value = True
        model.__init__()
        assert model.device == "cuda"

    @patch("torch.cuda.is_available")
    def test_device_cuda_not_available(self, mock_cuda, model):
        """Test device selection when CUDA is not available"""
        mock_cuda.return_value = False
        model.__init__()
        assert model.device == "cpu"
    @pytest.mark.asyncio
    @patch("app.model.AutoTokenizer.from_pretrained")
    @patch("app.model.AutoModelForSequenceClassification.from_pretrained")
    @patch("app.model.TextClassificationPipeline")
    @patch("torch.cuda.is_available")
    async def test_load_model_success(
        self, mock_cuda, mock_pipeline, mock_model_class, mock_tokenizer, model
    ):
        """Test successful model loading"""
        mock_cuda.return_value = False

        # Mock the model and tokenizer
        mock_model_instance = Mock()
        mock_model_class.return_value = mock_model_instance
        mock_tokenizer_instance = Mock()
        mock_tokenizer.return_value = mock_tokenizer_instance
        mock_pipeline_instance = Mock()
        mock_pipeline.return_value = mock_pipeline_instance

        await model.load_model()

        assert model.tokenizer == mock_tokenizer_instance
        assert model.model == mock_model_instance
        assert model.pipeline == mock_pipeline_instance
        assert model._loaded is True

        # Verify method calls
        mock_tokenizer.assert_called_once_with(model.model_name)
        mock_model_class.assert_called_once_with(model.model_name)
        mock_model_instance.to.assert_called_with("cpu")
        mock_pipeline.assert_called_once()
    @pytest.mark.asyncio
    @patch("app.model.AutoTokenizer.from_pretrained")
    async def test_load_model_tokenizer_failure(self, mock_tokenizer, model):
        """Test model loading failure during tokenizer loading"""
        mock_tokenizer.side_effect = Exception("Tokenizer error")

        with pytest.raises(RuntimeError, match="Model loading failed"):
            await model.load_model()

        assert model._loaded is False
    @pytest.mark.asyncio
    @patch("app.model.AutoTokenizer.from_pretrained")
    @patch("app.model.AutoModelForSequenceClassification.from_pretrained")
    async def test_load_model_model_failure(
        self, mock_model_class, mock_tokenizer, model
    ):
        """Test model loading failure during model loading"""
        mock_tokenizer.return_value = Mock()
        mock_model_class.side_effect = Exception("Model error")

        with pytest.raises(RuntimeError, match="Model loading failed"):
            await model.load_model()

        assert model._loaded is False

    async def test_predict_not_loaded(self, model):
        """Test prediction when model is not loaded"""
        with pytest.raises(RuntimeError, match="Model is not loaded"):
            await model.predict("test sentence")

    async def test_predict_batch_not_loaded(self, model):
        """Test batch prediction when model is not loaded"""
        with pytest.raises(RuntimeError, match="Model is not loaded"):
            await model.predict_batch(["test sentence"])
    @pytest.mark.asyncio
    @patch("asyncio.get_event_loop")
    async def test_predict_success(self, mock_loop, model):
        """Test successful prediction"""
        # Setup model as loaded
        model._loaded = True
        model.model = Mock()
        model.pipeline = Mock()

        # Mock the pipeline result
        mock_result = {"label": "LABEL_0", "score": 0.95}
        model.pipeline.return_value = [mock_result]

        # Mock asyncio loop
        mock_loop_instance = Mock()
        mock_loop.return_value = mock_loop_instance
        mock_loop_instance.run_in_executor = AsyncMock(return_value=mock_result)

        result = await model.predict("test sentence")

        assert result == {"label": "PRESENT", "score": 0.95}
        mock_loop_instance.run_in_executor.assert_called_once()
    @pytest.mark.asyncio
    @patch("asyncio.get_event_loop")
    async def test_predict_pipeline_error(self, mock_loop, model):
        """Test prediction with pipeline error"""
        # Setup model as loaded
        model._loaded = True
        model.model = Mock()
        model.pipeline = Mock()

        # Mock asyncio loop to raise error
        mock_loop_instance = Mock()
        mock_loop.return_value = mock_loop_instance
        mock_loop_instance.run_in_executor = AsyncMock(
            side_effect=Exception("Pipeline error")
        )

        with pytest.raises(RuntimeError, match="Prediction failed"):
            await model.predict("test sentence")

    def test_predict_sync_success(self, model):
        """Test synchronous prediction success"""
        # Setup pipeline
        model.pipeline = Mock()
        mock_result = {"label": "LABEL_1", "score": 0.87}
        model.pipeline.return_value = [mock_result]

        result = model._predict_sync("test sentence")

        assert result == {"label": "ABSENT", "score": 0.87}
        model.pipeline.assert_called_once_with(
            "test sentence", truncation=True, max_length=512
        )

    def test_predict_sync_list_result(self, model):
        """Test synchronous prediction with list result"""
        # Setup pipeline
        model.pipeline = Mock()
        mock_result = {"label": "LABEL_2", "score": 0.76}
        model.pipeline.return_value = [mock_result]

        result = model._predict_sync("test sentence")

        assert result == {"label": "POSSIBLE", "score": 0.76}

    def test_predict_sync_nested_list_result(self, model):
        """Test synchronous prediction with nested list result"""
        # Setup pipeline
        model.pipeline = Mock()
        mock_result = {"label": "LABEL_0", "score": 0.92}
        model.pipeline.return_value = [[mock_result]]

        result = model._predict_sync("test sentence")

        assert result == {"label": "PRESENT", "score": 0.92}

    def test_predict_sync_unexpected_result_type(self, model):
        """Test synchronous prediction with unexpected result type"""
        # Setup pipeline
        model.pipeline = Mock()
        model.pipeline.return_value = "unexpected"

        with pytest.raises(RuntimeError, match="Unexpected result type"):
            model._predict_sync("test sentence")
    @pytest.mark.asyncio
    @patch("asyncio.get_event_loop")
    async def test_predict_batch_success(self, mock_loop, model):
        """Test successful batch prediction"""
        # Setup model as loaded
        model._loaded = True
        model.model = Mock()
        model.pipeline = Mock()

        # Mock batch results
        mock_results = [
            [{"label": "LABEL_0", "score": 0.95}],
            [{"label": "LABEL_1", "score": 0.87}],
        ]
        model.pipeline.return_value = mock_results

        # Mock asyncio loop
        mock_loop_instance = Mock()
        mock_loop.return_value = mock_loop_instance
        mock_loop_instance.run_in_executor = AsyncMock(return_value=mock_results)

        result = await model.predict_batch(["sentence 1", "sentence 2"])

        expected = [
            {"label": "PRESENT", "score": 0.95},
            {"label": "ABSENT", "score": 0.87},
        ]
        assert result == expected

    def test_predict_batch_sync_success(self, model):
        """Test synchronous batch prediction success"""
        # Setup pipeline
        model.pipeline = Mock()
        mock_results = [
            [{"label": "LABEL_0", "score": 0.95}],
            [{"label": "LABEL_1", "score": 0.87}],
        ]
        model.pipeline.return_value = mock_results

        result = model._predict_batch_sync(["sentence 1", "sentence 2"])

        expected = [
            {"label": "PRESENT", "score": 0.95},
            {"label": "ABSENT", "score": 0.87},
        ]
        assert result == expected

    def test_predict_batch_sync_single_result(self, model):
        """Test synchronous batch prediction with single result per sentence"""
        # Setup pipeline
        model.pipeline = Mock()
        mock_results = [
            {"label": "LABEL_2", "score": 0.76},
            {"label": "LABEL_0", "score": 0.92},
        ]
        model.pipeline.return_value = mock_results

        result = model._predict_batch_sync(["sentence 1", "sentence 2"])

        expected = [
            {"label": "POSSIBLE", "score": 0.76},
            {"label": "PRESENT", "score": 0.92},
        ]
        assert result == expected

    def test_get_model_info(self, model):
        """Test getting model information"""
        with patch("torch.cuda.is_available", return_value=False):
            model.device = "cpu"
            model._loaded = True
            model.model = Mock()

            info = model.get_model_info()

            expected = {
                "model_name": "bvanaken/clinical-assertion-negation-bert",
                "device": "cpu",
                "loaded": True,
                "labels": ["PRESENT", "ABSENT", "POSSIBLE"],
                "cuda_available": False,
            }
            assert info == expected

    def test_get_model_info_cuda_available(self, model):
        """Test getting model information with CUDA available"""
        with patch("torch.cuda.is_available", return_value=True):
            model.device = "cuda"
            model._loaded = False

            info = model.get_model_info()

            assert info["cuda_available"] is True
            assert info["loaded"] is False

    def test_predict_sync_empty_result(self, model):
        """Test synchronous prediction with empty result list"""
        model.pipeline = Mock()
        model.pipeline.return_value = []

        with pytest.raises(IndexError):
            model._predict_sync("test sentence")

    def test_predict_sync_none_result(self, model):
        """Test synchronous prediction with None result"""
        model.pipeline = Mock()
        model.pipeline.return_value = None

        with pytest.raises(RuntimeError, match="Unexpected result type"):
            model._predict_sync("test sentence")

    def test_predict_batch_sync_empty_results(self, model):
        """Test synchronous batch prediction with empty results"""
        model.pipeline = Mock()
        model.pipeline.return_value = []

        result = model._predict_batch_sync([])
        assert result == []

    def test_predict_batch_sync_mixed_result_types(self, model):
        """Test synchronous batch prediction with mixed result types"""
        model.pipeline = Mock()
        mock_results = [
            {"label": "LABEL_0", "score": 0.95},
            [{"label": "LABEL_1", "score": 0.87}],
            {"label": "LABEL_2", "score": 0.76},
        ]
        model.pipeline.return_value = mock_results

        result = model._predict_batch_sync(["sentence 1", "sentence 2", "sentence 3"])

        expected = [
            {"label": "PRESENT", "score": 0.95},
            {"label": "ABSENT", "score": 0.87},
            {"label": "POSSIBLE", "score": 0.76},
        ]
        assert result == expected

    def test_predict_sync_unknown_label(self, model):
        """Test synchronous prediction with unknown label mapping"""
        model.pipeline = Mock()
        mock_result = {"label": "LABEL_UNKNOWN", "score": 0.85}
        model.pipeline.return_value = [mock_result]

        result = model._predict_sync("test sentence")

        # Should return the unknown label as-is since it's not in the mapping
        assert result == {"label": "LABEL_UNKNOWN", "score": 0.85}
