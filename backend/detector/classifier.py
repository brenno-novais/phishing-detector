import joblib

PHISHING = 1
LEGITIMATE = 0


class ModelLoadingError(Exception):
    pass


class PredictionError(Exception):
    pass


class PhishingClassifier:

    def __init__(self):
        self.random_forest_model = PhishingClassifier.load_random_forest_model(
            "detector\\resources\\random_forest_model.pkl")

    @classmethod
    def load_random_forest_model(cls, model_path):
        try:
            model = joblib.load(model_path)
            return model
        except Exception as e:
            print(e)
            raise ModelLoadingError("Failed to load the model") from e

    def classify(self, features):
        try:
            prediction = self.random_forest_model.predict(features)
            probabilities = self.random_forest_model.predict_proba(features)

            if prediction[0] == 1:
                return (PHISHING, probabilities)
            else:
                return (LEGITIMATE, probabilities)
        except Exception as e:
            raise PredictionError(
                "Error while trying to classify this website.") from e
