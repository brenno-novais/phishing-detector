from django.core.management.base import BaseCommand
from django.forms import ValidationError
from detector.classifier import PhishingClassifier
from detector.feature_extractor import WebsiteFeatureExtrator

from detector.helpers import is_valid_url


class Command(BaseCommand):
    help = """"
    Extract features and classify a website into phishing or legitimate.
    """

    def add_arguments(self, parser):
        parser.add_argument('--website_url', type=str, default=None,
                            help='URL from the intended website to classify.')

    def handle(self, **options):
        website_url = options['website_url']

        if not is_valid_url(website_url):
            raise ValidationError('Provide a valid website URL.')

        feature_extractor = WebsiteFeatureExtrator(website_url)
        phishing_classifier = PhishingClassifier()

        values, features = feature_extractor.get_features()
        result, probabilities = phishing_classifier.classify(values)

        print('====================================================================================')
        print('RESULTS:')
        print('====================================================================================')
        print('Classification: ' + ('PHISHING' if result == 1 else 'LEGITIMATE'))
        print('------------------------------------------------------------------------------------')
        print('Probabilities: ', probabilities)
        print(f"   - To be legitimate: {probabilities[0][0]}")
        print(f"   - To be phishing: {probabilities[0][1]}")
        print('------------------------------------------------------------------------------------')
        print('Non-Scaled Features:')
        for feature_name, value in features.items():
            print(f"   - {feature_name}: {value}")
