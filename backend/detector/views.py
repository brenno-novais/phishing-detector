from django.forms import ValidationError
from django.http import JsonResponse

from detector.helpers import is_valid_url
from .feature_extractor import WebsiteFeatureExtrator
from .classifier import PhishingClassifier
from django.views.decorators.csrf import csrf_exempt


@csrf_exempt  # TO DO: Retirar no futuro
def detect_phishing(request):
    website_url = request.GET.get('website_url')

    if not is_valid_url(website_url):
        raise ValidationError('Provide a valid website URL.')

    feature_extractor = WebsiteFeatureExtrator(website_url)
    phishing_classifier = PhishingClassifier()

    values, _ = feature_extractor.get_features()
    result, probabilities = phishing_classifier.classify(values)

    probability_number = round(probabilities[0][result] * 100, 1)
    probability = f'{probability_number}%'
    classification = 'PHISHING' if result == 1 else 'LEGITIMATE'
    result_message = 'Esse site tem chance considerável de ser ' + (
        'phishing.' if result == 1 or round(probabilities[0][result] * 100, 1) > 40 else 'legítimo.')

    data = {'message': result_message, 'result': classification, 'probability': probability}
    print(data)
    return JsonResponse(data, status=200)
