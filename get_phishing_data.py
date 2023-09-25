import re
from urllib.parse import urlparse

import joblib
import pandas as pd
from bs4 import BeautifulSoup
from selenium import webdriver
from selenium.webdriver.chrome.options import Options

# Inicialize o WebDriver do Chrome
chrome_options = Options()
# Executa o Chrome no modo sem interface gráfica (headless)
chrome_options.add_argument('--headless')
driver = webdriver.Chrome(options=chrome_options)


def extract_url_features(url, parsed_url):
    return {
        'NumDots': url.count("."),
        'SubdomainLevel': len(parsed_url.hostname.split(".")) - 2,
        'PathLevel': len(parsed_url.path.split("/")) - 1,
        'UrlLength': len(url),
        'NumDash': url.count("-"),
        'NumDashInHostname': parsed_url.hostname.count("-"),
        'AtSymbol': int("@" in url),
        'TildeSymbol': int("~" in url),
        'NumUnderscore': url.count("_"),
        'NumPercent': url.count("%"),
        'NumQueryComponents': len(parsed_url.query.split("&")),
        'NumAmpersand': url.count("&"),
        'NumHash': url.count("#"),
        'NumNumericChars': sum(c.isdigit() for c in url),
        'NoHttps': int(not url.startswith("https://")),
        'RandomString': int(bool(re.search(r'[0-9a-f]{8}', url))),
        'IpAddress': int(bool(re.match(r'\d+\.\d+\.\d+\.\d+', parsed_url.netloc))),
        'DomainInSubdomains': int(parsed_url.netloc.count(".") > 1),
        'DomainInPaths': int(parsed_url.path.count(parsed_url.netloc) > 0),
        'HttpsInHostname': int("https" in parsed_url.hostname),
        'HostnameLength': len(parsed_url.hostname),
        'PathLength': len(parsed_url.path),
        'QueryLength': len(parsed_url.query),
        'DoubleSlashInPath': int("//" in parsed_url.path),
        'SubdomainLevelRT': len(parsed_url.hostname.split(".")) - 2,
        'UrlLengthRT': len(url)
    }


def extract_html_features(soup, parsed_url):
    sensitive_words = ['login', 'bank', 'account', 'password', 'credential']
    num_sensitive_words = sum(soup.text.lower().count(word)
                              for word in sensitive_words)

    brand_name = "google"  # Substitua pelo nome da marca que você está verificando
    embedded_brand_name = int(brand_name.lower() in soup.text.lower())

    abnormal_ext_form_action_r = sum(1 for form in soup.find_all('form') if urlparse(
        form['action']).netloc != parsed_url.netloc and not form['action'].startswith(('http', 'www')))

    ext_meta_script_link_rt = sum(1 for tag in soup.find_all(['meta', 'script', 'link']) if urlparse(
        tag['content' if tag.name == 'meta' else 'src' if tag.name == 'script' else 'href']).
        netloc != parsed_url.netloc)

    total_hyperlinks = len(soup.find_all('a'))
    ext_null_self_redirect_hyperlinks = sum(1 for a in soup.find_all(
        'a') if a['href'] == "#" or a['href'] == parsed_url.path and urlparse(a['href']).netloc != parsed_url.netloc)
    pct_ext_null_self_redirect_hyperlinks_rt = (
        ext_null_self_redirect_hyperlinks / total_hyperlinks) * 100 if total_hyperlinks else 0

    return {
        'MissingTitle': 0 if soup.title else 1,
        'RightClickDisabled': int(len(soup.find_all("body", oncontextmenu="return false")) > 0),
        'PopUpWindow': int(len(soup.find_all("script", string=re.compile("window\.open\("))) > 0),
        'SubmitInfoToEmail': int(len(soup.find_all("form", action=re.compile("mailto:"))) > 0),
        'IframeOrFrame': int(len(soup.find_all(['iframe', 'frame'])) > 0),
        'ImagesOnlyInForm': int(len(soup.find_all('img')) == sum(len(form.find_all('img')) for form in
                                                                 soup.find_all('form'))),
        'NumSensitiveWords': num_sensitive_words,
        'EmbeddedBrandName': embedded_brand_name,
        'AbnormalExtFormActionR': abnormal_ext_form_action_r,
        'ExtMetaScriptLinkRT': ext_meta_script_link_rt,
        'PctExtNullSelfRedirectHyperlinksRT': pct_ext_null_self_redirect_hyperlinks_rt
    }


def extract_external_features(soup, parsed_url):
    favicon = soup.find("link", rel="icon")
    ext_favicon = 1 if favicon and urlparse(
        favicon['href']).netloc != parsed_url.netloc else 0

    insecure_forms = sum(1 for form in soup.find_all(
        'form') if not form['action'].startswith('https'))
    relative_form_action = sum(1 for form in soup.find_all(
        'form') if not form['action'].startswith(('http', 'www')))
    ext_form_action = sum(1 for form in soup.find_all(
        'form') if urlparse(form['action']).netloc != parsed_url.netloc)
    abnormal_form_action = sum(1 for form in soup.find_all(
        'form') if not form['action'] or form['action'] == parsed_url.path)

    total_resources = len(soup.find_all(['img', 'script', 'link']))
    ext_resources = sum(1 for tag in soup.find_all(['img', 'script', 'link']) if urlparse(
        tag['src' if tag.name == 'img' else 'href']).netloc != parsed_url.netloc)
    pct_ext_resource_urls = (
        ext_resources / total_resources) * 100 if total_resources else 0
    pct_ext_resource_urls_rt = (
        ext_resources / total_resources) * 100 if total_resources else 0

    total_hyperlinks = len(soup.find_all('a'))
    ext_hyperlinks = sum(1 for a in soup.find_all(
        'a') if urlparse(a['href']).netloc != parsed_url.netloc)
    null_self_redirect_hyperlinks = sum(1 for a in soup.find_all(
        'a') if a['href'] == "#" or a['href'] == parsed_url.path)

    pct_ext_hyperlinks = (ext_hyperlinks / total_hyperlinks) * \
        100 if total_hyperlinks else 0
    pct_null_self_redirect_hyperlinks = (
        null_self_redirect_hyperlinks / total_hyperlinks) * 100 if total_hyperlinks else 0

    domain_name = parsed_url.hostname.split(".")[-2]
    frequent_domain_name_mismatch = sum(
        1 for a in soup.find_all('a') if domain_name not in a['href'])

    fake_link_in_status_bar = sum(
        1 for a in soup.find_all('a', onmouseover=True))

    return {
        'ExtFavicon': ext_favicon,
        'InsecureForms': insecure_forms,
        'RelativeFormAction': relative_form_action,
        'ExtFormAction': ext_form_action,
        'AbnormalFormAction': abnormal_form_action,
        'PctExtResourceUrls': pct_ext_resource_urls,
        'PctExtResourceUrlsRT': pct_ext_resource_urls_rt,
        'PctExtHyperlinks': pct_ext_hyperlinks,
        'PctNullSelfRedirectHyperlinks': pct_null_self_redirect_hyperlinks,
        'FrequentDomainNameMismatch': frequent_domain_name_mismatch,
        'FakeLinkInStatusBar': fake_link_in_status_bar
    }


def extract_features(url):
    features = {}
    parsed_url = urlparse(url)
    soup = BeautifulSoup(driver.page_source, 'html.parser')

    features.update(extract_url_features(url, parsed_url))
    features.update(extract_html_features(soup, parsed_url))
    features.update(extract_external_features(soup, parsed_url))

    return features


def get_scaled_features(features):
    categorical_cols = ['AbnormalFormAction', 'SubdomainLevelRT', 'UrlLengthRT', 'PctExtResourceUrlsRT',
                        'AbnormalExtFormActionR', 'ExtMetaScriptLinkRT', 'PctExtNullSelfRedirectHyperlinksRT']

    discrete_cols = ['NumDots', 'SubdomainLevel', 'PathLevel', 'UrlLength', 'NumDash', 'NumDashInHostname',
                     'NumUnderscore', 'NumPercent', 'NumQueryComponents', 'NumAmpersand', 'NumHash',
                     'NumNumericChars', 'HostnameLength', 'PathLength', 'QueryLength', 'NumSensitiveWords']

    continuous_cols = ['PctExtHyperlinks',
                       'PctExtResourceUrls', 'PctNullSelfRedirectHyperlinks']
    cols_to_scale = discrete_cols + continuous_cols

    df = pd.DataFrame([features])

    # Aplica one-hot encoding
    df = pd.get_dummies(df, columns=categorical_cols)

    # List of all expected columns
    expected_columns = ['NumDots', 'SubdomainLevel', 'PathLevel', 'UrlLength', 'NumDash',
                        'NumDashInHostname', 'AtSymbol', 'TildeSymbol', 'NumUnderscore',
                        'NumPercent', 'NumQueryComponents', 'NumAmpersand', 'NumHash',
                        'NumNumericChars', 'NoHttps', 'RandomString', 'IpAddress',
                        'DomainInSubdomains', 'DomainInPaths', 'HttpsInHostname',
                        'HostnameLength', 'PathLength', 'QueryLength', 'DoubleSlashInPath',
                        'NumSensitiveWords', 'EmbeddedBrandName', 'PctExtHyperlinks',
                        'PctExtResourceUrls', 'ExtFavicon', 'InsecureForms',
                        'RelativeFormAction', 'ExtFormAction', 'PctNullSelfRedirectHyperlinks',
                        'FrequentDomainNameMismatch', 'FakeLinkInStatusBar',
                        'RightClickDisabled', 'PopUpWindow', 'SubmitInfoToEmail',
                        'IframeOrFrame', 'MissingTitle', 'ImagesOnlyInForm',
                        'AbnormalFormAction_0.0', 'AbnormalFormAction_1.0',
                        'SubdomainLevelRT_-1.0', 'SubdomainLevelRT_0.0', 'SubdomainLevelRT_1.0',
                        'UrlLengthRT_-1.0', 'UrlLengthRT_0.0', 'UrlLengthRT_1.0',
                        'PctExtResourceUrlsRT_-1.0', 'PctExtResourceUrlsRT_0.0',
                        'PctExtResourceUrlsRT_1.0', 'AbnormalExtFormActionR_-1.0',
                        'AbnormalExtFormActionR_0.0', 'AbnormalExtFormActionR_1.0',
                        'ExtMetaScriptLinkRT_-1.0', 'ExtMetaScriptLinkRT_0.0',
                        'ExtMetaScriptLinkRT_1.0', 'PctExtNullSelfRedirectHyperlinksRT_-1.0',
                        'PctExtNullSelfRedirectHyperlinksRT_0.0',
                        'PctExtNullSelfRedirectHyperlinksRT_1.0'
                        ]

    # Add missing columns and fill with zeros
    for col in expected_columns:
        if col not in df.columns:
            df[col] = 0

    # Reordena as colunas
    df = df[expected_columns]

    # Inicializa escalonador
    scaler = joblib.load('./utils/scaler.joblib')

    # Escalona as colunas numéricas
    df[cols_to_scale] = scaler.transform(df[cols_to_scale])

    return df.values


def load_mlp_model(model_path):
    try:
        model = joblib.load(model_path)
        return model
    except Exception as e:
        print(f"Erro ao carregar o modelo: {str(e)}")
        return None


# Uso de exemplo
if __name__ == "__main__":
    # Substitua pela URL do site que deseja classificar
    website_url = "https://www.google.com/"
    extracted_features = extract_features(website_url)

    if extracted_features:
        scaled_features = get_scaled_features(extracted_features)

        mlp_model = load_mlp_model("./utils/mlp_model.pkl")

        print(extracted_features, '\n')
        print(scaled_features, '\n')

        if mlp_model:
            prediction = mlp_model.predict(scaled_features)
            probabilities = mlp_model.predict_proba(scaled_features)

            # Print probabilities for the first sample
            print("Probabilidades:", probabilities[0], '\n')

            if prediction[0] == 1:
                print("Site de phishing")
            else:
                print("Não é um site de phishing")

    driver.quit()  # Fecha o navegador
