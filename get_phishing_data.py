import re
from urllib.parse import urlparse

import joblib
import pandas as pd
from bs4 import BeautifulSoup
from collections import Counter
import requests
import tldextract


def get_abnormal_ext_form_action_r(soup, parsed_url):
    forms = soup.find_all('form')

    for form in forms:
        action_url = form.get('action', '')

        if action_url == '' or action_url == 'about:blank':
            return -1

        parsed_action_url = urlparse(action_url)
        if parsed_action_url.netloc and parsed_action_url.netloc != parsed_url.netloc:
            return 0

    return 1


def get_images_only_in_form(soup):
    forms = soup.find_all('form')

    for form in forms:
        text_content = form.stripped_strings
        img_tags = form.find_all('img')

        if not any(text_content) and img_tags:
            return int(True)

    return int(False)


def get_popup_window(soup):
    scripts = soup.find_all('script')

    for script in scripts:
        if script.string and 'window.open' in script.string:
            return int(True)

    tags_with_onclick = soup.find_all(attrs={"onclick": True})

    if any('window.open' in tag.get('onclick', '') for tag in tags_with_onclick):
        return int(True)

    return int(False)


def get_right_click_disabled(soup):
    scripts = soup.find_all('script')

    for script in scripts:
        if script.string and 'event.button==2' in script.string:
            return int(True)

    tags_with_oncontextmenu = soup.find_all(attrs={"oncontextmenu": True})

    if any('return false' in tag.get('oncontextmenu', '') for tag in tags_with_oncontextmenu):
        return int(True)

    return int(False)


def get_embedded_brand_name(soup, parsed_url, extract_url):
    all_urls = [
        tag.get('href', '') for tag in soup.find_all(['a'])
    ]

    all_domain = [tldextract.extract(link).domain for link in all_urls if tldextract.extract(link).domain != ""]

    if all_domain:
        most_frequent_name = Counter(all_domain).most_common(1)[0][0]
        embedded_brand_name = int(
            most_frequent_name in extract_url.subdomain or most_frequent_name in parsed_url.path)
    else:
        embedded_brand_name = int(False)

    return embedded_brand_name


def pct_ext_resource_urls(soup, parsed_url, apply_threshold=False):
    all_urls = [
                   tag.get('href', '') for tag in soup.find_all(['a', 'link'])
               ] + [
                   tag.get('src', '') for tag in soup.find_all(['img', 'script'])
               ]

    total_urls = len(all_urls)
    external_urls = sum(1 for url in all_urls if urlparse(
        url).netloc and urlparse(url).netloc != parsed_url.netloc)

    pct_ext_resource_urls = (
            external_urls / total_urls) if total_urls > 0 else 0

    if apply_threshold:
        if pct_ext_resource_urls < 0.22:
            pct_ext_resource_urls = -1
        elif pct_ext_resource_urls < 0.61:
            pct_ext_resource_urls = 0
        else:
            pct_ext_resource_urls = 1

    return pct_ext_resource_urls


def get_pct_ext_hyperlinks(soup, parsed_url):
    hyperlinks = [a.get('href', '') for a in soup.find_all('a', href=True)]
    count_hyperlink = 0
    total_links = len(hyperlinks)

    for link in hyperlinks:
        if "http" in link.lower() and urlparse(link).netloc != parsed_url.netloc:
            count_hyperlink += 1

    if total_links > 0:
        pct_null_self_redirect = count_hyperlink / total_links
    else:
        pct_null_self_redirect = 0

    return pct_null_self_redirect


def get_pct_null_self_redirect_hyperlinks(soup, parsed_url):
    all_links = [tag.get('href', '') for tag in soup.find_all('a')]

    total_links = len(all_links)
    null_self_redirect_hyperlinks = sum(
        1 for link in all_links if
        link == '' or link == '#' or link == parsed_url or (link is not None and link.startswith('file://'))
    )

    pct_null_self_redirect_hyperlinks = null_self_redirect_hyperlinks / \
                                        total_links if total_links > 0 else 0

    return pct_null_self_redirect_hyperlinks


def get_frequent_domain_name_mismatch(soup, parsed_url):
    hyperlinks = [a.get('href', '') for a in soup.find_all('a', href=True)]

    domains = [urlparse(link).netloc for link in hyperlinks if urlparse(
        link).netloc != ""]
    domain_count = Counter(domains)
    most_frequent_domain = domain_count.most_common(
        1)[0][0] if domain_count else ""

    site_domain = parsed_url.netloc
    return 1 if most_frequent_domain and most_frequent_domain != site_domain else 0


def extract_url_features(url, parsed_url, extract_url):
    list_tld = ['.com', 'org', '.net', '.xyz', '.name', '.biz', '.space', '.site', '.info', '.club', '.tech', '.online',
                '.pro', '.app', '.dev', '.studio', '.agency', '.life', '.blog', '.cloud', '.link', '.io', '.tv', '.gov',
                '.edu', '.int', '.mil', '.mobi', '.jobs', '.icu', '.tel', '.post', '.asia', '.br', '.uk', '.es', '.us',
                '.ca', '.fr', '.in', '.cn', '.de', '.jp', '.pt']
    sensitive_words = ['secure', 'account', 'webscr',
                       'login', 'ebayisapi', 'signin', 'banking', 'confirm', 'senha', 'conta']

    return {
        'NumDots': url.count("."),
        'SubdomainLevel': 0 if not extract_url.subdomain else len(extract_url.subdomain.split(".")),  ###
        'PathLevel': 0 if parsed_url.path.strip("/") == "" else len(parsed_url.path.strip("/").split("/")),  ###
        'UrlLength': len(url),
        'NumDash': url.count("-"),
        'NumDashInHostname': parsed_url.hostname.count("-"),
        'AtSymbol': int("@" in url),
        'TildeSymbol': int("~" in url),
        'NumUnderscore': url.count("_"),
        'NumPercent': url.count("%"),
        'NumQueryComponents': 0 if parsed_url.query == "" else len(parsed_url.query.split("&")),  ###
        'NumAmpersand': url.count("&"),
        'NumHash': url.count("#"),
        'NumNumericChars': sum(c.isdigit() for c in url),
        'NoHttps': int(url.startswith("https://")),  ###
        'RandomString': int(bool(re.search(r'[0-9a-fA-F]{5}', url))),  ###
        'IpAddress': int(bool(re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', parsed_url.netloc))),  ###
        'DomainInSubdomains': int(any(tld in extract_url.subdomain for tld in list_tld)),  ###
        'DomainInPaths': int(any(tld in parsed_url.path for tld in list_tld)),  ###
        'HttpsInHostname': int("https" in parsed_url.hostname),
        'HostnameLength': len(parsed_url.hostname),
        'PathLength': len(parsed_url.path),
        'QueryLength': len(parsed_url.query),
        'DoubleSlashInPath': int("//" in parsed_url.path),
        'NumSensitiveWords': sum(1 for word in sensitive_words if word in url),  ###
        'SubdomainLevelRT': 1 if extract_url.subdomain.count(".") <= 1 ###
        else (0 if extract_url.subdomain.count(".") == 2 else -1),  ###
        'UrlLengthRT': 1 if len(url) < 54 else (0 if 54 < len(url) <= 75 else -1)  ###
    }


def extract_html_features(soup, parsed_url, extract_url):
    list_tags = soup.find_all(['meta', 'script', 'link'])
    total_tags = len(list_tags)

    total_ext_meta_script_link = sum(
        1 for tag in list_tags if (
                tag.get('content' if tag.name == 'meta' else 'src' if tag.name == 'script' else 'href') is not None
                and "http" in tag.get('content' if tag.name == 'meta' else 'src' if tag.name == 'script' else 'href',
                                      '')
                and urlparse(tag.get(
            'content' if tag.name == 'meta' else 'src' if tag.name == 'script' else 'href')).netloc != parsed_url.netloc
        )
    )
    ratio_ext = total_ext_meta_script_link / total_tags
    ext_meta_script_link_rt = -1 if ratio_ext < 0.17 else 0 if 0.17 <= ratio_ext <= 0.81 else 1

    total_hyperlinks = len(soup.find_all('a'))
    ext_null_self_redirect_hyperlinks = sum(1 for a in soup.find_all(
        'a') if a.get('href', '').startswith('#') or ("http" in a.get('href', '') and urlparse(
        a.get('href', '')).netloc != parsed_url.netloc))
    ratio_pct = ext_null_self_redirect_hyperlinks / total_hyperlinks
    pct_ext_null_self_redirect_hyperlinks_rt = -1 if ratio_pct < 0.31 else 0 if 0.31 <= ratio_pct <= 0.67 else 1

    return {
        'MissingTitle': 0 if soup.title else 1,
        'RightClickDisabled': get_right_click_disabled(soup),
        'PopUpWindow': get_popup_window(soup),
        'SubmitInfoToEmail': int(bool(soup.find_all('a', href=lambda x: x and x.startswith('mailto:')))),
        'IframeOrFrame': int(bool(soup.find_all(['iframe', 'frame']))),
        'ImagesOnlyInForm': get_images_only_in_form(soup),
        'EmbeddedBrandName': get_embedded_brand_name(soup, parsed_url, extract_url),  ###
        'AbnormalExtFormActionR': get_abnormal_ext_form_action_r(soup, parsed_url),
        'ExtMetaScriptLinkRT': ext_meta_script_link_rt,  ###
        'PctExtNullSelfRedirectHyperlinksRT': pct_ext_null_self_redirect_hyperlinks_rt  ###
    }


def extract_external_features(soup, parsed_url):
    favicon = soup.find("link", rel="icon")
    ext_favicon = 1 if favicon and urlparse(
        favicon.get('href', '')).netloc != parsed_url.netloc else 0

    cont_insecure_forms = sum(1 for form in soup.find_all('form') if (not urlparse(form.get('action', '')).scheme
                                                                      and not parsed_url.scheme == 'https')
                              or (urlparse(form.get('action', '')).scheme and not parsed_url.scheme == 'https'))
    insecure_forms = 1 if cont_insecure_forms >= 1 else 0
    relative_form_action = int(any(
        not urlparse(form.get('action')).scheme and not urlparse(
            form.get('action')).netloc
        for form in soup.find_all('form')
    ))
    ext_form_action = int(any(urlparse(form.get('action', '')).netloc !=
                              parsed_url.netloc for form in soup.find_all('form')))
    abnormal_form_action = int(any(
        form.get('action', '') in ['#', 'about:blank', '', 'javascript:true']
        for form in soup.find_all('form')
    ))

    fake_link_in_status_bar = int(any(
        'window.status' in tag['onmouseover'] for tag in soup.find_all(attrs={"onmouseover": True})))

    return {
        'ExtFavicon': ext_favicon,
        'InsecureForms': insecure_forms,  ###
        'RelativeFormAction': relative_form_action,  # verificar
        'ExtFormAction': ext_form_action,
        'AbnormalFormAction': abnormal_form_action,
        'PctExtResourceUrls': pct_ext_resource_urls(soup, parsed_url),
        'PctExtResourceUrlsRT': pct_ext_resource_urls(soup, parsed_url, apply_threshold=True),
        'PctExtHyperlinks': get_pct_ext_hyperlinks(soup, parsed_url),  ###
        'PctNullSelfRedirectHyperlinks': get_pct_null_self_redirect_hyperlinks(soup, parsed_url),
        'FrequentDomainNameMismatch': get_frequent_domain_name_mismatch(soup, parsed_url),
        'FakeLinkInStatusBar': fake_link_in_status_bar
    }


def extract_features(url, html_content):
    features = {}
    parsed_url = urlparse(url)
    extract_url = tldextract.extract(url)
    print(parsed_url, '\n')
    soup = BeautifulSoup(html_content, 'html.parser')

    features.update(extract_url_features(url, parsed_url, extract_url))
    features.update(extract_html_features(soup, parsed_url, extract_url))
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

    for col in expected_columns:
        if col not in df.columns:
            df[col] = 0

    # Reordena as colunas
    df = df[expected_columns]

    scaler = joblib.load('./utils/scaler.joblib')
    df[cols_to_scale] = scaler.transform(df[cols_to_scale])

    return df.values


def load_mlp_model(model_path):
    try:
        model = joblib.load(model_path)
        return model
    except Exception as e:
        print(f"Erro ao carregar o modelo: {str(e)}")
        return None


def fetch_html_content(url):
    try:
        response = requests.get(url)
        response.raise_for_status()
        return response.text
    except requests.RequestException as e:
        print(f"An error occurred: {e}")
        return None


# Uso de exemplo
if __name__ == "__main__":
    # Substitua pela URL do site que deseja classificar
    website_url = "https://www.google.com/"
    html_content = fetch_html_content(website_url)
    extracted_features = extract_features(website_url, html_content)

    if extracted_features:
        scaled_features = get_scaled_features(extracted_features)

        mlp_model = load_mlp_model("./utils/mlp_model.pkl")

        print(extracted_features, '\n')
        print(scaled_features, '\n')

        if mlp_model:
            prediction = mlp_model.predict(scaled_features)
            probabilities = mlp_model.predict_proba(scaled_features)

            print("Probabilidades:", probabilities[0], '\n')

            if prediction[0] == 1:
                print("Site de phishing")
            else:
                print("Não é um site de phishing")
