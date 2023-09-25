import re
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import joblib

from selenium import webdriver
from selenium.webdriver.chrome.options import Options

# Inicialize o WebDriver do Chrome
chrome_options = Options()
chrome_options.add_argument('--headless')  # Executa o Chrome no modo sem interface gráfica (headless)
driver = webdriver.Chrome(options=chrome_options)

# Função para extrair características relacionadas à URL
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

# Função para extrair características de conteúdo HTML
def extract_html_features(soup, parsed_url):
    sensitive_words = ['login', 'bank', 'account', 'password', 'credential']
    num_sensitive_words = sum(soup.text.lower().count(word) for word in sensitive_words)
    
    brand_name = "google"  # Substitua pelo nome da marca que você está verificando
    embedded_brand_name = int(brand_name.lower() in soup.text.lower())
    
    abnormal_ext_form_action_r = sum(1 for form in soup.find_all('form') if urlparse(form['action']).netloc != parsed_url.netloc and not form['action'].startswith(('http', 'www')))
    
    ext_meta_script_link_rt = sum(1 for tag in soup.find_all(['meta', 'script', 'link']) if urlparse(tag['content' if tag.name == 'meta' else 'src' if tag.name == 'script' else 'href']).netloc != parsed_url.netloc)

    total_hyperlinks = len(soup.find_all('a'))
    ext_null_self_redirect_hyperlinks = sum(1 for a in soup.find_all('a') if a['href'] == "#" or a['href'] == parsed_url.path and urlparse(a['href']).netloc != parsed_url.netloc)
    pct_ext_null_self_redirect_hyperlinks_rt = (ext_null_self_redirect_hyperlinks / total_hyperlinks) * 100 if total_hyperlinks else 0

    return {
        'MissingTitle': 0 if soup.title else 1,
        'RightClickDisabled': int(len(soup.find_all("body", oncontextmenu="return false")) > 0),
        'PopUpWindow': int(len(soup.find_all("script", string=re.compile("window\.open\("))) > 0),
        'SubmitInfoToEmail': int(len(soup.find_all("form", action=re.compile("mailto:"))) > 0),
        'IframeOrFrame': int(len(soup.find_all(['iframe', 'frame'])) > 0),
        'ImagesOnlyInForm': int(len(soup.find_all('img')) == sum(len(form.find_all('img')) for form in soup.find_all('form'))),
        'NumSensitiveWords': num_sensitive_words,
        'EmbeddedBrandName': embedded_brand_name,
        'AbnormalExtFormActionR': abnormal_ext_form_action_r,
        'ExtMetaScriptLinkRT': ext_meta_script_link_rt,
        'PctExtNullSelfRedirectHyperlinksRT': pct_ext_null_self_redirect_hyperlinks_rt
    }
def extract_features(url):
    features = {}
    parsed_url = urlparse(url)
    soup = BeautifulSoup(driver.page_source, 'html.parser')
    
    features.update(extract_url_features(url, parsed_url))    
    features.update(extract_html_features(soup, parsed_url))
    
    return features

# Função para carregar o modelo MLP
def load_mlp_model(model_path):
    try:
        model = joblib.load(model_path)
        return model
    except Exception as e:
        print(f"Erro ao carregar o modelo: {str(e)}")
        return None

# Uso de exemplo
if __name__ == "__main__":
    website_url = "https://www.google.com/"  # Substitua pela URL do site que deseja classificar
    extracted_features = extract_features(website_url)

    if extracted_features:
        mlp_model = load_mlp_model("mlp_model.pkl") 

        print (extracted_features, '\n')

        if mlp_model:
            prediction = mlp_model.predict([list(extracted_features.values())])

            if prediction[0] == 1:
                print("Site de phishing")
            else:
                print("Não é um site de phishing")

    driver.quit()  # Fecha o navegador