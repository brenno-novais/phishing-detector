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

def extract_features(url):
    features = {}
    parsed_url = urlparse(url)
    features.update(extract_url_features(url, parsed_url))    
    
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