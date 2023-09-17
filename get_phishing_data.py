import re
from urllib.parse import urlparse
import joblib

from selenium import webdriver
from selenium.webdriver.chrome.options import Options

# Inicialize o WebDriver do Chrome
chrome_options = Options()
chrome_options.add_argument('--headless')  # Executa o Chrome no modo sem interface gráfica (headless)
driver = webdriver.Chrome(options=chrome_options)

# Função para extrair características de um site
def extract_features(url):
    try:
        # Passo 1: Abre o site no navegador
        driver.get(url)

        # Passo 2: Extrai características básicas
        url_length = len(url)

        # Passo 3: Extrai características relacionadas à URL
        parsed_url = urlparse(url)
        path_length = len(parsed_url.path)

        # Passo 4: Extrai características de conteúdo HTML

        # Passo 5: Analisa recursos externos (por exemplo, imagens) em busca de domínios suspeitos

        # Passo 6: Extrai características baseadas em texto

        # Retorna um dicionário de características extraídas
        features = {
            'NumDots': url.count("."),
            'SubdomainLevel': len(parsed_url.hostname.split(".")) - 2,  # Subtrai 2 para o domínio principal e TLD
            'PathLevel': len(parsed_url.path.split("/")) - 1,  # Subtrai 1 para o primeiro elemento vazio
            'UrlLength': url_length,
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
            'PathLength': path_length,
            'QueryLength': len(parsed_url.query),
            'DoubleSlashInPath': int("//" in parsed_url.path),
            'NumSensitiveWords': 0,  # Adicionar lógica para esta característica
            'EmbeddedBrandName': 0,  # Adicionar lógica para esta característica
            'PctExtHyperlinks': 0,  # Adicionar lógica para esta característica
            'PctExtResourceUrls': 0,  # Adicionar lógica para esta característica
            'ExtFavicon': 0,  # Adicionar lógica para esta característica
            'InsecureForms': 0,  # Adicionar lógica para esta característica
            'RelativeFormAction': 0,  # Adicionar lógica para esta característica
            'ExtFormAction': 0,  # Adicionar lógica para esta característica
            'AbnormalFormAction': 0,  # Adicionar lógica para esta característica
            'PctNullSelfRedirectHyperlinks': 0,  # Adicionar lógica para esta característica
            'FrequentDomainNameMismatch': 0,  # Adicionar lógica para esta característica
            'FakeLinkInStatusBar': 0,  # Adicionar lógica para esta característica
            'RightClickDisabled': 0,  # Adicionar lógica para esta característica
            'PopUpWindow': 0,  # Adicionar lógica para esta característica
            'SubmitInfoToEmail': 0,  # Adicionar lógica para esta característica
            'IframeOrFrame': 0,  # Adicionar lógica para esta característica
            'MissingTitle': 0,  # Adicionar lógica para esta característica
            'ImagesOnlyInForm': 0,  # Adicionar lógica para esta característica
            'SubdomainLevelRT': 0,  # Adicionar lógica para esta característica
            'UrlLengthRT': 0,  # Adicionar lógica para esta característica
            'PctExtResourceUrlsRT': 0,  # Adicionar lógica para esta característica
            'AbnormalExtFormActionR': 0,  # Adicionar lógica para esta característica
            'ExtMetaScriptLinkRT': 0,  # Adicionar lógica para esta característica
            'PctExtNullSelfRedirectHyperlinksRT': 0  # Adicionar lógica para esta característica
        }

        return features

    except Exception as e:
        print(f"Erro ao extrair características de {url}: {str(e)}")
        return None

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