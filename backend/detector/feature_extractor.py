import re
from urllib.parse import urlparse

import joblib
import pandas as pd
from bs4 import BeautifulSoup
from collections import Counter
import requests
import tldextract


class WebsiteFeatureExtrator:

    def __init__(self, website_url):
        self.website_url = website_url
        self.html_content = WebsiteFeatureExtrator.fetch_html_content(
            website_url)

        self.parsed_url = urlparse(self.website_url)
        self.extract_url = tldextract.extract(self.website_url)
        self.soup = BeautifulSoup(self.html_content, 'html.parser')

    @classmethod
    def fetch_html_content(cls, url):
        try:
            response = requests.get(url)
            response.raise_for_status()
            return response.text
        except requests.RequestException as e:
            print(f"An error occurred: {e}")
            return None

    def get_features(self):
        categorical_cols = ['AbnormalFormAction', 'SubdomainLevelRT', 'UrlLengthRT', 'PctExtResourceUrlsRT',
                            'AbnormalExtFormActionR', 'ExtMetaScriptLinkRT', 'PctExtNullSelfRedirectHyperlinksRT']

        features = self.extract_features()
        df = pd.DataFrame([features])

        # Aplica one-hot encoding
        df = pd.get_dummies(df, columns=categorical_cols)

        expected_columns = ['PctExtHyperlinks', 'PctExtNullSelfRedirectHyperlinksRT_-1.0',
                            'PctExtResourceUrls', 'FrequentDomainNameMismatch',
                            'PctNullSelfRedirectHyperlinks',
                            'PctExtNullSelfRedirectHyperlinksRT_1.0', 'NumDash',
                            'ExtMetaScriptLinkRT_0.0', 'NumNumericChars', 'PathLevel',
                            'InsecureForms', 'SubmitInfoToEmail', 'ExtMetaScriptLinkRT_1.0',
                            'NumDots', 'PathLength', 'UrlLength', 'NumQueryComponents',
                            'QueryLength', 'NumSensitiveWords', 'IframeOrFrame']

        for col in expected_columns:
            if col not in df.columns:
                df[col] = 0

        # Reordena as colunas
        df = df[expected_columns]

        scaler = joblib.load("detector/resources/scaler.pkl")
        df = scaler.transform(df)

        return df, features

    def extract_features(self):
        features = {}
        features.update(self.extract_url_features())
        features.update(self.extract_html_features())
        features.update(self.extract_external_features())

        return features

    def extract_url_features(self):
        list_tld = ['.com', 'org', '.net', '.xyz', '.name', '.biz', '.space', '.site', '.info', '.club', '.tech',
                    '.online', '.pro', '.app', '.dev', '.studio', '.agency', '.life', '.blog', '.cloud', '.link',
                    '.io', '.tv', '.gov', '.edu', '.int', '.mil', '.mobi', '.jobs', '.icu', '.tel', '.post',
                    '.asia', '.br', '.uk', '.es', '.us', '.ca', '.fr', '.in', '.cn', '.de', '.jp', '.pt']
        sensitive_words = ['secure', 'account', 'webscr',
                           'login', 'ebayisapi', 'signin', 'banking', 'confirm', 'senha', 'conta']

        return {
            'NumDots': self.website_url.count("."),
            'SubdomainLevel': 0 if not self.extract_url.subdomain else len(self.extract_url.subdomain.split(".")),
            'PathLevel': 0 if self.parsed_url.path.strip("/") == "" else len(self.parsed_url.path.strip("/").
                                                                             split("/")),
            'UrlLength': len(self.website_url),
            'NumDash': self.website_url.count("-"),
            'NumDashInHostname': self.parsed_url.hostname.count("-"),
            'AtSymbol': int("@" in self.website_url),
            'TildeSymbol': int("~" in self.website_url),
            'NumUnderscore': self.website_url.count("_"),
            'NumPercent': self.website_url.count("%"),
            'NumQueryComponents': 0 if self.parsed_url.query == "" else len(self.parsed_url.query.split("&")),
            'NumAmpersand': self.website_url.count("&"),
            'NumHash': self.website_url.count("#"),
            'NumNumericChars': sum(c.isdigit() for c in self.website_url),
            'NoHttps': int(not self.website_url.startswith("https://")),
            'RandomString': int(bool(re.search(r'[0-9a-fA-F]{5}', self.website_url))),
            'IpAddress': int(bool(re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', self.parsed_url.netloc))),
            'DomainInSubdomains': int(any(tld in self.extract_url.subdomain for tld in list_tld)),
            'DomainInPaths': int(any(tld in self.parsed_url.path for tld in list_tld)),
            'HttpsInHostname': int("https" in self.parsed_url.hostname),
            'HostnameLength': len(self.parsed_url.hostname),
            'PathLength': len(self.parsed_url.path),
            'QueryLength': len(self.parsed_url.query),
            'DoubleSlashInPath': int("//" in self.parsed_url.path),
            'NumSensitiveWords': sum(1 for word in sensitive_words if word in self.website_url),
            'SubdomainLevelRT': 1 if self.extract_url.subdomain.count(".") <= 1
            else (0 if self.extract_url.subdomain.count(".") == 2 else -1),
            'UrlLengthRT': 1 if len(self.website_url) < 54 else (0 if 54 < len(self.website_url) <= 75 else -1)
        }

    def extract_html_features(self):
        list_tags = self.soup.find_all(['meta', 'script', 'link'])
        total_tags = len(list_tags)

        total_ext_meta_script_link = sum(
            1 for tag in list_tags if (
                tag.get('content' if tag.name == 'meta' else 'src' if tag.name ==
                        'script' else 'href') is not None
                and "http" in tag.get('content' if tag.name == 'meta' else 'src' if tag.name == 'script' else 'href',
                                      '')
                and urlparse(tag.get(
                    'content' if tag.name == 'meta' else 'src' if tag.name == 'script' else 'href')).netloc !=
                self.parsed_url.netloc
            )
        )
        ratio_ext = total_ext_meta_script_link / total_tags
        ext_meta_script_link_rt = - \
            1 if ratio_ext < 0.17 else 0 if 0.17 <= ratio_ext <= 0.81 else 1

        total_hyperlinks = len(self.soup.find_all('a'))
        ext_null_self_redirect_hyperlinks = sum(1 for a in self.soup.find_all(
            'a') if a.get('href', '').startswith('#') or ("http" in a.get('href', '') and urlparse(
                a.get('href', '')).netloc != self.parsed_url.netloc))
        ratio_pct = ext_null_self_redirect_hyperlinks / total_hyperlinks
        pct_ext_null_self_redirect_hyperlinks_rt = - \
            1 if ratio_pct < 0.31 else 0 if 0.31 <= ratio_pct <= 0.67 else 1

        return {
            'MissingTitle': 0 if self.soup.title else 1,
            'RightClickDisabled': self.get_right_click_disabled(),
            'PopUpWindow': self.get_popup_window(),
            'SubmitInfoToEmail': int(bool(self.soup.find_all('a', href=lambda x: x and x.startswith('mailto:')))),
            'IframeOrFrame': int(bool(self.soup.find_all(['iframe', 'frame']))),
            'ImagesOnlyInForm': self.get_images_only_in_form(),
            'EmbeddedBrandName': self.get_embedded_brand_name(),
            'AbnormalExtFormActionR': self.get_abnormal_ext_form_action_r(),
            'ExtMetaScriptLinkRT': ext_meta_script_link_rt,
            'PctExtNullSelfRedirectHyperlinksRT': pct_ext_null_self_redirect_hyperlinks_rt
        }

    def extract_external_features(self):
        favicon = self.soup.find("link", rel="icon")
        ext_favicon = 1 if favicon and urlparse(
            favicon.get('href', '')).netloc != self.parsed_url.netloc else 0

        cont_insecure_forms = sum(1 for form in self.soup.find_all('form') if (not urlparse(
            form.get('action', '')).scheme
            and not self.parsed_url.scheme == 'https')
            or (urlparse(form.get('action', '')).scheme and not self.parsed_url.scheme == 'https'))
        insecure_forms = 1 if cont_insecure_forms >= 1 else 0
        relative_form_action = int(any(
            not urlparse(form.get('action')).scheme and not urlparse(
                form.get('action')).netloc
            for form in self.soup.find_all('form')
        ))
        ext_form_action = int(any(urlparse(form.get('action', '')).netloc !=
                                  self.parsed_url.netloc for form in self.soup.find_all('form')))
        abnormal_form_action = int(any(
            form.get('action', '') in [
                '#', 'about:blank', '', 'javascript:true']
            for form in self.soup.find_all('form')
        ))

        fake_link_in_status_bar = int(any(
            'window.status' in tag['onmouseover'] for tag in self.soup.find_all(attrs={"onmouseover": True})))

        return {
            'ExtFavicon': ext_favicon,
            'InsecureForms': insecure_forms,
            'RelativeFormAction': relative_form_action,  # verificar
            'ExtFormAction': ext_form_action,
            'AbnormalFormAction': abnormal_form_action,
            'PctExtResourceUrls': self.get_pct_ext_resource_urls(),
            'PctExtResourceUrlsRT': self.get_pct_ext_resource_urls(apply_threshold=True),
            'PctExtHyperlinks': self.get_pct_ext_hyperlinks(),
            'PctNullSelfRedirectHyperlinks': self.get_pct_null_self_redirect_hyperlinks(),
            'FrequentDomainNameMismatch': self.get_frequent_domain_name_mismatch(),
            'FakeLinkInStatusBar': fake_link_in_status_bar
        }

    def get_abnormal_ext_form_action_r(self):
        forms = self.soup.find_all('form')

        for form in forms:
            action_url = form.get('action', '')

            if action_url == '' or action_url == 'about:blank':
                return -1

            parsed_action_url = urlparse(action_url)
            if parsed_action_url.netloc and parsed_action_url.netloc != self.parsed_url.netloc:
                return 0

        return 1

    def get_images_only_in_form(self):
        forms = self.soup.find_all('form')

        for form in forms:
            text_content = form.stripped_strings
            img_tags = form.find_all('img')

            if not any(text_content) and img_tags:
                return int(True)

        return int(False)

    def get_popup_window(self):
        scripts = self.soup.find_all('script')

        for script in scripts:
            if script.string and 'window.open' in script.string:
                return int(True)

        tags_with_onclick = self.soup.find_all(attrs={"onclick": True})

        if any('window.open' in tag.get('onclick', '') for tag in tags_with_onclick):
            return int(True)

        return int(False)

    def get_right_click_disabled(self):
        scripts = self.soup.find_all('script')

        for script in scripts:
            if script.string and 'event.button==2' in script.string:
                return int(True)

        tags_with_oncontextmenu = self.soup.find_all(
            attrs={"oncontextmenu": True})

        if any('return false' in tag.get('oncontextmenu', '') for tag in tags_with_oncontextmenu):
            return int(True)

        return int(False)

    def get_embedded_brand_name(self):
        all_urls = [
            tag.get('href', '') for tag in self.soup.find_all(['a'])
        ]

        all_domain = [tldextract.extract(
            link).domain for link in all_urls if tldextract.extract(link).domain != ""]

        if all_domain:
            most_frequent_name = Counter(all_domain).most_common(1)[0][0]
            embedded_brand_name = int(
                most_frequent_name in self.extract_url.subdomain or most_frequent_name in self.parsed_url.path)
        else:
            embedded_brand_name = int(False)

        return embedded_brand_name

    def get_pct_ext_resource_urls(self, apply_threshold=False):
        all_urls = [
            tag.get('href', '') for tag in self.soup.find_all(['a', 'link'])
        ] + [
            tag.get('src', '') for tag in self.soup.find_all(['img', 'script'])
        ]

        total_urls = len(all_urls)
        external_urls = sum(1 for url in all_urls if urlparse(
            url).netloc and urlparse(url).netloc != self.parsed_url.netloc)

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

    def get_pct_ext_hyperlinks(self):
        hyperlinks = [a.get('href', '')
                      for a in self.soup.find_all('a', href=True)]
        count_hyperlink = 0
        total_links = len(hyperlinks)

        for link in hyperlinks:
            if "http" in link.lower() and urlparse(link).netloc != self.parsed_url.netloc:
                count_hyperlink += 1

        if total_links > 0:
            pct_null_self_redirect = count_hyperlink / total_links
        else:
            pct_null_self_redirect = 0

        return pct_null_self_redirect

    def get_pct_null_self_redirect_hyperlinks(self):
        all_links = [tag.get('href', '') for tag in self.soup.find_all('a')]

        total_links = len(all_links)
        null_self_redirect_hyperlinks = sum(
            1 for link in all_links if
            link == '' or link == '#' or link == self.parsed_url or (
                link is not None and link.startswith('file://'))
        )

        pct_null_self_redirect_hyperlinks = null_self_redirect_hyperlinks / \
            total_links if total_links > 0 else 0

        return pct_null_self_redirect_hyperlinks

    def get_frequent_domain_name_mismatch(self):
        hyperlinks = [a.get('href', '')
                      for a in self.soup.find_all('a', href=True)]

        domains = [urlparse(link).netloc for link in hyperlinks if urlparse(
            link).netloc != ""]
        domain_count = Counter(domains)
        most_frequent_domain = domain_count.most_common(
            1)[0][0] if domain_count else ""

        site_domain = self.parsed_url.netloc
        return 1 if most_frequent_domain and most_frequent_domain != site_domain else 0
