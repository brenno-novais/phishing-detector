import Strings from './helpers/strings.tsx';
import { WebsiteClassification } from './helpers/enums.tsx';

const axios = require('axios');

chrome.tabs.onUpdated.addListener(function(tabId, changeInfo, tab) {
    if (changeInfo.url) {
        const urlObj = new URL(changeInfo.url);
        const mainUrl = urlObj.protocol + "//" + urlObj.hostname;
        checkWebsite(mainUrl);
    }
});

function checkWebsite(websiteUrl) {
    const apiUrl = 'http://localhost:8000/api/v1/detect';

    axios.get(apiUrl, {
        params: {
            website_url: websiteUrl
        }
    })
    .then(response => {
        if (response.data.result === WebsiteClassification.PHISHING)
            chrome.notifications.create({
                type: 'basic',
                iconUrl: './src/icons/warning.png',
                title: Strings.notifications.attention,
                message: Strings.notifications.phishingProbability(response.data.probability)
            });
    })
    .catch(error => {
        console.error(Strings.classificationError, error);
    });
}
