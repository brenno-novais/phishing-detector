# Table of Contents
1. [How to Set Up](#how-to-set-up)
   - [Install Python](#1-install-and-configure-python-3100)
   - [Clone Repository](#2-clone-this-repository-and-go-to-the-backend-folder)
   - [Create Virtual Environment](#3-create-a-virtual-environment)
   - [Activate Virtual Environment](#4-activate-the-virtual-environment)
   - [Install Dependencies](#5-install-dependencies)
2. [How to Start the Server](#how-to-start-the-server)
   - [Start Command](#1-run-the-command)
   - [Expected Terminal Output](#expected-terminal-output)
3. [How to Extract and Classify a Website](#how-to-extract-and-classify-a-website)
   - [Without Server](#1-the-first-way)
   - [With Server](#2-the-second-way)
4. [Project Structure and Key Files](#project-structure-and-key-files)
   - [PIPFILE](#pipfile)
   - [Classifier](#detectorclassifierpy)
   - [Feature Extractor](#detectorfeature_extractorpy)
   - [API Views](#detectorviewspy)
   - [Resources](#detectorresources)
   - [Command for Classification](#detectormanagementcommandsclassifypy)
   - [Tests](#detectortestspy)

# How to Set Up

1. Install and configure [Python (3.10.0)](https://www.python.org/downloads/release/python-3100/)

2. Clone this repository and go to the backend folder.

3. Create a virtual environment. To do this, type in the command prompt, in the folder where you cloned the repository:


```
pip install pipenv
```

4. After that, activate the virtual environment by typing:

```
pipenv shell
```

> Note: Running `pipenv shell` is necessary every time you use the setup.

5. Run the command below to install all project dependencies:

```
pipenv install
```

# How to Start the Server

1. Run the command:


```
cd backend
python manage.py runserver
```

> Note: It is necessary that the `pipenv shell` is active

The terminal is expected to print the following message:

```
Watching for file changes with StatReloader
Performing system checks...

System check identified no issues (0 silenced).
October 12, 2023 - 19:57:24
Django version 4.2.6, using settings 'phishing_detector.settings'
Starting development server at http://127.0.0.1:8000/
Quit the server with CTRL-BREAK.
```

# How to Extract and Classify a Website

There are two ways to classify a website:

1. The first way does not need to start the server, just run the following command in the backend folder with the `pipenv shell` active:

```
python manage.py classify --website_url <url_do_site>
```

> Example: `python manage.py classify --website_url https://www.google.com/`

2. The second way is with the server running. This is the way it will be used in production.
- It is necessary to install [Postman](https://www.postman.com/downloads/) to make calls to the API.
- Create an account.
- Import the Postman collection from the [postman](../postman) folder.
- Create an environment with a url variable set to http://127.0.0.1:8000
- Select this environment and click on the API that was imported by the collection: GET Classify Website.
- Click Send to send a request to the API.
- Change the site you want to classify in the website_url variable in Params.
- The expected result is:

```
{
    "message": "Esse site tem chance considerável de ser legítimo.",
    "result": "LEGITIMATE";
    "probability": "92.0%"
}
```
> Note: "Esse site tem chance considerável de ser legítimo." means "This site has a considerable chance of being legitimate.".

# Project Structure and Key Files

- **PIPFILE:** contains all the libraries that are being used.
- **detector/classifier.py:** is where the Random Forest model will be loaded and the website will be classified.
- **detector/feature_extractor.py:** is where the features necessary to classify the website will be extract.
- **detector/views.py:** is where the API is being declared. This where the backend gets the website url, calls for the extrator, the calls the classifier and then return the results.
- **detector/resources:** this folders contain the file where the Random Forest model and the scaler (responsible for normalizing the data) is stored. If you want to use your own model or scale, substitute this files and change the path which opens then if necessary.
- **detector/management/commands/classify.py:** this is the command you use to classify your websites without the server to be on. See "How to Extract and Classify a Website", first item, above to learn more details.
- **detector/tests.py:** this is where the tests are gonna be declared.
