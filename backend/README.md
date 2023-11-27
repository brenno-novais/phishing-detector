# Como montar o setup

1. Instalar e configurar o [Python (3.10.0)](https://www.python.org/downloads/release/python-3100/)

2. Clonar este repositório e ir para a pasta backend.

3. Criar um virtual environment. Para isso, digite no prompt de comando, na pasta onde você clonou o repositório:

```
pip install pipenv
```

4. Após isso, ative o venv, digitando:

```
pipenv shell
```

> Obs: Rodar o pipenv shell é necessário toda vez que for usar o setup

5. Rode o comando abaixo para instalar todas as dependências do projeto:

```
pipenv install
```

# Como ligar o servidor

1. Rode o comando:

```
cd backend
python manage.py runserver
```

> Obs: É necessário que o pipenv shell esteja ativado

É esperado que o terminal imprima a seguinte mensagem:

```
Watching for file changes with StatReloader
Performing system checks...

System check identified no issues (0 silenced).
October 12, 2023 - 19:57:24
Django version 4.2.6, using settings 'phishing_detector.settings'
Starting development server at http://127.0.0.1:8000/
Quit the server with CTRL-BREAK.
```

# Como extrair e classificar um site

Há duas formas de classificar um site:

1. A primeira forma não precisa ligar o servidor, basta rodar o comando a seguir na basta backend e com o pipenv shell ativado:

```
python manage.py classify --website_url <url_do_site>
```

> Exemplo: `python manage.py classify --website_url https://www.google.com/`

2. A segunda forma é com o servidor ligado. Essa é a forma que será usada em produção.
   - É necessário instalar o [Postman](https://www.postman.com/downloads/) para fazer as chamadas à API.
   - Crie uma conta.
   - Importe a coleção do Postman na pasta [postman](../postman).
   - Crie um environment com uma variável url com o valor http://127.0.0.1:8000
   - Selecione esse environment e clique na API que foi importada pela coleção: GET Classify Website.
   - Clique em Send para enviar uma requisição à API.
   - Altere o site que deseja classificar na variável website_url em Params.
   - O resultado esperado é:

```
{
    "message": "Esse site tem 99.5% de chance de ser legítimo."
}
```
