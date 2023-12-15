# Table of Contents
1. [How to Set Up](#how-to-set-up)
   - [Pre-requisites](#pre-requisites-the-server-must-be-on-please-check-backend-readme)
   - [Install NVM](#1-install-nvm)
     - [Windows](#windows)
     - [Linux](#linux)
   - [Install Node 20.10.0](#2-install-node-20100)
   - [Install Dependencies](#3-install-dependencies)
   - [Build After Changes](#4-build-after-changes)
   - [Browser Extension Setup](#5-browser-extension-setup)
2. [Project Structure and Key Files](#project-structure-and-key-files)
   - [package.json](#packagejson)
   - [manifest.json](#manifestjson)
   - [src/background.js](#srcbackgroundjs)

# How to Set Up

- Pre-requisites: the server must be on. Please check [Backend README](backend/README.md).

1. Install NVM

   - Windows: [https://github.com/coreybutler/nvm-windows/releases](https://github.com/coreybutler/nvm-windows/releases)
   - Linux: [https://github.com/nvm-sh/nvm#installing-and-updating](https://github.com/nvm-sh/nvm#installing-and-updating)

2. Install Node 20.10.0

```
nvm install 20.10.0
nvm use 20.10.0
```

3. Install dependencies

```
npm install
```

4. After every code change, run in the frontend folder:

```
npm run build
```

5. Go to the "Extensions" section of your browser. Enable developer mode and import the frontend folder from this repository.

- Extension tested in Microsoft Edge, Google Chrome, and Mozilla Firefox.

# Project Structure and Key Files

- **package.json:** contains all the libraries that are being used.
- **manifest.json:** responsible for declaring the browser extension.
- **src/background.js** responsible for calling the API everytime the user enters in a new website.
