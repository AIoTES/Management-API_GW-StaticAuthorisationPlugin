# Activage Express-gateway-Keycloak plugin

This project is a plugin to integrate [Keycloak NodeJS Adapter](https://github.com/keycloak/keycloak-nodejs-connect/) in [Express-Gateway](https://www.express-gateway.io/)

This project has been developed using the repository [Keycloak plugins for Express-gateway](https://github.com/gitfish/express-gateway-keycloak) as codebase.

## Usage

TODO

## Development

* Installation
- Install dependencies

```bash
npm install
```

* Compilation
- Create build directory with full plugin version

```bash
npm run compile
``` 

* Package
- Compress build directory to express-gateway-keycloak.tgz file

```bash
npm run package
``` 

* Build
- Cleans build directory and runs compile and package sequentially 

```bash
npm run build
``` 

* BuildDocker
- Runs build and creates a new docker image using Dockerfile

```bash
npm run buildDocker
``` 

## Changelog

### v1.16.7-debug
- Repository setup
- Include more logs
- New enforce policy defined based on Corinne work


## License

* [Apache License, Version 2.0](https://www.apache.org/licenses/LICENSE-2.0)