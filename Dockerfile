FROM express-gateway

COPY  express-gateway-keycloak.tgz /usr/local/plugins/express-gateway-keycloak.tgz

RUN yarn global add /usr/local/plugins/express-gateway-keycloak.tgz
