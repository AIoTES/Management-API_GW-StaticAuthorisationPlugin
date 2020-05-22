FROM express-gateway

COPY  express-gateway-keycloak.tgz /usr/local/plugins/express-gateway-keycloak.tgz

RUN yarn global add /usr/local/plugins/express-gateway-keycloak.tgz

ADD docker-entrypoint.sh /bin/docker-entrypoint.sh
RUN chmod a+x /bin/docker-entrypoint.sh
#USER node
CMD /bin/docker-entrypoint.sh
