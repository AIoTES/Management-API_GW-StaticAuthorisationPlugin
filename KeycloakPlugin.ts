import * as eg from 'express-gateway';
//@ts-ignore
import {createLoggerWithLabel} from 'express-gateway/lib/logger';
//@ts-ignore
import {parse, stringify} from 'flatted/esm';
import * as Keycloak from 'keycloak-connect';
import * as session from 'express-session';
import * as createMemoryStore from 'memorystore';
import Flatted = require("flatted");

interface KeycloakPluginSettings {
    session: session.SessionOptions;
    keycloakConfig: object;
    keycloakConfigRS?: object;
    paths: string[];
    registerName: string;
}

interface ActionParamsProtect {
    jsProtect?: string;
    jsProtectTokenVar?: string;
    role?: string;
}

interface ActionParamsEnforce {
    permissions: string;
    response_mode?: string;
    resource_server_id?: string;
}

interface ActionParamsValidate {
    permissions: string;
}

const memoryStore = createMemoryStore(session);

const DEFAULT_KEYCLOAK_PLUGIN_SETTINGS: KeycloakPluginSettings = {
    session: {
        secret: 'kc_secret',
    },
    keycloakConfig: {},
//    keycloakConfigRS: {},
    registerName: 'keycloak-activage-protect',
    paths: ['/'],
};

const keycloakPlugin: eg.ExpressGateway.Plugin = {
    version: '1.2.0',
    policies: ["keycloak-protect", "keycloak-enforce", "rpt-validate"],
    init: (ctx: eg.ExpressGateway.PluginContext) => {
        // this is slightly dodgy casting, as they don't expose settings on the public interface - but not sure how else you can access custom settings for a plugin
        const sessionStore = new memoryStore();

        //@ts-ignore
        const rawSettings: KeycloakPluginSettings = (ctx as eg.ExpressGateway.PluginContext).settings;

        const sessionSettings = {
            ...DEFAULT_KEYCLOAK_PLUGIN_SETTINGS.session,
            ...rawSettings.session,
            store: sessionStore
        };

        const keycloakConfig = {
            ...DEFAULT_KEYCLOAK_PLUGIN_SETTINGS.keycloakConfig,
            ...rawSettings.keycloakConfig,
        };
        const keycloakConfigRS = {
            ...DEFAULT_KEYCLOAK_PLUGIN_SETTINGS.keycloakConfigRS,
            ...rawSettings.keycloakConfigRS,
        };
        const pluginSettings: KeycloakPluginSettings = {
            //@ts-ignore
            session: sessionSettings, keycloakConfig, keycloakConfigRS,
            registerName: rawSettings.registerName || DEFAULT_KEYCLOAK_PLUGIN_SETTINGS.registerName,
            paths: rawSettings.paths || DEFAULT_KEYCLOAK_PLUGIN_SETTINGS.paths,
        };

        const keycloak = new Keycloak(
            {store: sessionStore},
            pluginSettings.keycloakConfig
        );
        const keycloakRS = new Keycloak(
            {store: sessionStore},     // not used
            pluginSettings.keycloakConfigRS
        );
        const logger = createLoggerWithLabel(
            '[EG:plugin:' + pluginSettings.registerName + ']'
        );

        logger.debug('Init ' + pluginSettings.registerName);
        logger.info(
            `Initialized Keycloak Plugin with settings: ${JSON.stringify(
                pluginSettings,
                null,
                '\t'
            )}`
        );

        keycloak.authenticated = req => {
//        Keycloak.authenticated = req => {
            const keyR = req as Keycloak.GrantedRequest;
            const grant = keyR.kauth.grant as Keycloak.Grant;
            logger.debug('Request {');
            logger.debug('method: ' + Flatted.stringify(req.method));
            logger.debug('url: ' + Flatted.stringify(req.originalUrl));
            logger.debug('headers: ' + Flatted.stringify(req.headers));
            logger.debug('body: ' + Flatted.stringify(req.body));
            logger.debug('}');
            logger.info(
                '-- Keycloak Authenticated: ' +
                JSON.stringify(grant.access_token.content, null, '\t')
            );
        };

        keycloak.accessDenied = (req, res) => {
//        Keycloak.accessDenied = (req, res) => {
            logger.warn('-- Keycloak Access Denied.');
            logger.debug('Request {');
            logger.debug('method: ' + Flatted.stringify(req.method));
            logger.debug('url: ' + Flatted.stringify(req.originalUrl));
            logger.debug('headers: ' + Flatted.stringify(req.headers));
            logger.debug('body: ' + Flatted.stringify(req.body));
            logger.debug('}');
            res.status(403).end('Access Denied');
        };

	// override of keycloak.checkPermissions function, needed by the front-end app to use
	//  the obtained RPT (grant) as the new access token; prototype in keycloak-connect/index.js)
        //@ts-ignore
	keycloak.checkPermissions = function (authzRequest, request, callback) {
            // var grantedReq = request as Keycloak.GrantedRequest;
            // var reqGrant = grantedReq.kauth.grant as Keycloak.Grant;
	    logger.debug("OVERRIDE start");
            //@ts-ignore
	    return keycloak.grantManager.checkPermissions(authzRequest, request, callback)
	        //@ts-ignore
		.then(function (grant) {
		    logger.debug("KC checkPermissions: got grant");
		    if (!authzRequest.response_mode) { // i.e. the authz request was issued with a response_mode 'token')
			// keycloak.storeGrant(grant, request);  // no need to store
            		//@ts-ignore
			request.kauth.grant = grant;
			// reqGrant = grant; // this does not work: value assigned by reference but the reference is to the value, not the variable...
			logger.debug("KC checkPermissions: grant stored in request.kauth ");
			//@ts-ignore
			logger.debug("KC checkPermissions grant: " + JSON.stringify(request.kauth.grant.access_token.token, null, "\t"));
			
		    }
		    return grant;
		});
	};

        keycloakRS.accessDenied = (req, res) => {
            logger.warn('-- Keycloak Access Denied.');
            logger.debug('Request {');
            logger.debug('method: ' + Flatted.stringify(req.method));
            logger.debug('url: ' + Flatted.stringify(req.originalUrl));
            logger.debug('headers: ' + JSON.stringify(req.headers));
            logger.debug('body: ' + Flatted.stringify(req.body));
            logger.debug('}');
            res.status(403).end('Access Denied');
        };
	
	// setup our keycloak middleware
        ctx.registerGatewayRoute(app => {
            logger.info('Registering Keycloak Middleware');
            app.use(pluginSettings.paths, session(pluginSettings.session));
            app.use(pluginSettings.paths, keycloak.middleware());
        });

        ctx.registerPolicy({
            name: 'keycloak-protect',
            schema: {
                $id: 'http://express-gateway.io/schemas/policies/keycloak-protect.json',
                type: 'object',
                properties: {
                    role: {
                        description: 'the keycloak role to restrict access to',
                        type: 'string',
                    },
                    jsProtectTokenVar: {
                        description:
                            'the keycloak token variable name to reference the token in jsProtect',
                        type: 'string',
                    },
                    jsProtect: {
                        description: 'a js snippet to apply for whether a user has access.',
                        type: 'string',
                    },
                },
            },
            policy: (actionParams: ActionParamsProtect) => {
                logger.info('Initializing keycloak-protect policy ');
                logger.info('Keycloak Protect action params → ' + JSON.stringify(actionParams, null, '\t'));
                if (actionParams.jsProtect) {
                    return keycloak.protect(
                        (token: Keycloak.Token, request) => {

                            logger.info('Keycloak user authenticated');
                            logger.info('Evaluating ' + actionParams.jsProtect);
                            logger.debug('Request {' +
                                '\n\t method: ' + JSON.stringify(request.method, null, '\t') +
                                '\n\t url: ' + JSON.stringify(request.originalUrl, null, '\t') +
                                '\n\t headers: ' + JSON.stringify(request.headers, null, '\t\t') +
                                '\n\t body: ' + JSON.stringify(request.body, null, '\t') +
                                '\n}');

                            logger.debug('Token {' +
                                '\n\t method: ' + JSON.stringify(token.clientId, null, '\t') +
                                '\n\t content: ' + JSON.stringify(token.content, null, '\t\t') +
                                '\n}');

                            //@ts-ignore
                            request.egContext[actionParams.jsProtectTokenVar || 'token'] = token;
                            //@ts-ignore
                            const runResult = request.egContext.run(actionParams.jsProtect);
                            logger.info('Keycloak Protect JS Result: ' + runResult);
                            return runResult;
                        }
                    );
                } else if (actionParams.role) {
                    return keycloak.protect(
                        (token: Keycloak.Token, request) => {

                            logger.info('Keycloak user authenticated');
                            logger.info('Evaluating user has role ' + actionParams.role);
                            logger.debug('Request {' +
                                '\n\t method: ' + JSON.stringify(request.method, null, '\t') +
                                '\n\t url: ' + JSON.stringify(request.originalUrl, null, '\t') +
                                '\n\t headers: ' + JSON.stringify(request.headers, null, '\t\t') +
                                '\n\t body: ' + JSON.stringify(request.body, null, '\t') +
                                '\n}');

                            logger.debug('Token {' +
                                '\n\t method: ' + JSON.stringify(token.clientId, null, '\t') +
                                '\n\t content: ' + JSON.stringify(token.content, null, '\t\t') +
                                '\n}');

                            //@ts-ignore
                            request.egContext[actionParams.jsProtectTokenVar || 'token'] = token;

                            //@ts-ignore
                            const runResult = request.egContext.run('token.hasRole(\"' + actionParams.role + '\")');
                            logger.debug('Keycloak Protect Evaluation condition: token.hasRole(\"' + actionParams.role + '\")');
                            logger.info('Keycloak Protect Result: ' + runResult);
                            return runResult;
                        }
                    );
                }
                return keycloak.protect(
                    (token: Keycloak.Token, request) => {

                        logger.info('Keycloak user authenticated');
                        logger.debug('Request {' +
                            '\n\t method: ' + JSON.stringify(request.method, null, '\t') +
                            '\n\t url: ' + JSON.stringify(request.originalUrl, null, '\t') +
                            '\n\t headers: ' + JSON.stringify(request.headers, null, '\t\t') +
                            '\n\t body: ' + JSON.stringify(request.body, null, '\t') +
                            '\n}');

                        logger.debug('Token {' +
                            '\n\t method: ' + JSON.stringify(token.clientId, null, '\t') +
                            '\n\t content: ' + JSON.stringify(token.content, null, '\t\t') +
                            '\n}');

                        return true;
                    }
                );
            },
        });

        ctx.registerPolicy({
            name: 'keycloak-enforce',
            schema: {
                $id: "http://express-gateway.io/schemas/policies/keycloak-enforce.json",
                type: "object",
                properties: {
                    permissions: {
                        description: "the resource or permissions, ex: \'resource_name:scope\'",
                        type: "string"
                    },
                    response_mode: {
                        description: "the enforcer mode to use; values: \'permissions\'(default) or \'token\'",
                        type: "string"
                    },
                    resource_server: {
                        description: "the resource server name in keycloak",
                        type: "string"
                    }
                }
            },
            policy: (actionParams: ActionParamsEnforce) => {
                logger.info('Initializing keycloak-enforce policy ');
                logger.info('Keycloak Enforce action params → ' + JSON.stringify(actionParams, null, '\t'));
                //@ts-ignore
                return keycloak.enforcer(
                    actionParams.permissions,
                    {
                        response_mode: actionParams.response_mode,
                        resource_server_id: actionParams.resource_server_id
                    }
                );
            },
        });

        ctx.registerPolicy( {
            name: 'rpt-validate',
            schema: {
                $id: "http://express-gateway.io/schemas/policies/rpt-validate.json",
                type: "object",
                properties: {
		    permissions: {
			description: "the resource or permissions, ex: \'item:scope\'",
			type: "string"
		    }
                }
            },
            policy: (actionParams: ActionParamsValidate) => {
                logger.info('Initializing rpt-validate policy ');
                logger.info('RPT validate action params → ' + JSON.stringify(actionParams, null, '\t'));
		let expectedPermissions = actionParams.permissions;
		if (typeof expectedPermissions === 'string') {
	    	   //@ts-ignore
		   expectedPermissions = [expectedPermissions];
		}		
		return (req, res, next) => {
		    var grantedReq = req as Keycloak.GrantedRequest;
		    if (grantedReq.kauth && grantedReq.kauth.grant && grantedReq.kauth.grant.access_token) {
		        var reqGrant = grantedReq.kauth.grant as Keycloak.Grant;
			//@ts-ignore
			return keycloakRS.grantManager.validateToken(reqGrant.access_token, 'Bearer')
			    .then(function() {				
				logger.debug("-- RPT VALIDATED, now checking permissions");

				if (!expectedPermissions || expectedPermissions.length === 0) {
				    // no resources named in the RPT validator parameters: DON'T GIVE ACCESS BUT BLOCK (original code lets go by calling next())
				    logger.warn("-- No expected resources in resource server configuration: Denying access");
				    return keycloakRS.accessDenied(grantedReq, res);
				}

				// the code in the loop is extracted from handlePermissions function in enforcer.js
				for (let i = 0; i < expectedPermissions.length; i++) {
				    const expected = expectedPermissions[i].split(':');
				    const resource = expected[0];
				    let scope;
				    if (expected.length > 1) {
					scope = expected[1];
				    }
				    logger.debug("-- Checking permission: " + resource + ", scope: " + scope);
				    //@ts-ignore
				    if (!reqGrant.access_token.hasPermission(resource, scope)) {
					logger.info("Access Denied. -- Permission is not granted in RPT");
					logger.debug(" -- RPT: " + reqGrant.access_token.token);
					//@ts-ignore
					return keycloakRS.accessDenied(req, res);
				    }
				}
				
				return next();
				
			    //@ts-ignore
			    }).catch(function (err) {
				logger.info("Access Denied. -- RPT not valid: " + err.message);
				// could refine here: if RPT just expired, get a permissions ticket ? - Actually, not needed because a fresh RPT is provided by eg-client-webapp
				//@ts-ignore
				return keycloakRS.accessDenied(req, res);
			    });
		    }
		    // case: no RPT
		    logger.info("Access Denied. -- RPT not present in request");
		    //@ts-ignore
		    return keycloakRS.accessDenied(req, res);

		};
	    }
        });


    },
    schema: {
        $id: 'http://express-gateway.io/schemas/plugin/keycloak.json',
        type: 'object',
        properties: {
            registerName: {
                title: 'Registring name',
                description: 'Multi keycloak feature',
                type: 'string',
            },
            paths: {
                title: 'Paths to apply protection',
                description: 'url paths to apply protection',
                type: 'array',
            },
            session: {
                title: 'Session Settings',
                description: 'Session Settings as outlined by express middleware',
                type: 'object',
            },
            keycloakConfig: {
                title: 'Keycloak Configuration',
                description:
                    'This can be used rather than requiring keycloak.json to be present',
                type: 'object',
            },
        },
    },
};

export {
    KeycloakPluginSettings as IKeycloakPluginSettings,
    DEFAULT_KEYCLOAK_PLUGIN_SETTINGS as DefaultKeycloakPluginSettings,
    keycloakPlugin as KeycloakPlugin,
    keycloakPlugin as default,
};
