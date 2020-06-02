interface IKeycloakPluginSettings {
    session?: any;
    keycloakConfig?: any;
    keycloakConfigRS?: any;
}
declare const DefaultKeycloakPluginSettings: IKeycloakPluginSettings;
declare const KeycloakPlugin: ExpressGateway.Plugin;
export { IKeycloakPluginSettings, DefaultKeycloakPluginSettings, KeycloakPlugin, KeycloakPlugin as default };
