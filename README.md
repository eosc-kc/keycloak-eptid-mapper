# keycloak eduPersonTargetedID mapper

A pluggable IdP mapper for eduPersonTargetedID in keycloak. To be used in eosc installations.

## Installation instructions:

1. Compile the plugin jar i.e. 'mvn clean install' or just get a built one from the "Releases" link on the right sidebar.
2. Drop the jar into the folder $KEYCLOAK_BASE/standalone/deployments/ and let all the hot-deploy magic commence.

## Use instructions

If the installation is successful, you will be able to use the SAML IdentityProvider mapper **EduPersonTargetedID Mapper**. Configuration options are same as in SAML Attribute Importer Mapper.
Default values:
- urn:oasis:names:tc:SAML:2.0:attrname-format:uri for Name Format
- eduPersonTargetedID for Friendly Name Format
- eduPersonTargetedID for User Attribute Name
