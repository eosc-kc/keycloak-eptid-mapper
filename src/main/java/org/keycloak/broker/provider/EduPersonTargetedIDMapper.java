package org.keycloak.broker.provider;

import java.io.StringWriter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Objects;
import java.util.Set;
import java.util.function.Consumer;
import java.util.function.Predicate;
import java.util.function.Supplier;
import java.util.stream.Collectors;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamWriter;

import org.keycloak.broker.saml.SAMLEndpoint;
import org.keycloak.broker.saml.SAMLIdentityProviderFactory;
import org.keycloak.broker.saml.mappers.UserAttributeMapper;
import org.keycloak.common.util.CollectionUtil;
import org.keycloak.dom.saml.v2.assertion.AssertionType;
import org.keycloak.dom.saml.v2.assertion.AttributeStatementType;
import org.keycloak.dom.saml.v2.assertion.AttributeType;
import org.keycloak.dom.saml.v2.assertion.NameIDType;
import org.keycloak.dom.saml.v2.metadata.AttributeConsumingServiceType;
import org.keycloak.dom.saml.v2.metadata.EntityDescriptorType;
import org.keycloak.dom.saml.v2.metadata.RequestedAttributeType;
import org.keycloak.models.IdentityProviderMapperModel;
import org.keycloak.models.IdentityProviderSyncMode;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.protocol.saml.mappers.SamlMetadataDescriptorUpdater;
import org.keycloak.provider.ProviderConfigProperty;
import org.keycloak.saml.common.constants.JBossSAMLConstants;
import org.keycloak.saml.common.constants.JBossSAMLURIConstants;
import org.keycloak.saml.common.exceptions.ProcessingException;
import org.keycloak.saml.common.util.StaxUtil;
import org.keycloak.saml.common.util.StringUtil;
import org.keycloak.saml.processing.core.saml.v2.writers.SAMLMetadataWriter;

import static org.keycloak.saml.common.constants.JBossSAMLURIConstants.ASSERTION_NSURI;
import static org.keycloak.saml.common.constants.JBossSAMLURIConstants.ATTRIBUTE_FORMAT_BASIC;

public class EduPersonTargetedIDMapper extends AbstractIdentityProviderMapper implements SamlMetadataDescriptorUpdater {

    public static final String[] COMPATIBLE_PROVIDERS = {SAMLIdentityProviderFactory.PROVIDER_ID};

    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

    protected static String ASSERTION_PREFIX = "saml2";
    protected static String ATTRIBUTE_NAME_DEFAULT ="urn:oid:1.3.6.1.4.1.5923.1.1.1.10";
    protected static String ATTRIBUTE_FRIENDLY_NAME_DEFAULT ="eduPersonTargetedID";
    protected static String USER_ATTRIBUTE_DEFAULT ="eduPersonTargetedID";
    protected static final String ATTRIBUTE_NAME = "attribute.name";
    protected static final String ATTRIBUTE_FRIENDLY_NAME = "attribute.friendly.name";
    protected static final String ATTRIBUTE_NAME_FORMAT = "attribute.name.format";
    protected static final String USER_ATTRIBUTE = "user.attribute";
    private static final Set<IdentityProviderSyncMode> IDENTITY_PROVIDER_SYNC_MODES = new HashSet<>(Arrays.asList(IdentityProviderSyncMode.values()));

    public static final List<String> NAME_FORMATS = Arrays.asList(JBossSAMLURIConstants.ATTRIBUTE_FORMAT_BASIC.name(), JBossSAMLURIConstants.ATTRIBUTE_FORMAT_URI.name(), JBossSAMLURIConstants.ATTRIBUTE_FORMAT_UNSPECIFIED.name());
    static {
        ProviderConfigProperty property;
        property = new ProviderConfigProperty();
        property.setName(ATTRIBUTE_NAME);
        property.setLabel("Attribute Name");
        property.setHelpText("Name of attribute to search for in assertion.  You can leave this blank and specify a friendly name instead. Default to urn:oid:1.3.6.1.4.1.5923.1.1.1.10 .");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setDefaultValue(ATTRIBUTE_NAME_DEFAULT);
        configProperties.add(property);
        property = new ProviderConfigProperty();
        property.setName(ATTRIBUTE_FRIENDLY_NAME);
        property.setLabel("Friendly Name");
        property.setHelpText("Friendly name of attribute to search for in assertion.  You can leave this blank and specify a name instead. Default to eduPersonTargetedID.");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setDefaultValue(ATTRIBUTE_FRIENDLY_NAME_DEFAULT);
        configProperties.add(property);
        property = new ProviderConfigProperty();
        property.setName(ATTRIBUTE_NAME_FORMAT);
        property.setLabel("Name Format");
        property.setHelpText("Name format of attribute to specify in the RequestedAttribute element. Default to uri format.");
        property.setType(ProviderConfigProperty.LIST_TYPE);
        property.setOptions(NAME_FORMATS);
        property.setDefaultValue(JBossSAMLURIConstants.ATTRIBUTE_FORMAT_URI.name());
        configProperties.add(property);
        property = new ProviderConfigProperty();
        property.setName(USER_ATTRIBUTE);
        property.setLabel("User Attribute Name");
        property.setHelpText("User attribute name to store saml attribute. Default to eduPersonTargetedID.");
        property.setType(ProviderConfigProperty.STRING_TYPE);
        property.setDefaultValue(USER_ATTRIBUTE_DEFAULT);
        configProperties.add(property);
    }

    public static final String PROVIDER_ID = "edu-person-targetedid-mapper";

    @Override
    public boolean supportsSyncMode(IdentityProviderSyncMode syncMode) {
        return IDENTITY_PROVIDER_SYNC_MODES.contains(syncMode);
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }

    @Override
    public String[] getCompatibleProviders() {
        return COMPATIBLE_PROVIDERS;
    }

    @Override
    public String getDisplayCategory() {
        return "EduPersonTargetedID Mapper";
    }

    @Override
    public String getDisplayType() {
        return "EduPersonTargetedID Mapper";
    }

    @Override
    public void preprocessFederatedIdentity(KeycloakSession session, RealmModel realm, IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
        String attribute = mapperModel.getConfig().get(USER_ATTRIBUTE);
        if (StringUtil.isNullOrEmpty(attribute)) {
            return;
        }
        String attributeName = getAttributeNameFromMapperModel(mapperModel);

        List<String> attributeValuesInContext = findAttributeValuesInContext(attributeName, context);
        if (!attributeValuesInContext.isEmpty()) {
           context.setUserAttribute(attribute, attributeValuesInContext);
        }
    }

    private String getAttributeNameFromMapperModel(IdentityProviderMapperModel mapperModel) {
        String attributeName = mapperModel.getConfig().get(ATTRIBUTE_NAME);
        if (attributeName == null) {
            attributeName = mapperModel.getConfig().get(ATTRIBUTE_FRIENDLY_NAME);
        }
        return attributeName;
    }

    private Predicate<AttributeStatementType.ASTChoiceType> elementWith(String attributeName) {
        return attributeType -> {
            AttributeType attribute = attributeType.getAttribute();
            return Objects.equals(attribute.getName(), attributeName)
                    || Objects.equals(attribute.getFriendlyName(), attributeName);
        };
    }


    private List<String> findAttributeValuesInContext(String attributeName, BrokeredIdentityContext context) {
        AssertionType assertion = (AssertionType) context.getContextData().get(SAMLEndpoint.SAML_ASSERTION);

        return assertion.getAttributeStatements().stream()
                .flatMap(statement -> statement.getAttributes().stream())
                .filter(elementWith(attributeName))
                .flatMap(attributeType -> attributeType.getAttribute().getAttributeValue().stream())
                .map(val -> {
                    String strVal= null;
                    if ( val != null && val instanceof NameIDType) {
                        StringWriter sw = new StringWriter();
                        NameIDType nameIDType=(NameIDType) val;
                        try {
                            XMLStreamWriter writer = StaxUtil.getXMLStreamWriter(sw);
                            SAMLMetadataWriter metadataWriter = new SAMLMetadataWriter(writer);
                            metadataWriter.write(nameIDType,new QName(ASSERTION_NSURI.get(), JBossSAMLConstants.NAMEID.get(), ASSERTION_PREFIX));
                            strVal = sw.toString();
                        } catch (ProcessingException e) {
                            e.printStackTrace();
                        }
                    } else  if ( val != null && val instanceof String) {
                        strVal = (String) val;
                    }
                    return strVal;
                })
                .filter(Objects::nonNull)
                .collect(Collectors.toList());
    }

    @Override
    public void updateBrokeredUser(KeycloakSession session, RealmModel realm, UserModel user, IdentityProviderMapperModel mapperModel, BrokeredIdentityContext context) {
        String attribute = mapperModel.getConfig().get(USER_ATTRIBUTE);
        if (StringUtil.isNullOrEmpty(attribute)) {
            return;
        }
        String attributeName = getAttributeNameFromMapperModel(mapperModel);
        List<String> attributeValuesInContext = findAttributeValuesInContext(attributeName, context);

        List<String> currentAttributeValues = user.getAttributes().get(attribute);
        if (attributeValuesInContext == null) {
            // attribute no longer sent by brokered idp, remove it
            user.removeAttribute(attribute);
        } else if (currentAttributeValues == null) {
            // new attribute sent by brokered idp, add it
            user.setAttribute(attribute, attributeValuesInContext);
        } else if (!CollectionUtil.collectionEquals(attributeValuesInContext, currentAttributeValues)) {
            // attribute sent by brokered idp has different values as before, update it
            user.setAttribute(attribute, attributeValuesInContext);
        }
    }

    @Override
    public String getHelpText() {
        return "Import eduPersonTargetedID saml attribute if it exists in assertion into the specified user attribute.";
    }

    // SamlMetadataDescriptorUpdater interface
    @Override
    public void updateMetadata(IdentityProviderMapperModel mapperModel, EntityDescriptorType entityDescriptor) {
        String attributeName = mapperModel.getConfig().get(ATTRIBUTE_NAME);
        String attributeFriendlyName = mapperModel.getConfig().get(ATTRIBUTE_FRIENDLY_NAME);

        RequestedAttributeType requestedAttribute = new RequestedAttributeType(attributeName);
        requestedAttribute.setIsRequired(null);
        requestedAttribute.setNameFormat(mapperModel.getConfig().get(ATTRIBUTE_NAME_FORMAT) != null ? JBossSAMLURIConstants.valueOf(mapperModel.getConfig().get(ATTRIBUTE_NAME_FORMAT)).get() :ATTRIBUTE_FORMAT_BASIC.get());

        if (attributeFriendlyName != null && attributeFriendlyName.length() > 0)
            requestedAttribute.setFriendlyName(attributeFriendlyName);

        // Add the requestedAttribute item to any AttributeConsumingServices
        for (EntityDescriptorType.EDTChoiceType choiceType : entityDescriptor.getChoiceType()) {
            List<EntityDescriptorType.EDTDescriptorChoiceType> descriptors = choiceType.getDescriptors();
            for (EntityDescriptorType.EDTDescriptorChoiceType descriptor : descriptors) {
                for (AttributeConsumingServiceType attributeConsumingService : descriptor.getSpDescriptor().getAttributeConsumingService()) {
                    boolean alreadyPresent = attributeConsumingService.getRequestedAttribute().stream()
                            .anyMatch(t -> (attributeName == null || attributeName.equalsIgnoreCase(t.getName())) &&
                                    (attributeFriendlyName == null || attributeFriendlyName.equalsIgnoreCase(t.getFriendlyName())));

                    if (!alreadyPresent)
                        attributeConsumingService.addRequestedAttribute(requestedAttribute);
                }
            }

        }
    }
}
