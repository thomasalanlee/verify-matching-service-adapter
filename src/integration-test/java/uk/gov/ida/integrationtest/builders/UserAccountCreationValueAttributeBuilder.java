package uk.gov.ida.integrationtest.builders;

import org.opensaml.saml.saml2.core.Attribute;
import org.opensaml.saml.saml2.core.AttributeValue;
import uk.gov.ida.matchingserviceadapter.domain.VerifyUserAccountCreationAttribute;
import uk.gov.ida.saml.core.OpenSamlXmlObjectFactory;

import java.util.ArrayList;
import java.util.List;

public class UserAccountCreationValueAttributeBuilder {

    private OpenSamlXmlObjectFactory openSamlXmlObjectFactory = new OpenSamlXmlObjectFactory();

    private List<AttributeValue> values = new ArrayList<>();

    public static UserAccountCreationValueAttributeBuilder aUserAccountCreationAttributeValue() {
        return new UserAccountCreationValueAttributeBuilder();
    }

    public Attribute buildAsAttribute(VerifyUserAccountCreationAttribute verifyUserAccountCreationAttribute) {
        Attribute attribute = build();

        String attributeName = verifyUserAccountCreationAttribute.getAttributeName();
        attribute.setFriendlyName(attributeName);
        attribute.setName(attributeName);

        return attribute;
    }

    public UserAccountCreationValueAttributeBuilder addValue(AttributeValue attributeValue) {
        this.values.add(attributeValue);
        return this;
    }

    private Attribute build() {
        Attribute userAccountCreationPersonNameAttribute = openSamlXmlObjectFactory.createAttribute();
        String nameFormat = Attribute.UNSPECIFIED;
        userAccountCreationPersonNameAttribute.setNameFormat(nameFormat);

        for (AttributeValue value : values) {
            userAccountCreationPersonNameAttribute.getAttributeValues().add(value);
        }
        return userAccountCreationPersonNameAttribute;
    }
}
