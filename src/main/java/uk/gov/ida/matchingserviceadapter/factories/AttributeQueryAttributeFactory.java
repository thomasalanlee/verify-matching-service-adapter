package uk.gov.ida.matchingserviceadapter.factories;

import com.google.inject.Inject;
import org.opensaml.saml.saml2.core.Attribute;
import uk.gov.ida.matchingserviceadapter.domain.VerifyUserAccountCreationAttribute;
import uk.gov.ida.saml.core.OpenSamlXmlObjectFactory;

public class AttributeQueryAttributeFactory {

    private final OpenSamlXmlObjectFactory openSamlXmlObjectFactory;

    @Inject
    public AttributeQueryAttributeFactory(OpenSamlXmlObjectFactory openSamlXmlObjectFactory) {
        this.openSamlXmlObjectFactory = openSamlXmlObjectFactory;
    }

    public Attribute createAttribute(final VerifyUserAccountCreationAttribute verifyUserAccountCreationAttribute) {
        final Attribute attribute = openSamlXmlObjectFactory.createAttribute();
        attribute.setName(verifyUserAccountCreationAttribute.getAttributeName());
        attribute.setNameFormat(Attribute.UNSPECIFIED);
        return attribute;
    }
}
