package uk.gov.ida.matchingserviceadapter.builders;

import com.google.common.collect.ImmutableList;
import org.joda.time.DateTime;
import org.opensaml.saml.saml2.core.Attribute;
import uk.gov.ida.matchingserviceadapter.domain.ProxyNodeAssertion;
import uk.gov.ida.matchingserviceadapter.domain.VerifyUserAccountCreationAttribute;
import uk.gov.ida.matchingserviceadapter.factories.AttributeQueryAttributeFactory;
import uk.gov.ida.matchingserviceadapter.saml.transformers.inbound.InboundEidasMatchingServiceRequest;
import uk.gov.ida.matchingserviceadapter.saml.transformers.inbound.InboundVerifyMatchingServiceRequest;
import uk.gov.ida.saml.core.OpenSamlXmlObjectFactory;
import uk.gov.ida.saml.core.domain.HubAssertion;
import uk.gov.ida.saml.core.domain.IdentityProviderAssertion;

import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import static uk.gov.ida.matchingserviceadapter.builders.IdentityProviderAssertionBuilder.anIdentityProviderAssertion;
import static uk.gov.ida.matchingserviceadapter.builders.IdentityProviderAuthnStatementBuilder.anIdentityProviderAuthnStatement;
import static uk.gov.ida.matchingserviceadapter.builders.MatchingDatasetBuilder.aMatchingDataset;
import static uk.gov.ida.matchingserviceadapter.builders.PersistentIdBuilder.aPersistentId;

public class InboundMatchingServiceRequestBuilder {

    private String id = "id";
    private String issuer = "issuer-id";
    private IdentityProviderAssertion matchingDatasetAssertion = anIdentityProviderAssertion().withMatchingDataset(
            aMatchingDataset().build()).withPersistentId(aPersistentId().build()).build();
    private IdentityProviderAssertion authnStatementAssertion = anIdentityProviderAssertion().withAuthnStatement(anIdentityProviderAuthnStatement().build()).build();
    private ProxyNodeAssertion proxyNodeAssertion;
    private Optional<HubAssertion> cycle3AttributeAssertion = Optional.empty();
    private String requestIssuerEntityId = "issuer-id";
    private String assertionConsumerServiceUrl = "/foo";
    private List<VerifyUserAccountCreationAttribute> userCreationAttributes = ImmutableList.of();

    public static InboundMatchingServiceRequestBuilder anInboundMatchingServiceRequest() {
        return new InboundMatchingServiceRequestBuilder();
    }

    public InboundVerifyMatchingServiceRequest buildForVerify() {
        Iterable<Attribute> requiredAttributes = userCreationAttributes.stream()
                .map(userAccountCreationAttribute -> new AttributeQueryAttributeFactory(new OpenSamlXmlObjectFactory()).createAttribute(userAccountCreationAttribute))
                .collect(Collectors.toList());
        return new InboundVerifyMatchingServiceRequest(
                id,
                issuer,
                matchingDatasetAssertion,
                authnStatementAssertion,
                cycle3AttributeAssertion,
                DateTime.now(),
                requestIssuerEntityId,
                assertionConsumerServiceUrl,
                ImmutableList.copyOf(requiredAttributes));
    }

    public InboundEidasMatchingServiceRequest buildForEidas() {
        Iterable<Attribute> requiredAttributes = userCreationAttributes.stream()
                .map(userAccountCreationAttribute -> new AttributeQueryAttributeFactory(new OpenSamlXmlObjectFactory()).createAttribute(userAccountCreationAttribute))
                .collect(Collectors.toList());
        return new InboundEidasMatchingServiceRequest(
                id,
                issuer,
                proxyNodeAssertion,
                cycle3AttributeAssertion,
                DateTime.now(),
                requestIssuerEntityId,
                assertionConsumerServiceUrl,
                ImmutableList.copyOf(requiredAttributes));
    }

    public InboundMatchingServiceRequestBuilder withMatchingDatasetAssertion(IdentityProviderAssertion assertion) {
        this.matchingDatasetAssertion = assertion;
        return this;
    }

    public InboundMatchingServiceRequestBuilder withAuthnStatementAssertion(IdentityProviderAssertion assertion) {
        this.authnStatementAssertion = assertion;
        return this;
    }

    public InboundMatchingServiceRequestBuilder withProxyNodeAssertion(ProxyNodeAssertion proxyNodeAssertion) {
        this.proxyNodeAssertion = proxyNodeAssertion;
        return this;
    }

    public InboundMatchingServiceRequestBuilder withCycle3DataAssertion(HubAssertion cycle3DataAssertion) {
        this.cycle3AttributeAssertion = Optional.ofNullable(cycle3DataAssertion);
        return this;
    }

    public InboundMatchingServiceRequestBuilder withRequestIssuerEntityId(String requestIssuerEntityId) {
        this.requestIssuerEntityId = requestIssuerEntityId;
        return this;
    }

    public InboundMatchingServiceRequestBuilder withAssertionConsumerServiceUrl(String assertionConsumerServiceUrl) {
        this.assertionConsumerServiceUrl = assertionConsumerServiceUrl;
        return this;
    }

    public InboundMatchingServiceRequestBuilder withUserCreationAttributes(List<VerifyUserAccountCreationAttribute> userCreationAttributes) {
        this.userCreationAttributes = userCreationAttributes;
        return this;
    }
}
