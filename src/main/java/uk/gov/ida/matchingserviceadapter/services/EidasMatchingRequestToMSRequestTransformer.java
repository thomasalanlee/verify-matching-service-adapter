package uk.gov.ida.matchingserviceadapter.services;

import com.google.common.base.Optional;
import org.joda.time.LocalDate;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import uk.gov.ida.matchingserviceadapter.domain.EidasLoa;
import uk.gov.ida.matchingserviceadapter.domain.MatchingServiceRequestContext;
import uk.gov.ida.matchingserviceadapter.rest.MatchingServiceRequestDto;
import uk.gov.ida.matchingserviceadapter.rest.matchingservice.Cycle3DatasetDto;
import uk.gov.ida.matchingserviceadapter.rest.matchingservice.EidasMatchingDatasetDto;
import uk.gov.ida.matchingserviceadapter.rest.matchingservice.LevelOfAssuranceDto;
import uk.gov.ida.matchingserviceadapter.saml.UserIdHashFactory;
import uk.gov.ida.saml.core.IdaConstants;
import uk.gov.ida.saml.core.IdaConstants.Eidas_Attributes;
import uk.gov.ida.saml.core.domain.AuthnContext;
import uk.gov.ida.saml.core.domain.Cycle3Dataset;
import uk.gov.ida.saml.core.domain.HubAssertion;
import uk.gov.ida.saml.core.extensions.eidas.BirthName;
import uk.gov.ida.saml.core.extensions.eidas.CurrentFamilyName;
import uk.gov.ida.saml.core.extensions.eidas.CurrentGivenName;
import uk.gov.ida.saml.core.extensions.eidas.DateOfBirth;
import uk.gov.ida.saml.core.extensions.eidas.Gender;
import uk.gov.ida.saml.core.extensions.eidas.PersonIdentifier;
import uk.gov.ida.saml.core.extensions.eidas.PlaceOfBirth;
import uk.gov.ida.saml.core.transformers.inbound.HubAssertionUnmarshaller;

import java.util.List;
import java.util.Map;
import java.util.function.Function;
import java.util.stream.Collectors;


public class EidasMatchingRequestToMSRequestTransformer implements Function<MatchingServiceRequestContext, MatchingServiceRequestDto> {

    private final UserIdHashFactory userIdHashFactory;
    private final String hubEntityId;
    private final HubAssertionUnmarshaller hubAssertionUnmarshaller;

    public EidasMatchingRequestToMSRequestTransformer(final UserIdHashFactory userIdHashFactory,
        final String hubEntityId,
        final HubAssertionUnmarshaller hubAssertionUnmarshaller) {
        this.userIdHashFactory = userIdHashFactory;
        this.hubEntityId = hubEntityId;
        this.hubAssertionUnmarshaller = hubAssertionUnmarshaller;
    }

    @Override
    public MatchingServiceRequestDto apply(MatchingServiceRequestContext matchingServiceRequestContext) {
        Map<Boolean, Assertion> assertions = matchingServiceRequestContext.getAssertions().stream()
            .collect(Collectors.toMap(this::isHubAssertion, Function.identity()));
        Assertion eidasAssertion = assertions.get(false);
        Optional<Assertion> hubAssertion = Optional.fromNullable(assertions.get(true));

        Optional<Cycle3DatasetDto> cycle3Data = hubAssertion.transform(this::extractCycle3Data).transform(Optional::get);
        List<Attribute> attributes = eidasAssertion.getAttributeStatements().get(0).getAttributes();

        return new MatchingServiceRequestDto(extractEidasMatchingDataset(attributes),
            cycle3Data,
            extractAndHashPid(eidasAssertion),
            matchingServiceRequestContext.getAttributeQuery().getID(),
            extractVerifyLoa(eidasAssertion));
    }

    private LevelOfAssuranceDto extractVerifyLoa(Assertion assertion) {
        String eidasLoaUri = assertion.getAuthnStatements().get(0).getAuthnContext().getAuthnContextClassRef().getAuthnContextClassRef();
        return EidasLoa.valueOfUri(eidasLoaUri).getVerifyLoa();
    }

    private String extractAndHashPid(Assertion assertion) {
        Attribute personIdentifierAttribute = assertion.getAttributeStatements()
            .get(0)
            .getAttributes()
            .stream()
            .filter(a -> a.getName().equals(IdaConstants.Eidas_Attributes.PersonIdentifier.NAME))
            .findFirst()
            .get();
        String euPid = ((PersonIdentifier) personIdentifierAttribute.getAttributeValues().get(0)).getPersonIdentifier();

        return userIdHashFactory.hashId(assertion.getIssuer().getValue(),
            euPid,
            Optional.of(AuthnContext.valueOf(extractVerifyLoa(assertion).name())));
    }

    private EidasMatchingDatasetDto extractEidasMatchingDataset(List<Attribute> attributes) {
        LocalDate dob = getAttributeValue(attributes, Eidas_Attributes.DateOfBirth.NAME, DateOfBirth::getDateOfBirth);
        String givenName = getAttributeValue(attributes, Eidas_Attributes.FirstName.NAME, CurrentGivenName::getFirstName);
        String familyName = getAttributeValue(attributes, Eidas_Attributes.FamilyName.NAME, CurrentFamilyName::getFamilyName);
        String birthName = getAttributeValue(attributes, Eidas_Attributes.BirthName.NAME, BirthName::getBirthName);
        String placeOfBirth = getAttributeValue(attributes, Eidas_Attributes.PlaceOfBirth.NAME, PlaceOfBirth::getPlaceOfBirth);
        String gender = getAttributeValue(attributes, Eidas_Attributes.Gender.NAME, Gender::getValue);

        return new EidasMatchingDatasetDto(null,
            dob,
            givenName,
            familyName,
            birthName,
            gender,
            placeOfBirth
        );
    }

    private Optional<Cycle3DatasetDto> extractCycle3Data(final Assertion hubAssertion) {
        return hubAssertionUnmarshaller.toHubAssertion(hubAssertion).getCycle3Data()
            .transform(Cycle3Dataset::getAttributes)
            .transform(Cycle3DatasetDto::createFromData);
    }

    private <T, V> V getAttributeValue(List<Attribute> attributes, String attributeName, Function<T, V> getContent) {
        return attributes.stream()
            .filter(a -> a.getName().equals(attributeName))
            .findFirst()
            .map(a -> a.getAttributeValues().get(0))
            .map(value -> getContent.apply((T) value))
            .orElse(null);
    }

    private boolean isHubAssertion(final Assertion assertion) {
        return assertion.getIssuer().getValue().equals(hubEntityId);
    }
}
