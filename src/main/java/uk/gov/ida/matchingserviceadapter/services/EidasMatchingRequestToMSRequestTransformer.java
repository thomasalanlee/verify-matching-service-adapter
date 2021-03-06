package uk.gov.ida.matchingserviceadapter.services;

import org.joda.time.LocalDate;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.Attribute;
import uk.gov.ida.matchingserviceadapter.domain.EidasLoa;
import uk.gov.ida.matchingserviceadapter.domain.MatchingServiceRequestContext;
import uk.gov.ida.matchingserviceadapter.rest.UniversalMatchingServiceRequestDto;
import uk.gov.ida.matchingserviceadapter.rest.matchingservice.Cycle3DatasetDto;
import uk.gov.ida.matchingserviceadapter.rest.matchingservice.GenderDto;
import uk.gov.ida.matchingserviceadapter.rest.matchingservice.LevelOfAssuranceDto;
import uk.gov.ida.matchingserviceadapter.rest.matchingservice.SimpleMdsValueDto;
import uk.gov.ida.matchingserviceadapter.rest.matchingservice.UniversalMatchingDatasetDto;
import uk.gov.ida.matchingserviceadapter.rest.matchingservice.TransliterableMdsValueDto;
import uk.gov.ida.matchingserviceadapter.rest.matchingservice.helper.GenderDtoHelper;
import uk.gov.ida.matchingserviceadapter.saml.HubAssertionExtractor;
import uk.gov.ida.matchingserviceadapter.saml.UserIdHashFactory;
import uk.gov.ida.saml.core.IdaConstants;
import uk.gov.ida.saml.core.IdaConstants.Eidas_Attributes;
import uk.gov.ida.saml.core.domain.AuthnContext;
import uk.gov.ida.saml.core.domain.Cycle3Dataset;
import uk.gov.ida.saml.core.domain.HubAssertion;
import uk.gov.ida.saml.core.extensions.eidas.CurrentFamilyName;
import uk.gov.ida.saml.core.extensions.eidas.CurrentGivenName;
import uk.gov.ida.saml.core.extensions.eidas.DateOfBirth;
import uk.gov.ida.saml.core.extensions.eidas.Gender;
import uk.gov.ida.saml.core.extensions.eidas.PersonIdentifier;
import uk.gov.ida.saml.core.extensions.eidas.TransliterableString;

import java.util.Collections;
import java.util.List;
import java.util.Optional;
import java.util.function.Function;

public class EidasMatchingRequestToMSRequestTransformer implements Function<MatchingServiceRequestContext, UniversalMatchingServiceRequestDto> {

    private final UserIdHashFactory userIdHashFactory;
    private final HubAssertionExtractor hubAssertionExtractor;

    public EidasMatchingRequestToMSRequestTransformer(final UserIdHashFactory userIdHashFactory,
        final HubAssertionExtractor hubAssertionExtractor) {
        this.userIdHashFactory = userIdHashFactory;
        this.hubAssertionExtractor = hubAssertionExtractor;
    }

    @Override
    public UniversalMatchingServiceRequestDto apply(MatchingServiceRequestContext matchingServiceRequestContext) {
        Assertion eidasAssertion = hubAssertionExtractor.getNonHubAssertions(matchingServiceRequestContext.getAssertions()).get(0);
        Optional<HubAssertion> hubAssertion = hubAssertionExtractor.getHubAssertion(matchingServiceRequestContext.getAssertions());

        Optional<Cycle3DatasetDto> cycle3Data = hubAssertion.map(this::extractCycle3Data);
        List<Attribute> attributes = eidasAssertion.getAttributeStatements().get(0).getAttributes();

        return new UniversalMatchingServiceRequestDto(extractUniversalMatchingDataset(attributes),
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

    private UniversalMatchingDatasetDto extractUniversalMatchingDataset(List<Attribute> attributes) {
        SimpleMdsValueDto<LocalDate> dateOfBirth = extractSimpleMdsValue(attributes, Eidas_Attributes.DateOfBirth.NAME, DateOfBirth::getDateOfBirth);
        TransliterableMdsValueDto firstName = extractTransliterableMdsValue(attributes, Eidas_Attributes.FirstName.NAME, CurrentGivenName::getFirstName);
        TransliterableMdsValueDto surname = extractTransliterableMdsValue(attributes, Eidas_Attributes.FamilyName.NAME, CurrentFamilyName::getFamilyName);

        // Current address

        return new UniversalMatchingDatasetDto(
            Optional.ofNullable(firstName),
            Optional.empty(),
            Collections.singletonList(surname),
            Optional.ofNullable(extractSimpleMdsGenderValue(attributes)),
            Optional.ofNullable(dateOfBirth),
            Optional.empty()
        );
    }

    private SimpleMdsValueDto<GenderDto> extractSimpleMdsGenderValue(List<Attribute> attributes) {
        String genderStr = getAttributeValue(attributes, Eidas_Attributes.Gender.NAME, Gender::getValue);

        if (genderStr == null) {
            return null;
        }

        GenderDto genderDto = GenderDtoHelper.convertToVerifyGenderDto(genderStr);
        return new SimpleMdsValueDto<>(genderDto, null, null, true);
    }

    private <T, V> SimpleMdsValueDto<V> extractSimpleMdsValue(List<Attribute> attributes, String attributeName, Function<T, V> getContent) {
        V attributeValue = getAttributeValue(attributes, attributeName, getContent);

        return attributeValue == null ? null : new SimpleMdsValueDto<>(attributeValue, null, null, true);
    }

    private <T> TransliterableMdsValueDto extractTransliterableMdsValue(List<Attribute> attributes, String attributeName, Function<T, String> getContent) {
        String latinScriptAttributeValue = getTransliterableAttributeValue(attributes, attributeName, getContent, true);
        String nonLatinScriptValue = getTransliterableAttributeValue(attributes, attributeName, getContent, false);

        return latinScriptAttributeValue == null && nonLatinScriptValue == null ? null : new TransliterableMdsValueDto(latinScriptAttributeValue, nonLatinScriptValue);
    }

    private Cycle3DatasetDto extractCycle3Data(final HubAssertion hubAssertion) {
        return hubAssertion.getCycle3Data()
            .map(Cycle3Dataset::getAttributes)
            .map(Cycle3DatasetDto::createFromData)
            .get();
    }

    private <T, V> V getAttributeValue(List<Attribute> attributes, String attributeName, Function<T, V> getContent) {
        return attributes.stream()
            .filter(a -> a.getName().equals(attributeName))
            .findFirst()
            .map(a -> a.getAttributeValues().get(0))
            .map(value -> getContent.apply((T) value))
            .orElse(null);
    }

    private <T> String getTransliterableAttributeValue(List<Attribute> attributes, String attributeName,
                                                       Function<T, String> getContent, Boolean isLatinScript) {
        return attributes.stream()
                .filter(a -> a.getName().equals(attributeName))
                .findFirst()
                .map(a -> getFirstTransliterableAttributeValue(a, isLatinScript))
                .map(value -> getContent.apply((T) value))
                .orElse(null);
    }

    private XMLObject getFirstTransliterableAttributeValue(Attribute attribute, Boolean isLatinScript) {
        return attribute.getAttributeValues()
                .stream()
                .filter(value -> ((TransliterableString) value).isLatinScript() == isLatinScript)
                .findFirst()
                .orElse(null);
    }
}
