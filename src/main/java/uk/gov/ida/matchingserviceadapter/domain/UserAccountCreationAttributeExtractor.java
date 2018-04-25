package uk.gov.ida.matchingserviceadapter.domain;

import com.google.common.collect.ImmutableList;
import com.google.inject.Inject;
import org.joda.time.LocalDate;
import org.opensaml.saml.saml2.core.Attribute;
import uk.gov.ida.matchingserviceadapter.saml.factories.UserAccountCreationAttributeFactory;
import uk.gov.ida.saml.core.OpenSamlXmlObjectFactory;
import uk.gov.ida.saml.core.domain.Address;
import uk.gov.ida.saml.core.domain.HubAssertion;
import uk.gov.ida.saml.core.domain.MatchingDataset;
import uk.gov.ida.saml.core.domain.SimpleMdsValue;

import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.Response;
import java.text.MessageFormat;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

import static java.util.stream.Collectors.toList;

public class UserAccountCreationAttributeExtractor {

    @Inject
    public UserAccountCreationAttributeExtractor() {
    }

    private final UserAccountCreationAttributeFactory userAccountCreationAttributeFactory = new UserAccountCreationAttributeFactory(new OpenSamlXmlObjectFactory());

    public List<Attribute> getUserAccountCreationAttributes(List<Attribute> userCreationAttributes,
                                                            Optional<MatchingDataset> matchingDatasetOptional,
                                                            Optional<HubAssertion> cycle3Data) {

        //How can we be sure that the Matching dataset will not be absent, and if we can be sure then why is it optional?
        return userCreationAttributes.stream()
                .map(Attribute::getName)
                .map(UserAccountCreationAttribute::getUserAccountCreationAttribute)
                .map(attributeType ->
                        attributeType == UserAccountCreationAttribute.CYCLE_3 ?
                                        cycle3Data
                                                .flatMap(HubAssertion::getCycle3Data)
                                                .map(cycle3Dataset -> cycle3Dataset.getAttributes().values())
                                                .map(userAccountCreationAttributeFactory::createUserAccountCreationCycle3DataAttributes) :
                                        matchingDatasetOptional
                                                .flatMap(matchingDataset -> getAttribute(attributeType, matchingDataset))
                )
                .filter(Optional::isPresent)
                .map(Optional::get)
                .collect(Collectors.toList());
    }

    private Optional<Attribute> getAttribute(UserAccountCreationAttribute userAccountCreationAttribute, MatchingDataset matchingDataset) {
        switch (userAccountCreationAttribute) {
            case FIRST_NAME:
                List<SimpleMdsValue<String>> firstNameAttributeValues = getAttributeValuesWithoutMdsDetails(matchingDataset.getFirstNames(), userAccountCreationAttribute);
                return optionalOfList(firstNameAttributeValues, userAccountCreationAttributeFactory.createUserAccountCreationFirstnameAttribute(firstNameAttributeValues));
            case FIRST_NAME_VERIFIED:
                return getCurrentValue(matchingDataset.getFirstNames(), userAccountCreationAttribute).map(stringSimpleMdsValue ->
                        userAccountCreationAttributeFactory.createUserAccountCreationVerifiedAttribute(UserAccountCreationAttribute.FIRST_NAME_VERIFIED, stringSimpleMdsValue.isVerified()));
            case MIDDLE_NAME:
                List<SimpleMdsValue<String>> middleNameAttributeValues = getAttributeValuesWithoutMdsDetails(matchingDataset.getMiddleNames(), userAccountCreationAttribute);
                return optionalOfList(middleNameAttributeValues, userAccountCreationAttributeFactory.createUserAccountCreationMiddlenameAttribute(middleNameAttributeValues));
            case MIDDLE_NAME_VERIFIED:
                return getCurrentValue(matchingDataset.getMiddleNames(), userAccountCreationAttribute).map(stringSimpleMdsValue ->
                                userAccountCreationAttributeFactory.createUserAccountCreationVerifiedAttribute(UserAccountCreationAttribute.MIDDLE_NAME_VERIFIED, stringSimpleMdsValue.isVerified()));
            case SURNAME:
                List<SimpleMdsValue<String>> surnameAttributeValues = getAttributeValuesWithoutMdsDetails(matchingDataset.getSurnames(), userAccountCreationAttribute);
                return optionalOfList(surnameAttributeValues, userAccountCreationAttributeFactory.createUserAccountCreationSurnameAttribute(surnameAttributeValues));
            case SURNAME_VERIFIED:
                return getCurrentValue(matchingDataset.getSurnames(), userAccountCreationAttribute).map(stringSimpleMdsValue ->
                        userAccountCreationAttributeFactory.createUserAccountCreationVerifiedAttribute(UserAccountCreationAttribute.SURNAME_VERIFIED, stringSimpleMdsValue.isVerified()));
            case DATE_OF_BIRTH:
                List<SimpleMdsValue<LocalDate>> dateOfBirthAttributeValues = getAttributeValuesWithoutMdsDetails(matchingDataset.getDateOfBirths(), userAccountCreationAttribute);
                return optionalOfList(dateOfBirthAttributeValues, userAccountCreationAttributeFactory.createUserAccountCreationDateOfBirthAttribute(dateOfBirthAttributeValues));
            case DATE_OF_BIRTH_VERIFIED:
                return getCurrentValue(matchingDataset.getDateOfBirths(), userAccountCreationAttribute).map(localDateSimpleMdsValue ->
                        userAccountCreationAttributeFactory.createUserAccountCreationVerifiedAttribute(UserAccountCreationAttribute.DATE_OF_BIRTH_VERIFIED, localDateSimpleMdsValue.isVerified()));
            case CURRENT_ADDRESS:
                return extractCurrentAddress(matchingDataset.getCurrentAddresses(), userAccountCreationAttribute).map(address ->
                        userAccountCreationAttributeFactory.createUserAccountCreationCurrentAddressAttribute(ImmutableList.of(address)));
            case CURRENT_ADDRESS_VERIFIED:
                return extractCurrentAddress(matchingDataset.getCurrentAddresses(), userAccountCreationAttribute).map(address ->
                        userAccountCreationAttributeFactory.createUserAccountCreationVerifiedAttribute(UserAccountCreationAttribute.CURRENT_ADDRESS_VERIFIED, address.isVerified()));
            case ADDRESS_HISTORY:
                List<Address> allAddresses = matchingDataset.getAddresses();
                return optionalOfList(allAddresses, userAccountCreationAttributeFactory.createUserAccountCreationAddressHistoryAttribute(ImmutableList.copyOf(allAddresses)));
            default:
                throw new UnsupportedOperationException();
        }
    }

    private <T> Optional<Attribute> optionalOfList(List<T> firstNameAttributeValues, Attribute userAccountCreationFirstnameAttribute) {
        return !firstNameAttributeValues.isEmpty() ? Optional.of(userAccountCreationFirstnameAttribute) : Optional.empty();
    }

    private <T> List<SimpleMdsValue<T>> getAttributeValuesWithoutMdsDetails(final List<SimpleMdsValue<T>> simpleMdsValues, UserAccountCreationAttribute userAccountCreationAttribute) {
        Optional<SimpleMdsValue<T>> currentValue = getCurrentValue(simpleMdsValues, userAccountCreationAttribute);
        List<SimpleMdsValue<T>> attributesWithoutMdsDetails = new ArrayList<>();
        currentValue.ifPresent(tSimpleMdsValue -> attributesWithoutMdsDetails.add(new SimpleMdsValue<>(tSimpleMdsValue.getValue(), null, null, false)));
        return attributesWithoutMdsDetails;
    }

    private Optional<Address> extractCurrentAddress(List<Address> addresses, UserAccountCreationAttribute userAccountCreationAttribute) {
        List<Address> currentValues = ImmutableList.copyOf(addresses.stream()
                .filter(candidateValue -> !candidateValue.getTo().isPresent())
                .collect(toList()));

        if (currentValues.size() > 1) {
            String message = MessageFormat.format("There cannot be multiple current values for {0} attribute.", userAccountCreationAttribute.getAttributeName());
            throw new WebApplicationException(new IllegalStateException(message), Response.Status.INTERNAL_SERVER_ERROR);
        }
        if (currentValues.isEmpty()) {
            return Optional.empty();
        }
        return Optional.of(currentValues.get(0));
    }

    private <T> Optional<SimpleMdsValue<T>> getCurrentValue(final List<SimpleMdsValue<T>> simpleMdsValues, UserAccountCreationAttribute userAccountCreationAttribute) {
        List<SimpleMdsValue<T>> currentValues = ImmutableList.copyOf(simpleMdsValues.stream()
                .filter(simpleMdsValue -> simpleMdsValue.getTo() == null)
                .collect(toList()));
        if (currentValues.size() > 1) {
            String message = MessageFormat.format("There cannot be multiple current values for {0} attribute.", userAccountCreationAttribute.getAttributeName());
            throw new WebApplicationException(new IllegalStateException(message), Response.Status.INTERNAL_SERVER_ERROR);
        }
        if (currentValues.isEmpty()) {
            return Optional.empty();
        }
        return Optional.of(currentValues.get(0));
    }

}
