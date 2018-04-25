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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;
import java.util.stream.Collectors;

import static java.util.stream.Collectors.toList;

public class UserAccountCreationAttributeExtractor {

	private final Map<UserAccountCreationAttribute, Function<MatchingDataset, Optional<Attribute>>> attributeExtractorFunctionMap = initAttributeMap();
	
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
				.map(attributeType -> attributeType == UserAccountCreationAttribute.CYCLE_3 ? 
						cycle3Data
						.flatMap(HubAssertion::getCycle3Data)
						.map(cycle3Dataset -> cycle3Dataset.getAttributes().values())
						.map(userAccountCreationAttributeFactory::createUserAccountCreationCycle3DataAttributes) : matchingDatasetOptional
						.flatMap(matchingDataset -> getAttribute(attributeType, matchingDataset))
						)
				.filter(Optional::isPresent)
				.map(Optional::get)
				.collect(Collectors.toList());
	}
	
	private Optional<Attribute> getAttribute(UserAccountCreationAttribute userAccountCreationAttribute, MatchingDataset matchingDataset) {
		if(attributeExtractorFunctionMap.containsKey(userAccountCreationAttribute)){
			return attributeExtractorFunctionMap.get(userAccountCreationAttribute).apply(matchingDataset);
		}else {
			throw new UnsupportedOperationException();
		}
	}

	private <T> Optional<Attribute> optionalOfList(List<T> firstNameAttributeValues, Attribute userAccountCreationFirstnameAttribute) {
		return !firstNameAttributeValues.isEmpty() ? Optional.of(userAccountCreationFirstnameAttribute) : Optional.empty();
	}

	private <T> List<SimpleMdsValue<T>> getAttributeValuesWithoutMdsDetails(final List<SimpleMdsValue<T>> simpleMdsValues) {
		Optional<SimpleMdsValue<T>> currentValue = getCurrentValue(simpleMdsValues);
		List<SimpleMdsValue<T>> attributesWithoutMdsDetails = new ArrayList<>();
		currentValue.ifPresent(tSimpleMdsValue -> attributesWithoutMdsDetails.add(new SimpleMdsValue<>(tSimpleMdsValue.getValue(), null, null, false)));
		return attributesWithoutMdsDetails;
	}

	private Optional<Address> extractCurrentAddress(List<Address> addresses) {
		List<Address> currentValues = ImmutableList.copyOf(addresses.stream()
				.filter(candidateValue -> !candidateValue.getTo().isPresent())
				.collect(toList()));

		if (currentValues.size() > 1) {
			throw new IllegalStateException("There cannot be multiple current values for attribute.");
		}
		if (currentValues.isEmpty()) {
			return Optional.empty();
		}
		return Optional.of(currentValues.get(0));
	}

	private <T> Optional<SimpleMdsValue<T>> getCurrentValue(final List<SimpleMdsValue<T>> simpleMdsValues) {
		List<SimpleMdsValue<T>> currentValues = ImmutableList.copyOf(simpleMdsValues.stream()
				.filter(simpleMdsValue -> simpleMdsValue.getTo() == null)
				.collect(toList()));
		if (currentValues.size() > 1) {
			throw new IllegalStateException("There cannot be multiple current values for attribute.");
		}
		if (currentValues.isEmpty()) {
			return Optional.empty();
		}
		return Optional.of(currentValues.get(0));
	}
	
	
	private Map<UserAccountCreationAttribute,Function<MatchingDataset, Optional<Attribute>>>  initAttributeMap() {
		Map<UserAccountCreationAttribute,Function<MatchingDataset, Optional<Attribute>>> map = new HashMap<UserAccountCreationAttribute, Function<MatchingDataset, Optional<Attribute>>>(){
			{
				put(UserAccountCreationAttribute.FIRST_NAME, (matchingDataset) -> {
					List<SimpleMdsValue<String>> firstNameAttributeValues = getAttributeValuesWithoutMdsDetails(matchingDataset.getFirstNames());
					return optionalOfList(firstNameAttributeValues, userAccountCreationAttributeFactory.createUserAccountCreationFirstnameAttribute(firstNameAttributeValues));
				});

				put(UserAccountCreationAttribute.FIRST_NAME_VERIFIED, (matchingDataset) -> {
					return getCurrentValue(matchingDataset.getFirstNames())
							.map(stringSimpleMdsValue -> userAccountCreationAttributeFactory.createUserAccountCreationVerifiedAttribute(UserAccountCreationAttribute.FIRST_NAME_VERIFIED, stringSimpleMdsValue.isVerified()));
				});

				put(UserAccountCreationAttribute.MIDDLE_NAME, (matchingDataset) -> {
					List<SimpleMdsValue<String>> middleNameAttributeValues = getAttributeValuesWithoutMdsDetails(matchingDataset.getMiddleNames());
					return optionalOfList(middleNameAttributeValues, userAccountCreationAttributeFactory.createUserAccountCreationMiddlenameAttribute(middleNameAttributeValues));

				});

				put(UserAccountCreationAttribute.MIDDLE_NAME_VERIFIED, (matchingDataset) -> {
					return getCurrentValue(matchingDataset.getMiddleNames())
							.map(stringSimpleMdsValue -> userAccountCreationAttributeFactory.createUserAccountCreationVerifiedAttribute(UserAccountCreationAttribute.MIDDLE_NAME_VERIFIED, stringSimpleMdsValue.isVerified()));
				});

				put(UserAccountCreationAttribute.SURNAME, (matchingDataset) -> {
					List<SimpleMdsValue<String>> surnameAttributeValues = getAttributeValuesWithoutMdsDetails(matchingDataset.getSurnames());
					return optionalOfList(surnameAttributeValues, userAccountCreationAttributeFactory.createUserAccountCreationSurnameAttribute(surnameAttributeValues));
				});

				put(UserAccountCreationAttribute.SURNAME_VERIFIED, (matchingDataset) -> {
					return getCurrentValue(matchingDataset.getSurnames())
							.map(stringSimpleMdsValue -> userAccountCreationAttributeFactory.createUserAccountCreationVerifiedAttribute(UserAccountCreationAttribute.SURNAME_VERIFIED, stringSimpleMdsValue.isVerified()));
				});

				put(UserAccountCreationAttribute.DATE_OF_BIRTH, (matchingDataset) -> {
					List<SimpleMdsValue<LocalDate>> dateOfBirthAttributeValues = getAttributeValuesWithoutMdsDetails(matchingDataset.getDateOfBirths());
					return optionalOfList(dateOfBirthAttributeValues, userAccountCreationAttributeFactory.createUserAccountCreationDateOfBirthAttribute(dateOfBirthAttributeValues));
				});

				put(UserAccountCreationAttribute.DATE_OF_BIRTH_VERIFIED, (matchingDataset) -> {
					return getCurrentValue(matchingDataset.getDateOfBirths())
							.map(localDateSimpleMdsValue -> userAccountCreationAttributeFactory.createUserAccountCreationVerifiedAttribute(UserAccountCreationAttribute.DATE_OF_BIRTH_VERIFIED, localDateSimpleMdsValue.isVerified()));
				});

				put(UserAccountCreationAttribute.CURRENT_ADDRESS, (matchingDataset) -> {
					return extractCurrentAddress(matchingDataset.getCurrentAddresses()).
							map(address -> userAccountCreationAttributeFactory.createUserAccountCreationCurrentAddressAttribute(ImmutableList.of(address)));
				});

				put(UserAccountCreationAttribute.CURRENT_ADDRESS_VERIFIED, (matchingDataset) -> {
					return extractCurrentAddress(matchingDataset.getCurrentAddresses()).map(address ->
					userAccountCreationAttributeFactory.createUserAccountCreationVerifiedAttribute(UserAccountCreationAttribute.CURRENT_ADDRESS_VERIFIED, address.isVerified()));
				});

				put(UserAccountCreationAttribute.ADDRESS_HISTORY, (matchingDataset) -> {
					List<Address> allAddresses = matchingDataset.getAddresses();
					return optionalOfList(allAddresses, userAccountCreationAttributeFactory.createUserAccountCreationAddressHistoryAttribute(ImmutableList.copyOf(allAddresses)));
				});
			}
		};
		
		return map;
	}

}
