package uk.gov.ida.matchingserviceadapter.validators;

import org.joda.time.DateTime;
import org.joda.time.Duration;
import org.junit.Before;
import org.junit.Test;
import org.opensaml.saml.saml2.core.SubjectConfirmationData;
import uk.gov.ida.saml.core.IdaSamlBootstrap;
import uk.gov.ida.validation.messages.Messages;

import static java.util.function.Function.identity;
import static org.assertj.core.api.Assertions.assertThat;
import static uk.gov.ida.matchingserviceadapter.validators.SubjectConfirmationDataValidator.CONFIRMATION_DATA_NOT_PRESENT;
import static uk.gov.ida.matchingserviceadapter.validators.SubjectConfirmationDataValidator.IN_RESPONSE_TO_NOT_PRESENT;
import static uk.gov.ida.matchingserviceadapter.validators.SubjectConfirmationDataValidator.NOT_BEFORE_INVALID;
import static uk.gov.ida.matchingserviceadapter.validators.SubjectConfirmationDataValidator.NOT_ON_OR_AFTER_INVALID;
import static uk.gov.ida.matchingserviceadapter.validators.SubjectConfirmationDataValidator.NOT_ON_OR_AFTER_NOT_PRESENT;
import static uk.gov.ida.matchingserviceadapter.validators.SubjectConfirmationDataValidator.RECIPIENT_NOT_PRESENT;
import static uk.gov.ida.saml.core.test.builders.SubjectConfirmationDataBuilder.aSubjectConfirmationData;
import static uk.gov.ida.validation.messages.MessagesImpl.messages;

public class SubjectConfirmationDataValidatorTest {

    private static final String DEFAULT_REQUEST_ID = "some request id";

    private SubjectConfirmationDataValidator<SubjectConfirmationData> validator;

    public TimeRestrictionValidator timeRestrictionValidator = new TimeRestrictionValidator(new DateTimeComparator(Duration.ZERO));

    @Before
    public void setup() {
        validator = new SubjectConfirmationDataValidator<>(identity(), timeRestrictionValidator);
        IdaSamlBootstrap.bootstrap();
    }

    @Test
    public void shouldGenerateErrorWhenSubjectConfirmationDataMissing() throws Exception {
        Messages messages = validator.validate(null, messages());

        assertThat(messages.hasErrorLike(CONFIRMATION_DATA_NOT_PRESENT)).isTrue();
    }

    @Test
    public void shouldGenerateErrorWhenSubjectConfirmationDataNotOnOrAfterIsMissing() throws Exception {
        SubjectConfirmationData subjectConfirmationData = aSubjectConfirmationData().withNotOnOrAfter(null).build();

        Messages messages = validator.validate(subjectConfirmationData, messages());

        assertThat(messages.hasErrorLike(NOT_ON_OR_AFTER_NOT_PRESENT)).isTrue();
    }

    @Test
    public void shouldGenerateErrorWhenSubjectConfirmationDataNotOnOrAfterIsInThePast() throws Exception {
        SubjectConfirmationData subjectConfirmationData = aSubjectConfirmationData().withNotOnOrAfter(DateTime.now().minusMinutes(5)).build();

        Messages messages = validator.validate(subjectConfirmationData, messages());

        assertThat(messages.hasErrorLike(NOT_ON_OR_AFTER_INVALID)).isTrue();
    }

    @Test
    public void shouldGenerateErrorWhenSubjectConfirmationDataNotBeforeIsInTheFuture() throws Exception {
        SubjectConfirmationData subjectConfirmationData = aSubjectConfirmationData().withNotBefore(DateTime.now().plusMinutes(10)).build();

        Messages messages = validator.validate(subjectConfirmationData, messages());

        assertThat(messages.hasErrorLike(NOT_BEFORE_INVALID)).isTrue();
    }

    @Test
    public void shouldGenerateErrorWhenSubjectConfirmationDataHasNoInResponseTo() throws Exception {
        SubjectConfirmationData subjectConfirmationData = aSubjectConfirmationData().withInResponseTo(null).build();

        Messages messages = validator.validate(subjectConfirmationData, messages());

        assertThat(messages.hasErrorLike(IN_RESPONSE_TO_NOT_PRESENT)).isTrue();
    }

    @Test
    public void shouldGenerateErrorWhenSubjectConfirmationDataHasNoRecipient() throws Exception {
        SubjectConfirmationData subjectConfirmationData = aSubjectConfirmationData().withInResponseTo(DEFAULT_REQUEST_ID).withRecipient(null).build();

        Messages messages = validator.validate(subjectConfirmationData, messages());

        assertThat(messages.hasErrorLike(RECIPIENT_NOT_PRESENT)).isTrue();
    }

}