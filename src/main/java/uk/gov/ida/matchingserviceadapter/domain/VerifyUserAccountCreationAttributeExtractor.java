package uk.gov.ida.matchingserviceadapter.domain;

import com.google.inject.Inject;

public class VerifyUserAccountCreationAttributeExtractor extends UserAccountCreationAttributeExtractor {

    @Inject
    public VerifyUserAccountCreationAttributeExtractor() {
    }

    @Override
    VerifyUserAccountCreationAttribute getAttributeExtractor(String name) {
         return VerifyUserAccountCreationAttribute.getUserAccountCreationAttribute(name);
    }
}
