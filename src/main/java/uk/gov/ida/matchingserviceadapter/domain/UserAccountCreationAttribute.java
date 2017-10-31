package uk.gov.ida.matchingserviceadapter.domain;

import java.io.Serializable;
import java.util.Arrays;

public enum UserAccountCreationAttribute implements Serializable {
    FIRST_NAME("firstname"),
    FIRST_NAME_VERIFIED("firstname_verified"),
    MIDDLE_NAME("middlename"),
    MIDDLE_NAME_VERIFIED("middlename_verified"),
    SURNAME("surname"),
    SURNAME_VERIFIED("surname_verified"),
    DATE_OF_BIRTH("dateofbirth"),
    DATE_OF_BIRTH_VERIFIED("dateofbirth_verified"),
    CURRENT_ADDRESS("currentaddress"),
    CURRENT_ADDRESS_VERIFIED("currentaddress_verified"),
    ADDRESS_HISTORY("addresshistory"),
    CYCLE_3("cycle_3");

    private String attributeName;

    UserAccountCreationAttribute(final String attributeName) {
        this.attributeName = attributeName;
    }

    public String getAttributeName(){
        return attributeName;
    }

    public static UserAccountCreationAttribute getUserAccountCreationAttribute(final String name){
        return Arrays.stream(values())
                .filter(value -> value.getAttributeName().equals(name))
                .findFirst()
                .get();
    }
}
