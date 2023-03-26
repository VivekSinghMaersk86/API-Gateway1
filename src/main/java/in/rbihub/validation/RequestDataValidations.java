package in.rbihub.validation;

import in.rbihub.error.InvalidParamException;
import in.rbihub.utils.PlatformConstants;

import java.util.Objects;

public class RequestDataValidations implements IDataValidation {

    private static RequestDataValidations requestDataValidations = new RequestDataValidations();

    public static RequestDataValidations getInstance() {

        return requestDataValidations;
    }

    /**
     * Validation for all common URL Parameters like version, apikey, lang, txncode
     * and consent
     *
     * @param version
     * @param apikey
     * @param lang
     * @param txncode
     * @return true in case validation is success
     */
    public boolean validateCommonURLParams(String version, String apikey, String lang, String txncode, String consent,
                                           String consentId) throws InvalidParamException {

        if (version != null && apikey != null && lang != null && txncode != null) {
            return isVersionValid(version) && isAPIKeyValid(apikey) && isISOLangValid(lang) && isTxncodeValid(txncode)
                    && isConsentIDValid(consentId, consent);
        } else {
            return false;
        }
    }


    /**
     * Validation for all common URL Parameters for POST  like version, apikey, lang
     *
     * @param version
     * @param apikey
     * @param lang
     * @return true in case validation is success
     */
    public boolean validateCommonURPOSTLParams(String version, String apikey, String lang) throws InvalidParamException{
        if (version != null && apikey != null && lang != null ) {
            return isVersionValid(version) && isAPIKeyValid(apikey) && isISOLangValid(lang);
        } else {
            return false;
        }
    }

    /**
     * Validation for all common URL Parameters like version, apikey, lang, txncode
     * and consent
     *
     * @param version
     * @param apikey
     * @param lang
     * @param txncode
     * @return true in case validation is success
     */
    public boolean validateCommonURLParamsWithOutConsent(String version, String apikey, String lang, String txncode)
            throws InvalidParamException {

        if (version != null && apikey != null && lang != null && txncode != null) {
            return isVersionValid(version) && isAPIKeyValid(apikey) && isISOLangValid(lang) && isTxncodeValid(txncode);
        } else {
            return false;
        }
    }

    /**
     * This specific validation for the version field in url can take values like
     * 1.0, 2.1 etc
     *
     * @param version
     * @return true in case validation is success
     */
    public boolean isVersionValid(String version) throws InvalidParamException {
        if (version == null || version.trim().equals("") || !version.equals(PlatformConstants.VERION_SUPPORTED)) {
            throw new InvalidParamException(InvalidParamException.ErrorCodes.E009,
                    InvalidParamException.getErrorDescription(InvalidParamException.ErrorCodes.E009));
        } else {
            return true;
        }
    }

    /**
     * This specific validation for the timestamp field  values like below
     * "timestamp in ISO-8601 format e.g. 2023-01-03T21:10:23+05:30[Asia/Kolkata]"
     *
     * @param timestamp
     * @return true in case validation is success
     */
    public boolean isTSValid(String timestamp) throws InvalidParamException {
        if (timestamp == null || timestamp.trim().equals("") ) {
            throw new InvalidParamException(InvalidParamException.ErrorCodes.E010,
                    InvalidParamException.getErrorDescription(InvalidParamException.ErrorCodes.E010));
        } else {
            return true;
        }
    }

    /**
     * This specific validation for the apikey field in url. this field needs to be
     * filled as it caters for log tracing for dispute resolution
     *
     * @param apikey
     * @return true in case validation is success
     */
    public boolean isAPIKeyValid(String apikey) throws InvalidParamException {
        if (apikey == null || apikey.trim().equals("") || apikey.length() != 24 || !apikey.matches("[A-Za-z0-9]+")) {
            throw new InvalidParamException(InvalidParamException.ErrorCodes.E032,
                    InvalidParamException.getErrorDescription(InvalidParamException.ErrorCodes.E032));
        } else {
            return true;
        }
    }

    /**
     * This specific validation for the lang field in url and can have value like
     * english -99,hindi -06
     *
     * @param lang
     * @return true in case validation is success
     */
    public boolean isLangValid(Integer lang) throws InvalidParamException {
        try {
            if (lang.intValue() == PlatformConstants.LANGCODE_ENGLISH) {
                return true;
            }
            if (!(lang.intValue() > 0 || lang.intValue() < 23)) {
                throw new InvalidParamException(InvalidParamException.ErrorCodes.E033,
                        InvalidParamException.getErrorDescription(InvalidParamException.ErrorCodes.E033));
            } else if (!(lang.intValue() == PlatformConstants.LANGCODE_TAMIL
                    || lang.intValue() == PlatformConstants.LANGCODE_ORIYA
                    || lang.intValue() == PlatformConstants.LANGCODE_MARATHI
                    || lang.intValue() == PlatformConstants.LANGCODE_HINDI)) {
                throw new InvalidParamException(InvalidParamException.ErrorCodes.E033,
                        InvalidParamException.getErrorDescription(InvalidParamException.ErrorCodes.E033));

            } else {
                return true;
            }

        } catch (Exception exp) {
            throw new InvalidParamException(InvalidParamException.ErrorCodes.E033,
                    InvalidParamException.getErrorDescription(InvalidParamException.ErrorCodes.E033));
        }

    }

    /**
     * This specific validation for the txncode field in url this needs to be filled
     * as it caters for log tracing for dispute resolution
     *
     * @param txncode
     * @return true in case validation is success
     */
    public boolean isTxncodeValid(String txncode) throws InvalidParamException {
        if (txncode == null || txncode.trim().equals("") || !txncode.matches("[A-Za-z0-9]+")) {
            throw new InvalidParamException(InvalidParamException.ErrorCodes.E034,
                    InvalidParamException.getErrorDescription(InvalidParamException.ErrorCodes.E034));
        } else {
            return true;
        }
    }
    /**
     * This specific validation for the hmac field this needs to be
     * checked for the data payload verification
     *
     * @param hmac
     * @return true in case validation is success
     */
    public boolean isHmacValid(String hmac) throws InvalidParamException{
        if (hmac == null || hmac.trim().equals("") || hmac.length() > 60) {
            throw new InvalidParamException(InvalidParamException.ErrorCodes.E042,
                    InvalidParamException.getErrorDescription(InvalidParamException.ErrorCodes.E042));
        } else {
            return true;
        }
    }

    /**
     * This specific validation for the ClientId field in url this needs to be
     * filled as it caters for log tracing for dispute resolution
     *
     * @param clientId
     * @return true in case validation is success
     */
    public boolean isClientIdValid(String clientId) throws InvalidParamException {
        if (clientId == null || clientId.trim().equals("") || !clientId.matches("[A-Za-z0-9]+")) {
            throw new InvalidParamException(InvalidParamException.ErrorCodes.E028,
                    InvalidParamException.getErrorDescription(InvalidParamException.ErrorCodes.E028));
        } else {
            return true;
        }
    }

    /**
     * This specific validation for the Consent field and its mandatory for consent
     * in case of handling sensitive PI data
     *
     * @param consent
     * @return true in case validation is success
     */
    public boolean isConsentValid(String consent) throws InvalidParamException {
        if (consent == null || consent.trim().equals("")) {
            throw new InvalidParamException(InvalidParamException.ErrorCodes.E035,
                    InvalidParamException.getErrorDescription(InvalidParamException.ErrorCodes.E035));
        } else {
            if (consent.equalsIgnoreCase("y") || consent.equalsIgnoreCase("n")) {
                return true;
            }
            throw new InvalidParamException(InvalidParamException.ErrorCodes.E035,
                    InvalidParamException.getErrorDescription(InvalidParamException.ErrorCodes.E035));
        }
    }

    /**
     * This specific validation for the ConsentID field and its mandatory for
     * consent in case of handling sensitive PI data. The ConsentID is must in case
     * consent is provided
     *
     * @param consentId
     * @param consent
     * @return true in case validation is success
     */
    public boolean isConsentIDValid(String consentId, String consent) throws InvalidParamException {
        if (consent.equalsIgnoreCase("y")
                && (consentId == null || consentId.trim().equals("") || !consentId.matches("[A-Za-z0-9]+"))) {
            throw new InvalidParamException(InvalidParamException.ErrorCodes.E036,
                    InvalidParamException.getErrorDescription(InvalidParamException.ErrorCodes.E036));
        }
        return true;
    }

    /**
     * This specific validation for the name field and can have values of name in
     * local language Not using MDDS Standard : G01.02-02
     * https://www.javatpoint.com/java-string-max-size
     *
     * @param name
     * @return
     */
    public boolean isValidName(String name, String srclang) throws InvalidParamException {
        boolean isValid = false;
        if (name == null || name.trim().equals("") || name.length() > 2147483647) {
            throw new InvalidParamException(InvalidParamException.ErrorCodes.E176,
                    InvalidParamException.getErrorDescription(InvalidParamException.ErrorCodes.E176));
        } else if (srclang.equalsIgnoreCase("en")) {
            if (!name.matches("[A-Za-z\\s]+")) {
                throw new InvalidParamException(InvalidParamException.ErrorCodes.E177,
                        InvalidParamException.getErrorDescription(InvalidParamException.ErrorCodes.E177));
            }
        } else if (srclang.equalsIgnoreCase("hi")) {
            if (!name.matches("[\\u0900-\\u097F\\s]+")) {
                throw new InvalidParamException(InvalidParamException.ErrorCodes.E178,
                        InvalidParamException.getErrorDescription(InvalidParamException.ErrorCodes.E178));
            }

        } else if (srclang.equalsIgnoreCase("tn")) {
            if (!name.matches("[\\u0B80-\\u0BFF\\s]+")) {
                throw new InvalidParamException(InvalidParamException.ErrorCodes.E179,
                        InvalidParamException.getErrorDescription(InvalidParamException.ErrorCodes.E179));
            }
        }
        isValid = true;
        return isValid;

    }

    /**
     * This specific validation for the address field and can have values of name in
     * local language Not using MDDS Standard : G01.02-02
     * https://www.javatpoint.com/java-string-max-size
     *
     * @param address
     * @param srclang
     * @return
     */
    public boolean isValidAddress(String address, String srclang) throws InvalidParamException {
        boolean isValid = false;
        if (address == null || address.trim().equals("") || address.length() > 2147483647) {
            throw new InvalidParamException(InvalidParamException.ErrorCodes.E182,
                    InvalidParamException.getErrorDescription(InvalidParamException.ErrorCodes.E182));
        } else if (srclang.equalsIgnoreCase("en")) {
            if (!address.matches("[A-Za-z\\s]+")) {
                throw new InvalidParamException(InvalidParamException.ErrorCodes.E183,
                        InvalidParamException.getErrorDescription(InvalidParamException.ErrorCodes.E183));
            }
        } else if (srclang.equalsIgnoreCase("hi")) {
            if (!address.matches("[\\u0900-\\u097F\\s]+")) {
                throw new InvalidParamException(InvalidParamException.ErrorCodes.E184,
                        InvalidParamException.getErrorDescription(InvalidParamException.ErrorCodes.E184));
            }

        } else if (srclang.equalsIgnoreCase("tn")) {
            if (!address.matches("[\\u0B80-\\u0BFF\\s]+")) {
                throw new InvalidParamException(InvalidParamException.ErrorCodes.E185,
                        InvalidParamException.getErrorDescription(InvalidParamException.ErrorCodes.E185));
            }
        }
        isValid = true;
        return isValid;

    }

    /**
     * This specific validation for source and destination in language supported for
     * MVP
     * @param srcLang
     * @param destLang
     * @return
     */
    public boolean isValidSrcAndDestLang(String srcLang, String destLang) throws InvalidParamException {
        boolean isValid = false;
        if (srcLang == null || srcLang.trim().equals("")) {
            throw new InvalidParamException(InvalidParamException.ErrorCodes.E180,
                    InvalidParamException.getErrorDescription(InvalidParamException.ErrorCodes.E180));
        }
        // Check the supported src lang for transliteration
        switch (srcLang) {
            case "en":
                break;
            case "hi":
                break;
            case "tn":
                break;
            default:
                throw new InvalidParamException(InvalidParamException.ErrorCodes.E180,
                        InvalidParamException.getErrorDescription(InvalidParamException.ErrorCodes.E180));
        }
        // Check the supported destination lang for transliteration
        switch (destLang) {
            case "en":
                break;
            case "hi":
                break;
            case "tn":
                break;
            default:
                throw new InvalidParamException(InvalidParamException.ErrorCodes.E033,
                        InvalidParamException.getErrorDescription(InvalidParamException.ErrorCodes.E033));
        }
        // Transliteration only supported for tn-> en, en -->tn hi --> en, en --> hi

        if (srcLang.equals("tn") && destLang.equals("hi")) {
            throw new InvalidParamException(InvalidParamException.ErrorCodes.E181,
                    InvalidParamException.getErrorDescription(InvalidParamException.ErrorCodes.E181));
        } else if (srcLang.equals("hi") && destLang.equals("tn")) {
            throw new InvalidParamException(InvalidParamException.ErrorCodes.E181,
                    InvalidParamException.getErrorDescription(InvalidParamException.ErrorCodes.E181));
        } else if (srcLang.equals(destLang)) {
            throw new InvalidParamException(InvalidParamException.ErrorCodes.E181,
                    InvalidParamException.getErrorDescription(InvalidParamException.ErrorCodes.E181));
        }
        isValid = true;
        return isValid;

    }

    /**
     * This specific validation for the distId field in url and can have values like
     * 18
     *
     * @param distId
     * @return
     */
    public boolean isValidDistrict(Integer distId) throws InvalidParamException {
        boolean isValid = false;

        if (distId.intValue() > 100) {
            throw new InvalidParamException(InvalidParamException.ErrorCodes.E501,
                    InvalidParamException.getErrorDescription(InvalidParamException.ErrorCodes.E501));
        }
        isValid = true;
        return isValid;

    }

    /**
     * This specific validation for the tehId field in url and can have values like
     * 03
     *
     * @param tehId
     * @return true in case validation is success
     */
    public boolean isValidTehId(String tehId) throws InvalidParamException {
        boolean isValid = false;
        if (tehId == null || tehId.trim().equals("")) {
            throw new InvalidParamException(InvalidParamException.ErrorCodes.E502,
                    InvalidParamException.getErrorDescription(InvalidParamException.ErrorCodes.E502));
        } else {
            try {
                int tehInt = Integer.parseInt(tehId);
                if (tehInt > 500) {
                    throw new InvalidParamException(InvalidParamException.ErrorCodes.E502,
                            InvalidParamException.getErrorDescription(InvalidParamException.ErrorCodes.E502));
                } else {
                    isValid = true;
                }
                return isValid;
            } catch (Exception exp) {
                throw new InvalidParamException(InvalidParamException.ErrorCodes.E502,
                        InvalidParamException.getErrorDescription(InvalidParamException.ErrorCodes.E502));
            }
        }
    }

    /**
     * This specific validation for the tehId field in url and can have values like
     * 118040200107207000995
     *
     * @param khasraId
     * @return true in case validation is success
     */
    public boolean isValidKhasaraId(String khasraId) throws InvalidParamException {
        if (khasraId == null || khasraId.trim().equals("")) {
            throw new InvalidParamException(InvalidParamException.ErrorCodes.E503,
                    InvalidParamException.getErrorDescription(InvalidParamException.ErrorCodes.E503));
        }
        return true;
    }

    /**
     * This specific validation for the lang field in url and can have value like
     * english -en,hindi -hi, Marathi - mr , Oriya - or, tamil - ta Codes for the
     * Representation of Names of Languages Codes arranged alphabetically by
     * alpha-3/ISO 639-2 Code
     * https://www.loc.gov/standards/iso639-2/php/code_list.php
     *
     * @param lang
     * @return true in case validation is success
     */
    public boolean isISOLangValid(String lang) throws InvalidParamException {
        try {
            if (lang == null || lang.trim().equals("")) {
                throw new InvalidParamException(InvalidParamException.ErrorCodes.E033,
                        InvalidParamException.getErrorDescription(InvalidParamException.ErrorCodes.E033));
            } else if (!(lang.trim().equals(PlatformConstants.LANGISO_HINDI)
                    || lang.trim().equals(PlatformConstants.LANGISO_ORIYA)
                    || lang.trim().equals(PlatformConstants.LANGISO_MARATHI)
                    || lang.trim().equals(PlatformConstants.LANGISO_ENGLISH)
                    || lang.trim().equals(PlatformConstants.LANGISO_TAMIL))) {
                throw new InvalidParamException(InvalidParamException.ErrorCodes.E033,
                        InvalidParamException.getErrorDescription(InvalidParamException.ErrorCodes.E033));

            } else {
                return true;
            }

        } catch (Exception exp) {
            throw new InvalidParamException(InvalidParamException.ErrorCodes.E033,
                    InvalidParamException.getErrorDescription(InvalidParamException.ErrorCodes.E033));
        }

    }

    public boolean isValidDocument(String document) throws InvalidParamException {
        boolean isValid = false;

        if (Objects.isNull(document)) {
            throw new InvalidParamException(InvalidParamException.ErrorCodes.E501,
                    InvalidParamException.getErrorDescription(InvalidParamException.ErrorCodes.E501));
        }
        isValid = true;
        return isValid;

    }
}

