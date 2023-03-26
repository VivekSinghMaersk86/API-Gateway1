package in.rbihub.validation;

import in.rbihub.config.ApplicationConfig;
import in.rbihub.error.InvalidParamException;
import in.rbihub.utils.CommonUtils;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;

import java.io.File;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.SignatureException;

import in.rbihub.utils.RSA;


public class Validator {

    private static final Logger log = LogManager.getLogger(Validator.class);

    private PrivateKey privateKey = null;

    @Autowired
    private ApplicationConfig applicationConfig;

    public Validator() {

    }


    /**
     * This method is responsible to validate all common uri params like version,
     * txncode, lang and apikey
     *
     * @param logtrcmsg
     * @param version
     * @param txncode
     * @param lang
     * @param apikey
     * @return
     * @throws SignatureException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    public JSONObject validateCommonURIParams(String logtrcmsg, String version, String txncode, String lang,
                                              String apikey, String consent, String consentId)
            throws InvalidKeyException, NoSuchAlgorithmException, SignatureException {
        JSONObject resp = null;
        boolean isValid = false;
        JSONObject data = new JSONObject();
        try {
            isValid = RequestDataValidations.getInstance().validateCommonURLParams(version, apikey, lang, txncode,
                    consent, consentId);

        } catch (InvalidParamException invExp) {
            resp = CommonUtils.getInstance().getPlatformResponseObject(invExp.getErrorCode(), data,
                    applicationConfig.getSecretkey(), true, loadPrivateKey(), null,
                    applicationConfig.getSigpassword().toCharArray(), txncode, logtrcmsg);
            log.info(logtrcmsg + ": Request processed with response:" + resp);
            return resp;
        }

        if (!isValid) {
            resp = CommonUtils.getInstance().getPlatformResponseObject(InvalidParamException.ErrorCodes.E028, data,
                    applicationConfig.getSecretkey(), true, loadPrivateKey(), null,
                    applicationConfig.getSigpassword().toCharArray(), txncode, logtrcmsg);
            log.info(logtrcmsg + ": Request processed with response:" + resp);
        } else if (!consent.equalsIgnoreCase("y")) {
            resp = CommonUtils.getInstance().getPlatformResponseObject(InvalidParamException.ErrorCodes.E030, data,
                    applicationConfig.getSecretkey(), true, loadPrivateKey(), null,
                    applicationConfig.getSigpassword().toCharArray(), txncode, logtrcmsg);
            log.info(logtrcmsg + ": Request processed with response:" + resp);
        } else if (consent.equalsIgnoreCase("y")) {
            log.info(logtrcmsg + ": Consent provided with ID :" + consentId);
        }

        return resp;
    }

    private PrivateKey loadPrivateKey() {

        try {
            if (privateKey == null) {
                privateKey = RSA.readPEMPrivateKey(new File(applicationConfig.getPrivatekey()));
            }
        } catch (Exception exp) {

        }
        return privateKey;
    }
}
