package in.rbihub.controller;

import in.rbihub.model.ESignDTO;
import in.rbihub.service.EsignService;
import in.rbihub.validation.Validator;
import org.apache.log4j.LogManager;
import org.apache.log4j.Logger;
import org.json.JSONObject;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.Resource;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.multipart.MultipartFile;
//import io.swagger.annotations.ApiOperation;

import javax.servlet.http.HttpServletRequest;
import java.io.File;

@RestController
public class ESignController {

    private static final Logger logger = LogManager.getLogger(ESignController.class);
    @Autowired
    private EsignService esignService;


    //@ApiOperation(value = "To get list of land owners", response = String.class, code = 200)
    @PostMapping(path= "/eSign/{version}/{lang}", consumes = {MediaType.APPLICATION_FORM_URLENCODED_VALUE,
            MediaType.MULTIPART_FORM_DATA_VALUE,MediaType.APPLICATION_PDF_VALUE})
    public String getSignedDocument(@RequestParam(value = "inputFile" , required = true) MultipartFile file,
                                    @PathVariable("version") String version, @PathVariable("lang") String lang,
                                    @RequestHeader("api_key") String licensekey, @RequestHeader("txncode") String txncode,
                                    @RequestHeader("clientid") String clientid, @RequestHeader("consent") String consent,
                                    @RequestHeader("consentId") String consentId, @RequestHeader("authtype") int authtype,
                                    @RequestHeader("requestername") String requestername, @RequestHeader("requesterlocation") String requesterlocation,
                                    @RequestHeader("purpose") String purpose, @RequestHeader("signxposition") int signxposition,
                                    @RequestHeader("signyposition") int signyposition, 
                                    
                                    
                                    HttpServletRequest request) throws Exception {

        String logtraceMsg = "[ srcIP : " + request.getRemoteAddr() + ", clientId : " + clientid + ", apikey : "
                + licensekey + ", txncode : " + txncode + "] ";
        
        logger.info(logtraceMsg);

        /**
         * Common validation for the URI Parameters are done below for version, txncode, lang, api-key and consent
         */
        
        JSONObject response = null;

        Validator validator = new Validator();
        response = validator.validateCommonURIParams(logtraceMsg, version, txncode, lang, licensekey, consent, consentId);

        if (response != null) {
            return response.toString();
        }

        JSONObject signedDocument = esignService.getSignedDocument(logtraceMsg,txncode, authtype,  requestername, requesterlocation, purpose, signxposition, signyposition, file);
        return signedDocument.toString();
    }

    @PostMapping(path = "/eSignCallback",consumes = {MediaType.MULTIPART_FORM_DATA_VALUE})
    public String postSignedDocument(String msg, HttpServletRequest request) throws Exception {

        logger.info("Inside The Platform callback eSign rest-endpoint"+msg);
        
        System.out.println("msg");
        System.out.println(msg);
        
        
        String logtraceMsg = "[ srcIP : " + request.getRemoteAddr() + ", clientId : 'ASPRBIHUAT006571', apikey : 'WSgMgn8ZcUX2VGHrDIH9ABCD', txncode : '1234'] ";
        
        logger.info(logtraceMsg);
        
        JSONObject response = esignService.SignDocument(logtraceMsg,"1234", msg);
		return response.toString();

        //return ;
    }

    @GetMapping("/")
    public String index() {

        return "Greetings from RBiH - microservice!";
    }
}
