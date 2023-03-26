package in.rbihub.service;

import com.nsdl.esign.preverifiedNo.controller.EsignApplication;
import in.rbihub.config.ApplicationConfig;
import in.rbihub.error.InvalidParamException;
import in.rbihub.model.ESignDocument;
import in.rbihub.repository.ESignDocumentRepository;
import in.rbihub.utils.CommonUtils;
import in.rbihub.utils.RSA;
import in.rbihub.validation.RequestDataValidations;
import io.micrometer.core.annotation.Timed;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;
import org.springframework.core.io.support.PropertiesLoaderUtils;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.json.JSONObject;
import org.springframework.web.multipart.MultipartFile;
import java.io.File;
import java.io.IOException;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.util.Properties;
import java.io.File;
import java.io.FileOutputStream;
import static in.rbihub.utils.EsignUtility.bytesToHex;
import in.rbihub.model.ESignDocument;

@Service
public class EsignService {

    private static final Logger log = LogManager.getLogger(EsignService.class);

    @Autowired
    private ApplicationConfig applicationConfig;
    
    @Autowired
    ESignDocumentRepository eSignDocumentRepository;

    private PrivateKey privateKey = null;


    public JSONObject SignDocument(String logtraceMsg, String txncode, String msg) throws Exception {
    	JSONObject resp = null;

        ClassPathResource resource = new ClassPathResource("application.properties");
        Properties props = PropertiesLoaderUtils.loadProperties(resource);
        
        
        ESignDocument eSignDocument = eSignDocumentRepository.findById(1).get(); 
        
        EsignApplication esignApplication = new EsignApplication();
        String responseData = "";
        
        if(eSignDocument != null) {
        	responseData = esignApplication.getSignOnDocument(msg, props.getProperty("fileUploadPath") + "/" + eSignDocument.getFilePath(), props.getProperty("fileUploadPath") + "/checkmark.jpeg", Integer.parseInt(props.getProperty("timeInterval")), eSignDocument.getAuthType(),eSignDocument.getRequesterName(), eSignDocument.getRequesterLocation(),eSignDocument.getPurpose(),eSignDocument.getSignYPosition(),eSignDocument.getSignXPosition(),Integer.parseInt(props.getProperty("signatureWidth")),Integer.parseInt(props.getProperty("signatureHeight")),"",props.getProperty("fileUploadPath"));
        } else {
        	responseData = esignApplication.getSignOnDocument(msg, props.getProperty("fileUploadPath") + "/" + props.getProperty("fileuploaded"), props.getProperty("fileUploadPath") + "/checkmark.jpeg", Integer.parseInt(props.getProperty("timeInterval")), Integer.parseInt(props.getProperty("authtype")),props.getProperty("requestername"), props.getProperty("requesterlocation"),props.getProperty("purpose"),Integer.parseInt(props.getProperty("signyposition")),Integer.parseInt(props.getProperty("signxposition")),Integer.parseInt(props.getProperty("signatureWidth")),Integer.parseInt(props.getProperty("signatureHeight")),"",props.getProperty("fileUploadPath"));
        }
        
        
        
        
        JSONObject jsonData = new JSONObject();
        jsonData.put("responsedata", responseData);
        
        
        resp = CommonUtils.getInstance().getPlatformResponseObject(InvalidParamException.ErrorCodes.E000, jsonData,
                applicationConfig.getSecretkey(), true, loadPrivateKey(), null,
                applicationConfig.getSigpassword().toCharArray(), txncode, logtraceMsg);
        
        return resp;
        
        
    }
    
    /**
     * This method will retrieve signed document and construct response based
     * on data received
     */
    
    @Timed(value = "EsignService.getSigned.Document", description = "Time to complete the query")
    public JSONObject getSignedDocument(String logtrcmsg, String txncode, int authtype, String requestername,String requesterlocation, String purpose, int signxposition, int signyposition, MultipartFile file) throws Exception {

        JSONObject resp = null;
        JSONObject tempdata = new JSONObject();
        boolean isValid = false;

        log.debug(logtrcmsg + ": Request Received with document :" + file.toString());
        
        
      

        try {
            isValid = RequestDataValidations.getInstance().isValidDocument(file.toString());
        } catch (InvalidParamException inpExcep) {
            resp = CommonUtils.getInstance().getPlatformResponseObject(inpExcep.getErrorCode(), tempdata,
                    applicationConfig.getSecretkey(), true, loadPrivateKey(), null,
                    applicationConfig.getSigpassword().toCharArray(), txncode, logtrcmsg);
            log.error(logtrcmsg + ": Request processed with response:" + resp);

            return resp;
        }

        if (!isValid) {
            resp = CommonUtils.getInstance().getPlatformResponseObject(InvalidParamException.ErrorCodes.E028, tempdata,
                    applicationConfig.getSecretkey(), true, loadPrivateKey(), null,
                    applicationConfig.getSigpassword().toCharArray(), txncode, logtrcmsg);
        } else {
            JSONObject data = new JSONObject();

            try {
            	
            	String fileName = StringUtils.cleanPath(file.getOriginalFilename());
                //byte[] documentContent = file.getBytes();

                // Create a MessageDigest instance for SHA-256
                //MessageDigest digest = MessageDigest.getInstance("SHA-256");

                // Calculate the hash value of the document content
                //byte[] hash = digest.digest(documentContent);

                // Convert the hash value to a hexadecimal string
                //String hashHex = bytesToHex(hash);

                ClassPathResource resource = new ClassPathResource("application.properties");
                Properties props = PropertiesLoaderUtils.loadProperties(resource);

                String aspId = props.getProperty("aspId");
                String authMode = props.getProperty("authMode");
                String alias = props.getProperty("alias");
                String txn = props.getProperty("txn");
                String p12CertificatePath = props.getProperty("p12CertificatePath");
                String p12CertiPwd = props.getProperty("p12CertiPwd");
                String signDocRequestXml = props.getProperty("signDocRequestXml");
                String respSignatureType = props.getProperty("respSignatureType");
                String responseUrl = props.getProperty("responseUrl");
                
                
                File path = new File(props.getProperty("fileUploadPath") + "/" + file.getOriginalFilename());
                path.createNewFile();
                FileOutputStream output = new FileOutputStream(path);
                output.write(file.getBytes());
                output.close();
                
                
                ESignDocument eSignDocument = new ESignDocument();
                eSignDocument.setId(1);
                eSignDocument.setAuthType(authtype);
                eSignDocument.setRequesterName(requestername);
                eSignDocument.setRequesterLocation(requesterlocation);
                eSignDocument.setPurpose(purpose);
                eSignDocument.setSignXPosition(signxposition);
                eSignDocument.setSignYPosition(signyposition);
                eSignDocument.setFilePath(fileName);
                eSignDocument.setTransactionID(txncode);
                
                eSignDocumentRepository.save(eSignDocument);  
                
                
                EsignApplication esignApplication = new EsignApplication();
                

                //String responseN = esignApplication.generateEsignRequestXmlUsingHash(signDocRequestXml, hashHex, aspId, authMode, responseUrl, p12CertificatePath, p12CertiPwd, alias, txn, respSignatureType);
                String responseN = esignApplication.getEsignRequestXml("",props.getProperty("fileUploadPath") + "/" + fileName, aspId,authMode, responseUrl, p12CertificatePath, p12CertiPwd, props.getProperty("fileUploadPath") + "/checkmark.jpeg",Integer.parseInt(props.getProperty("timeInterval")),alias,authtype, requestername, requesterlocation, purpose, signyposition,signxposition,Integer.parseInt(props.getProperty("signatureWidth")),Integer.parseInt(props.getProperty("signatureHeight")),"","");

                data.put("signedDocument",responseN);

            } catch (InvalidParamException exp) {
                resp = CommonUtils.getInstance().getPlatformResponseObject(exp.getErrorCode(), tempdata,
                        applicationConfig.getSecretkey(), true, loadPrivateKey(), null,
                        applicationConfig.getSigpassword().toCharArray(), txncode, logtrcmsg);
                return resp;
            }

            if (data == null) {
                // Internal error
                resp = CommonUtils.getInstance().getPlatformResponseObject(InvalidParamException.ErrorCodes.E025,
                        tempdata, applicationConfig.getSecretkey(), true, loadPrivateKey(), null,
                        applicationConfig.getSigpassword().toCharArray(), txncode, logtrcmsg);
            } else {

                log.debug(logtrcmsg + ": Received Signed Document details are: " + data);

                resp = CommonUtils.getInstance().getPlatformResponseObject(InvalidParamException.ErrorCodes.E000, data,
                        applicationConfig.getSecretkey(), true, loadPrivateKey(), null,
                        applicationConfig.getSigpassword().toCharArray(), txncode, logtrcmsg);

            }

        }
        log.info(logtrcmsg + ": Request processed with response:" + resp);
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
