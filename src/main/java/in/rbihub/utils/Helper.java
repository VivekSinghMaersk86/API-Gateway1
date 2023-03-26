package in.rbihub.utils;

import org.springframework.boot.web.servlet.server.Encoding;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.Collections;
import java.util.ArrayList;
import java.util.Base64;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;
import org.json.JSONArray;
import org.json.JSONObject;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestTemplate;

import in.rbihub.error.InvalidParamException;

public class Helper {

    private static Helper helper = new Helper();

    public static Helper getInstance() {
        return helper;
    }

    private RestTemplate restTemplate = new RestTemplate();
    private static final Logger log = LogManager.getLogger(Helper.class);

    public JSONObject performPostMethod(String logtrcmsg, String uri, String user, String password,
                                        Map<String, String> extraheaders, Map<String, Object> data) throws InvalidParamException {
        JSONObject result = null;
        try {
            // create headers
            HttpHeaders headers = new HttpHeaders();
            // set `content-type` header
            headers.setContentType(MediaType.APPLICATION_JSON_UTF8);
            // set `accept` header
            headers.setAcceptCharset(Collections.singletonList(StandardCharsets.UTF_8));
            headers.setAccept(Collections.singletonList(MediaType.APPLICATION_JSON));

            String aarequestEncodedString = Base64.getEncoder().encodeToString((user + ":" + password).getBytes());
            headers.set("Authorization", "Basic " + aarequestEncodedString);
            // Add any extra headers
            if (extraheaders != null) {
                for (Map.Entry<String, String> entry : extraheaders.entrySet()) {
                    headers.set(entry.getKey(), entry.getValue());
                }
            }
            // build the request
            HttpEntity<Map<String, Object>> entity = new HttpEntity<>(data, headers);
            // send POST request
            ResponseEntity<String> response = restTemplate.postForEntity(uri, entity, String.class);

            // check response
            if (response.getStatusCode() == HttpStatus.OK || response.getStatusCode() == HttpStatus.CREATED) {
                log.debug(logtrcmsg + "Request Successful: " + response.toString());
                result = new JSONObject(response.getBody());
            } else {
                log.info(logtrcmsg + "Transliteration Service Request Failed " + response.getStatusCode());
                throw new InvalidParamException(InvalidParamException.ErrorCodes.E031,
                        InvalidParamException.getErrorDescription(InvalidParamException.ErrorCodes.E031));
            }
        } catch (InvalidParamException invExp) {
            throw invExp;

        } catch (Exception e) {
            log.info(logtrcmsg + "Transliteration Service Request with error: " + e.getMessage());
            throw new InvalidParamException(InvalidParamException.ErrorCodes.E031,
                    InvalidParamException.getErrorDescription(InvalidParamException.ErrorCodes.E031));
        }
        return result;
    }
}

