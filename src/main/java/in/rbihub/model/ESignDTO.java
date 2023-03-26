package in.rbihub.model;

import org.springframework.web.multipart.MultipartFile;

public class ESignDTO {

    private String rspMsg;
    private MultipartFile documentData;

    public String getRspMsg() {
        return rspMsg;
    }

    public void setRspMsg(String rspMsg) {
        this.rspMsg = rspMsg;
    }

    public MultipartFile getDocumentData() {
        return documentData;
    }

    public void setDocumentData(MultipartFile documentData) {
        this.documentData = documentData;
    }
}

