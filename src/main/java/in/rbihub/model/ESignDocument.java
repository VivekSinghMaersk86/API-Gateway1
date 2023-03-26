package in.rbihub.model;

import javax.persistence.Column;  
import javax.persistence.Entity;  
import javax.persistence.Id;  
import javax.persistence.Table;  

//mark class as an Entity   
@Entity  
//defining class name as Table name  
@Table  
public class ESignDocument {
	@Id 
	@Column  
	private int id;  	
	
	@Column  
	private String transactionID;
	
	@Column  
	private String filePath;
	
	@Column  
	private int authType;
	
	@Column
	private String requesterName;
	
	@Column
	private String requesterLocation;
	
	@Column
	private String purpose;
	
	@Column
	private int signXPosition;
	
	@Column
	private int signYPosition;

	public int getId() {
		return id;
	}

	public void setId(int id) {
		this.id = id;
	}

	public String getTransactionID() {
		return transactionID;
	}

	public void setTransactionID(String transactionID) {
		this.transactionID = transactionID;
	}

	public String getFilePath() {
		return filePath;
	}

	public void setFilePath(String filePath) {
		this.filePath = filePath;
	}

	public int getAuthType() {
		return authType;
	}

	public void setAuthType(int authType) {
		this.authType = authType;
	}

	public String getRequesterName() {
		return requesterName;
	}

	public void setRequesterName(String requesterName) {
		this.requesterName = requesterName;
	}

	public String getRequesterLocation() {
		return requesterLocation;
	}

	public void setRequesterLocation(String requesterLocation) {
		this.requesterLocation = requesterLocation;
	}

	public String getPurpose() {
		return purpose;
	}

	public void setPurpose(String purpose) {
		this.purpose = purpose;
	}

	public int getSignXPosition() {
		return signXPosition;
	}

	public void setSignXPosition(int signXPosition) {
		this.signXPosition = signXPosition;
	}

	public int getSignYPosition() {
		return signYPosition;
	}

	public void setSignYPosition(int signYPosition) {
		this.signYPosition = signYPosition;
	}

	

}
