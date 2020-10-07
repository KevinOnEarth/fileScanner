package org.kevin.processors.fileScanner;

import org.apache.nifi.processor.Relationship;

public class VirusScanningReturnObject {
	private Relationship relationship;
	private StringBuilder virusList;
	
	public Relationship getRelationship() {
		return relationship;
	}
	public void setRelationship(Relationship relationship) {
		this.relationship = relationship;
	}
	public String getVirusList() {
		return virusList.toString();
	}
	public void setVirusList(String virusList) {
		if (this.virusList == null) {
			this.virusList = new StringBuilder();
		}
		this.virusList.append(virusList);
	}
}
