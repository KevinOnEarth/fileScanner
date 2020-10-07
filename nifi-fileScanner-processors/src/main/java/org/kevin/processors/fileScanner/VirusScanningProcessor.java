/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.kevin.processors.fileScanner;

import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import org.apache.nifi.annotation.behavior.ReadsAttribute;
import org.apache.nifi.annotation.behavior.ReadsAttributes;
import org.apache.nifi.annotation.behavior.WritesAttribute;
import org.apache.nifi.annotation.behavior.WritesAttributes;
import org.apache.nifi.annotation.documentation.CapabilityDescription;
import org.apache.nifi.annotation.documentation.SeeAlso;
import org.apache.nifi.annotation.documentation.Tags;
import org.apache.nifi.annotation.lifecycle.OnScheduled;
import org.apache.nifi.components.PropertyDescriptor;
import org.apache.nifi.flowfile.FlowFile;
import org.apache.nifi.processor.AbstractProcessor;
import org.apache.nifi.processor.ProcessContext;
import org.apache.nifi.processor.ProcessSession;
import org.apache.nifi.processor.ProcessorInitializationContext;
import org.apache.nifi.processor.Relationship;
import org.apache.nifi.processor.exception.ProcessException;
import org.apache.nifi.processor.util.StandardValidators;

import xyz.capybara.clamav.ClamavClient;
import xyz.capybara.clamav.commands.scan.result.ScanResult;


@Tags({"example"})
@CapabilityDescription("Provide a description")
@SeeAlso({})
@ReadsAttributes({@ReadsAttribute(attribute="", description="")})
@WritesAttributes({@WritesAttribute(attribute="", description="")})
public class VirusScanningProcessor extends AbstractProcessor {

    public static final PropertyDescriptor VIRUS_SCANNER_IP = new PropertyDescriptor
            .Builder().name("VIRUS_SCANNER_IP")
            .displayName("IP Of Virus Scanner")
            .description("The IP of the server running the virus scanner")
            .required(true)
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .build();

    public static final PropertyDescriptor VIRUS_SCANNER_PORT = new PropertyDescriptor
            .Builder().name("VIRUS_SCANNER_PORT")
            .displayName("Port Of Virus Scanner")
            .description("The port of the server running the virus scanner")
            .required(true)
            .addValidator(StandardValidators.NON_EMPTY_VALIDATOR)
            .addValidator(StandardValidators.INTEGER_VALIDATOR)
            .build();
    
    public static final Relationship ERROR = new Relationship.Builder()
            .name("ERROR")
            .description("Failed Virus Scan")
            .build();

    public static final Relationship VIRUS_FOUND = new Relationship.Builder()
            .name("VIRUS")
            .description("Found a Virus on Scan")
            .build();

    public static final Relationship SUCCESS = new Relationship.Builder()
            .name("SUCCESS")
            .description("Passed Virus Scan")
            .build();

    private List<PropertyDescriptor> descriptors;

    private Set<Relationship> relationships;

    @Override
    protected void init(final ProcessorInitializationContext context) {
        final List<PropertyDescriptor> descriptors = new ArrayList<PropertyDescriptor>();
        descriptors.add(VIRUS_SCANNER_IP);
        descriptors.add(VIRUS_SCANNER_PORT);
        this.descriptors = Collections.unmodifiableList(descriptors);

        final Set<Relationship> relationships = new HashSet<Relationship>();
        relationships.add(SUCCESS);
        relationships.add(ERROR);
        relationships.add(VIRUS_FOUND);
        this.relationships = Collections.unmodifiableSet(relationships);
    }

    @Override
    public Set<Relationship> getRelationships() {
        return this.relationships;
    }

    @Override
    public final List<PropertyDescriptor> getSupportedPropertyDescriptors() {
        return descriptors;
    }

    @OnScheduled
    public void onScheduled(final ProcessContext context) {

    }
//  
//  private String getListOfViruses(Map<String, Collection<String>> viruses) {
//  	String returnString = viruses.entrySet()
//  			.stream()
//  			.map(entry -> entry.getKey() + " - " + entry.getValue())
//  			.collect(Collectors.joining(","));
//  	return returnString;
//  }
    public VirusScanningReturnObject scanStream(InputStream inputStream, String scannerIp, Integer scannerPort) throws IOException, NoSuchAlgorithmException {
    	VirusScanningReturnObject vsro = new VirusScanningReturnObject();
    	try {
    		
        	ClamavClient client = new ClamavClient(scannerIp, scannerPort);
        	ScanResult scanResult = client.scan(inputStream);
        	if (scanResult instanceof ScanResult.OK) {
        		vsro.setRelationship(SUCCESS); 
        	} else if (scanResult instanceof ScanResult.VirusFound) {
        		Map<String, Collection<String>> virusMap = ((ScanResult.VirusFound) scanResult).getFoundViruses();
        		virusMap.forEach((k,v) -> {
        			vsro.setVirusList(k);
        			vsro.setVirusList(": "+v.stream()
        							    .collect(Collectors.joining(",")));
        			//v.forEach(virusString -> vsro.setVirusList(virusString));
        		});
        		vsro.setRelationship(VIRUS_FOUND);
        	} else {
        		vsro.setRelationship(ERROR);
        	}
    	} finally {
            try {
                if (inputStream != null){
                    inputStream.close();
                }
            } catch (IOException e) {
                System.out.println("Exception occurred while closing inputStream = {} "+ e.getMessage());
            }
    	}
    	return vsro;
    }

    @Override
    public void onTrigger(final ProcessContext context, final ProcessSession session) throws ProcessException {
        FlowFile flowFile = session.get();
        if ( flowFile == null ) {
            return;
        }
        try (InputStream inputStream = session.read(flowFile)){
        	System.out.println("About to scan");
        	String scannerIp = context.getProperty(VIRUS_SCANNER_IP).getValue();
        	Integer scannerPort = Integer.valueOf(context.getProperty(VIRUS_SCANNER_PORT).getValue());
        	VirusScanningReturnObject vsro = scanStream(inputStream, scannerIp, scannerPort);
        	if (vsro.getRelationship().equals(VIRUS_FOUND))
        		session.putAttribute(flowFile, "Virus List", vsro.getVirusList());
            session.transfer(flowFile, vsro.getRelationship());
        } catch (IOException | NoSuchAlgorithmException e) {
            e.printStackTrace();
            session.putAttribute(flowFile, "Error", e.getMessage());
            session.transfer(flowFile, ERROR);
            
        }

    }
   
 
}
