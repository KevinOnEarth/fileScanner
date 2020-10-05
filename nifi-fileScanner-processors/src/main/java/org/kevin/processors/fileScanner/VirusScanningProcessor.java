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
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

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
    
    public static String scanStream(InputStream inputStream, String scannerIp, Integer scannerPort) throws IOException, NoSuchAlgorithmException {
    	try {
        	ClamavClient client = new ClamavClient(scannerIp, scannerPort);
        	ScanResult scanResult = client.scan(inputStream);
        	if (scanResult instanceof ScanResult.OK) {
        		return "OK";
        	} else if (scanResult instanceof ScanResult.VirusFound) {
        		return "VIRUS";
        	} else {
        		return "ERROR";
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
    }

 /*   public static String scanStream(InputStream inputStream, String scannerIp, Integer scannerPort) throws IOException, NoSuchAlgorithmException {
        Socket socket = null;
        OutputStream outStream = null;
        InputStream inStream = null;
        String returnString = null;
 //       String scannerEndpoint = "http://172.17.0.3:8080/scan";
        //curl -F "name=blabla" -F "file=@/tmp/k/eicar.com" http://172.17.0.3:8080/scan
        try {
            socket = new Socket(scannerIp, scannerPort);
            outStream = new BufferedOutputStream(socket.getOutputStream());
            socket.setSoTimeout(2000);
            outStream.write("zINSTREAM\0".getBytes(StandardCharsets.UTF_8));
            outStream.flush();
            byte[] buffer = new byte[2048];
            try {
            	
                inStream = socket.getInputStream();
                int read = inputStream.read(buffer);
                while (read >= 0) {
                    byte[] chunkSize = ByteBuffer.allocate(4).putInt(read).array();
                    outStream.write(chunkSize);
                    outStream.write(buffer, 0, read);
                    if (inStream.available() > 0) {
                        byte[] reply = IOUtils.toByteArray(inStream);
                        throw new IOException("Reply from server: " + new String(reply, StandardCharsets.UTF_8));
                    }
                    read = inputStream.read(buffer);
                }
                outStream.write(new byte[]{0,0,0,0});
                outStream.flush();
                returnString = new String(IOUtils.toByteArray(inputStream));
                
            } finally {
                try {
                    if (inputStream != null){
                        inputStream.close();
                    }
                } catch (IOException e) {
                    System.out.println("Exception occurred while closing inputStream = {} "+ e.getMessage());
                }
                try {
                    if (outStream != null){
                    	outStream.close();
                    }
                } catch (IOException e) {
                    System.out.println("Exception occurred while closing outStream = {} "+ e.getMessage());
                }
            }
        }finally {
            try {
                if(socket != null)
                    socket.close();
            } catch (IOException e) {
                System.out.println("Exception occurred while closing socket = {} "+ e.getMessage());
            }
            try {
                if(inStream != null)
                    inStream.close();
            } catch(IOException e) {
                System.out.println("Exception occurred while closing input streams = {} "+ e.getMessage());
            }
            try {
                if(outStream != null)
                    outStream.close();
            } catch(IOException e) {
                System.out.println("Exception occurred while closing output streams = {} "+ e.getMessage());
            }
        }
        return returnString;
    }

*/


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
            String result = scanStream(inputStream, scannerIp, scannerPort);
            session.putAttribute(flowFile, "scanResult", result);
            if ("OK".equals(result)) {
                session.transfer(flowFile, SUCCESS);
            } else if ("VIRUS".equals(result)) {
            	session.transfer(flowFile, VIRUS_FOUND);
            } else {
                session.transfer(flowFile, ERROR);            	
            }
        } catch (IOException | NoSuchAlgorithmException e) {
            e.printStackTrace();
            flowFile = session.putAttribute(flowFile, "log", e.getMessage());
            session.putAttribute(flowFile, "Virus", e.getMessage());
            session.transfer(flowFile, ERROR);
            
        }

    }
   
 
}
