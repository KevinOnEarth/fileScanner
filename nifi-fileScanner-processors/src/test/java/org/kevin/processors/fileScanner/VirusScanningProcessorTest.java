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

import static org.junit.Assert.assertTrue;

import java.io.IOException;
import java.io.InputStream;
import java.security.NoSuchAlgorithmException;
import java.util.List;

import org.apache.nifi.util.MockFlowFile;
import org.apache.nifi.util.TestRunner;
import org.apache.nifi.util.TestRunners;
import org.junit.Before;
import org.junit.Ignore;
import org.junit.Test;

public class VirusScanningProcessorTest {

    private TestRunner testRunner;
    private final String VIRUS_FILE = "eicar.com";
    private final String CLEAN_FILE = "cleanFile.txt";
    
    @Before
    public void init() {
        testRunner = TestRunners.newTestRunner(VirusScanningProcessor.class);
        testRunner.setProperty("VIRUS_SCANNER_IP", "172.17.0.2");
        testRunner.setProperty("VIRUS_SCANNER_PORT", "3310");
    }
    @Ignore
    @Test
    public void testProcessorVirusFile() throws NoSuchAlgorithmException {
    	try (InputStream virusFile = getClass().getClassLoader().getResourceAsStream(VIRUS_FILE)) {
    		testRunner.enqueue(virusFile);
    		testRunner.run(1);
    		testRunner.assertQueueEmpty();
    		List<MockFlowFile> results = testRunner.getFlowFilesForRelationship(VirusScanningProcessor.VIRUS_FOUND);
    		assertTrue("1 match", results.size() == 1);
    		results.get(0).assertAttributeExists("Virus List");
    	} catch (IOException e) {
			e.printStackTrace();
		}
    }
    @Ignore
    @Test
    public void testProcessorCleanFile() {
    	try (InputStream cleanFile = getClass().getClassLoader().getResourceAsStream(CLEAN_FILE)) {
    		testRunner.enqueue(cleanFile);
    		testRunner.run(1);
    		testRunner.assertQueueEmpty();
    		List<MockFlowFile> results = testRunner.getFlowFilesForRelationship(VirusScanningProcessor.SUCCESS);
    		assertTrue("1 match", results.size() == 1);
    	} catch (IOException e) {
			e.printStackTrace();
		}

    }

}
