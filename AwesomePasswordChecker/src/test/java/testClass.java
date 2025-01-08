/*
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/Classes/Class.java to edit this template
 */
import  fr.isima.codereview.awesomepasswordchecker.AwesomePasswordChecker;

import org.testng.Assert;
import org.testng.annotations.BeforeClass;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

import java.io.IOException;

public class testClass {

    private AwesomePasswordChecker checker;

    @BeforeClass
    public void setUp() throws IOException {
        // Initialize the instance with a sample cluster centers file
        checker = AwesomePasswordChecker.getInstance();
    }

    @Test
    public void testSingletonInstance() throws IOException {
        // Ensure the singleton behavior
        AwesomePasswordChecker instance1 = AwesomePasswordChecker.getInstance();
        AwesomePasswordChecker instance2 = AwesomePasswordChecker.getInstance();
        Assert.assertSame(instance1, instance2, "Instances should be the same");
    }

    @Test
    public void testMaskAff() {
        String password = "Hello123!";
        int[] expectedMask = {4, 1, 1, 1, 1, 5, 5, 5, 6, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};
        int[] mask = checker.maskAff(password);

        Assert.assertEquals(mask, expectedMask, "Generated mask array does not match the expected values.");
    }

    @Test
    public void testComputeMD5() {
        String input = "password";
        String expectedMD5 = "5f4dcc3b5aa765d61d8327deb882cf99";
        String computedMD5 = AwesomePasswordChecker.computeMD5(input);
        Assert.assertEquals(computedMD5, expectedMD5, "Computed MD5 hash is incorrect.");
    }

    @Test(dataProvider = "passwordDistanceProvider")
    public void testGetDistance(String password, double expectedMinDistance) {
        
        double distance = checker.getDIstance(password);
        
        Assert.assertTrue(distance >= 0, "Distance should be non-negative.");
    }

    @DataProvider
    public Object[][] passwordDistanceProvider() {
        return new Object[][]{
            {"password1", 0.0}, // Replace 0.0 with an expected distance for "password1"
            {"HelloWorld", 0.0} // Replace 0.0 with an expected distance for "HelloWorld"
        };
    }
    
    public class ComputeMD5PerformanceTest {

    @Test
    public void testComputeMD5Performance() {
        // Input string to test
        String input = "The quick brown fox jumps over the lazy dog";

        // Number of iterations for performance testing
        int iterations = 100000;

        // Record the start time
        long startTime = System.nanoTime();

        // Execute the method multiple times
        for (int i = 0; i < iterations; i++) {
            String md5Hash = AwesomePasswordChecker.computeMD5(input);
            Assert.assertNotNull(md5Hash, "MD5 hash should not be null");
        }

        // Record the end time
        long endTime = System.nanoTime();

        // Calculate the total time taken
        long duration = (endTime - startTime) / 1_000_000; // Convert to milliseconds

        // Log the duration for analysis
        System.out.println("Execution time for computeMD5: " + iterations + " iterations: " + duration + " ms");

        // Define an acceptable time threshold (e.g., 2000 ms for 100,000 iterations)
        long acceptableThresholdMs = 2000;

        // Verify that the execution time is within the acceptable threshold
        Assert.assertTrue(duration <= acceptableThresholdMs,
            "Performance test failed: Execution time exceeded " + acceptableThresholdMs + " ms");
    }
}

}