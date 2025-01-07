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
        System.out.println(AwesomePasswordChecker.getInstance());
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
        
        System.out.println("dist");
        System.out.println(distance);

        Assert.assertTrue(distance >= 0, "Distance should be non-negative.");
    }

    @DataProvider
    public Object[][] passwordDistanceProvider() {
        return new Object[][]{
            {"password1", 0.0}, // Replace 0.0 with an expected distance for "password1"
            {"HelloWorld", 0.0} // Replace 0.0 with an expected distance for "HelloWorld"
        };
    }
}