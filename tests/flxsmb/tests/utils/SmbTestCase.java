package flxsmb.tests.utils;

import flxsmb.tests.data.ShareInfo;
import jcifs.smb.NtlmPasswordAuthentication;
import jcifs.smb.SmbException;
import jcifs.smb.SmbFile;
import org.testng.annotations.AfterMethod;
import org.testng.annotations.BeforeClass;

import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.util.HashSet;
import java.util.Properties;
import java.util.Random;
import java.util.Set;
import java.util.logging.*;

/**
 * Base class for FLXSMB unit-tests, providing common services for the tests.
 */
public class SmbTestCase
{
    protected static final Logger _logger = Logger.getLogger(SmbTestCase.class.getName());

    /**
     * Files to clean up following each test.
     */
    private Set<SmbFile> cleanupFiles = new HashSet<SmbFile>();

    /**
     * Gets a writable share from the test sources.
     *
     * @return info for a writable share
     * @throws Exception
     */
    protected ShareInfo getWritableShare() throws Exception
    {

        Set<ShareInfo> testShareInfo = getTestShareInfo("data/test-sources.properties");
        return testShareInfo.iterator().next();
    }

    /**
     * Builds an SmbFile for the root of a share
     *
     * @param shareInfo share details
     * @return SmbFile for the share's root directory
     * @throws MalformedURLException
     */
    protected SmbFile getShareRoot(ShareInfo shareInfo) throws MalformedURLException
    {
        String url = String.format("smb://%s/%s/", shareInfo.getHostname(), shareInfo.getSharename());
        NtlmPasswordAuthentication auth = new NtlmPasswordAuthentication(shareInfo.getDomain(), shareInfo.getUsername(), shareInfo.getPassword());

        SmbFile f = new SmbFile(url, auth);

        return f;
    }

    /**
     * Creates a new, temporary file for testing.
     *
     * @param shareInfo share details
     * @return a new SmbFile
     * @throws MalformedURLException
     */
    protected SmbFile getTemporaryFile(ShareInfo shareInfo) throws Exception
    {
        int randNum = new Random().nextInt();
        String fileName = String.format("temporaryTestFile-%d.txt", randNum);
        String url = String.format("smb://%s/%s/%s", shareInfo.getHostname(), shareInfo.getSharename(), fileName);

        try
        {
            NtlmPasswordAuthentication auth = new NtlmPasswordAuthentication(shareInfo.getDomain(), shareInfo.getUsername(), shareInfo.getPassword());

            SmbFile file = new SmbFile(url, auth);

            if (file.exists())
            {
                _logger.severe(String.format("temporary file \"%s\" already exists [%s]", fileName, url));
            }

            _logger.fine(String.format("creating temporary file [%s]", url));
            file.createNewFile();

            cleanupFiles.add(file);

            return file;
        }
        catch (Exception e)
        {
            _logger.log(Level.SEVERE, String.format("error creating temporary file [%s]", url, e));
            throw e;
        }
    }

//    * Creates a new, temporary file for testing.
//    * @param shareInfo share details
//    * @return a new SmbFile
//    * @throws MalformedURLException
//    protected SmbFile getModifiedFile(ShareInfo shareInfo)
//    {
//        return null;
//    }
//
//    protected SmbFile getDeletedFile(ShareInfo shareInfo)
//    {
//        return null;
//    }

//    protected boolean assertFileTimes(SmbFile file, long atime, long mtime, long ctime, float delta)
//    {
//        return true;
//    }

    /**
     * Cleans up all files created after each test.
     */
    @AfterMethod
    public void cleanupFiles()
    {
        _logger.fine(String.format("clean up temporary files: %s", cleanupFiles));

        for (SmbFile file : cleanupFiles)
        {
            try
            {
                file.delete();
            }
            catch (SmbException e)
            {
                _logger.warning(String.format("[%s] error cleaning up temporary file", file));
            }
        }

        cleanupFiles.clear();
    }

    /**
     * Locates and loads the properties file defining test shares
     *
     * @param propertiesFileName name of properties file
     * @return Properties for test shares
     * @throws IOException the properties file was not found
     */
    protected Properties loadTestProperties(String propertiesFileName) throws IOException
    {
        InputStream inputStream = getClass().getResourceAsStream(propertiesFileName);

        Properties properties = new Properties();
        properties.load(inputStream);

        return properties;
    }

    /**
     * Imports all shares from the test shares file
     *
     * @param propertiesFileName name of properties file
     * @return All shares defined in properties file
     * @throws Exception
     */
    protected Set<ShareInfo> getTestShareInfo(String propertiesFileName) throws Exception
    {
        Properties properties = loadTestProperties(propertiesFileName);

        Set<ShareInfo> shareInfo = new HashSet<ShareInfo>();

        String[] testShares = properties.getProperty("testShares").split(",");
        for (String testShareName : testShares)
        {
            String hostname = properties.getProperty(testShareName + ".hostname");
            String sharename = properties.getProperty(testShareName + ".share");
            String domain = properties.getProperty(testShareName + ".domain");
            String username = properties.getProperty(testShareName + ".username");
            String password = properties.getProperty(testShareName + ".password");

            shareInfo.add(new ShareInfo(hostname, sharename, domain, username, password));
        }

        return shareInfo;
    }

    /**
     * Configures logging at the start of a suite.
     */
    @BeforeClass
    public static void setupLogging()
    {
        LoggingUtil.setupLogging();
    }
}
