package flxsmb.tests.utils;

import jcifs.smb.NtlmPasswordAuthentication;
import jcifs.smb.SmbFile;
import org.testng.annotations.BeforeClass;

import java.io.IOException;
import java.io.InputStream;
import java.net.MalformedURLException;
import java.util.HashSet;
import java.util.Properties;
import java.util.Set;
import java.util.logging.*;

public class SmbTestCase
{
    protected static final Logger _logger = Logger.getLogger(SmbTestCase.class.getName());

    private Set<SmbFile> cleanupFiles = new HashSet<SmbFile>();

    protected ShareInfo getWritableShare() throws Exception {

        Set<ShareInfo> testShareInfo = getTestShareInfo("test-sources.properties");
        return testShareInfo.iterator().next();
    }

    protected SmbFile getShareRoot(ShareInfo shareInfo) throws MalformedURLException {

        String url = String.format("smb://%s/%s/", shareInfo.getHostname(), shareInfo.getSharename());
        NtlmPasswordAuthentication auth = new NtlmPasswordAuthentication(shareInfo.getDomain(), shareInfo.getUsername(), shareInfo.getPassword());

        SmbFile f = new SmbFile(url, auth);

        return f;
    }

    protected SmbFile getNewFile(ShareInfo shareInfo) throws MalformedURLException {

        String fileName = "testNewFile.txt";

        String url = String.format("smb://%s/%s/%s", shareInfo.getHostname(), shareInfo.getSharename(), fileName);
        NtlmPasswordAuthentication auth = new NtlmPasswordAuthentication(shareInfo.getDomain(), shareInfo.getUsername(), shareInfo.getPassword());

        SmbFile f = new SmbFile(url, auth);

        cleanupFiles.add(f);

        return f;
    }

    protected SmbFile getModifiedFile(ShareInfo shareInfo)
    {
        return null;
    }

    protected SmbFile getDeletedFile(ShareInfo shareInfo)
    {
        return null;
    }

    protected boolean assertFileTimes(SmbFile file, long atime, long mtime, long ctime, float delta)
    {
        return true;
    }

    protected void cleanupFile(SmbFile file)
    {

    }

    protected Properties loadTestProperties(String propertiesFileName) throws IOException
    {
        InputStream inputStream = getClass().getResourceAsStream(propertiesFileName);

        Properties properties = new Properties();
        properties.load(inputStream);

        return properties;
    }

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

    @BeforeClass
    public static void setupLogging()
    {
        LoggingUtil.setupLogging();
    }
}
