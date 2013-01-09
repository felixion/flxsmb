package flxsmb.tests;

import flxsmb.tests.utils.ShareInfo;
import org.testng.annotations.Test;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Properties;
import java.util.Set;

public class FileAccessTimesTest
{
    @Test
    public void fileAccessTimesTest() throws Exception
    {
//        System.out.println(getClass().getResourceAsStream("test-sources.properties"));
        for (ShareInfo i : getTestShareInfo("test-sources.properties"))
        {
            System.out.println(i);
        }
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

            System.out.println(String.format("hostname %s share %s domain %s username %s password %s", hostname, sharename, domain, username, password));

            shareInfo.add(new ShareInfo(hostname, sharename, domain, username, password));
        }

        return shareInfo;
    }

    protected ShareInfo getShareInfo(Properties p, String testShareName)
    {
        String hostname = p.getProperty(testShareName + ".hostname");
        String sharename = p.getProperty(testShareName + ".share");
        String domain = p.getProperty(testShareName + ".domain");
        String username = p.getProperty(testShareName + ".username");
        String password = p.getProperty(testShareName + ".password");

        System.out.println(String.format("hostname %s share %s domain %s username %s password %s", hostname, sharename, domain, username, password));

        return new ShareInfo(hostname, sharename, domain, username, password);
    }
}
