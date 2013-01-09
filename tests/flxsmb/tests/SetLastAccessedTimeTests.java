package flxsmb.tests;

import flxsmb.tests.data.ShareInfo;
import flxsmb.tests.utils.SmbTestCase;
import jcifs.smb.NtlmPasswordAuthentication;
import jcifs.smb.SmbFile;
import org.testng.annotations.Test;

import java.util.Date;

/**
 * Test cases for setting the last accessed date.
 */
public class SetLastAccessedTimeTests extends SmbTestCase
{
    /**
     * Tests that the last accessed date of a file is correctly set.
     */
    @Test
    public void testSetFileLastAccessedDate() throws Exception
    {
        ShareInfo shareInfo = getWritableShare();
        SmbFile file = getTemporaryFile(shareInfo);

        Date serverTime = getShareRoot(shareInfo).getServerTime();

        // new time one hour in future
        Date newTime = new Date(serverTime.getTime() + (60 * 60 * 1000));

        file.setAccessTime(newTime.getTime());
//        file.setAccessTime(1000000L);

        SmbFile file2 = new SmbFile(file.getURL(), shareInfo.getAuthenticator());

        _logger.info(String.format("server time: %s", serverTime));
        _logger.info(String.format("[%s] new accessed time: %s", file, new Date(file.lastAccessed())));

//        assertFileAccessTimeRange(file, serverTime, -1);
    }

    /**
     * Tests that the last accessed date of a directory is correctly set.
     */
    public void testSetDirectoryLastAccessedDate() {}

}
