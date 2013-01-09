package flxsmb.tests;

import flxsmb.tests.utils.ShareInfo;
import flxsmb.tests.utils.SmbTestCase;
import jcifs.smb.SmbFile;
import org.testng.annotations.Test;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.*;

/**
 * Tests getting and setting access times for files.
 */
public class FileAccessTimesTest extends SmbTestCase
{
    @Test
    public void fileAccessTimesTest() throws Exception
    {
        ShareInfo shareInfo = getWritableShare();
        SmbFile file = getNewFile(shareInfo);

        Date serverTime = getShareRoot(shareInfo).getServerTime();
        Date minAccessTime = new Date(serverTime.getTime() - 1000);
        Date maxAccessTime = new Date(serverTime.getTime() + 1000);

        Date lastAccessed = new Date(file.lastAccessed());

        _logger.warning(String.format("checking access time %s [server time %s]", lastAccessed, serverTime));

        boolean valid = lastAccessed.before(maxAccessTime) && lastAccessed.after(minAccessTime);

        if (!valid)
        {
            _logger.warning(String.format("new file access date must be between %s and %s", minAccessTime, maxAccessTime));
        }

        assert valid;
    }

    @Test
    public void modifiedFileAccessTimesTest() throws Exception
    {
        ShareInfo shareInfo = getWritableShare();
        SmbFile file = getNewFile(shareInfo);

        Date serverTime = getShareRoot(shareInfo).getServerTime();
        Date minAccessTime = new Date(serverTime.getTime() - 1000);
        Date maxAccessTime = new Date(serverTime.getTime() + 1000);

        Date origLastAccessed = new Date(file.lastAccessed());

        OutputStream outputStream = file.getOutputStream();
        outputStream.write("test update".getBytes());

        Date newLastAccessed = new Date(file.lastAccessed());

        _logger.warning(String.format("checking access time %s [orig %s server time %s]", newLastAccessed, origLastAccessed, serverTime));

        boolean valid = origLastAccessed.before(maxAccessTime) && origLastAccessed.after(minAccessTime) && newLastAccessed != origLastAccessed;

        if (!valid)
        {
            _logger.warning(String.format("new file access date must be between %s and %s", minAccessTime, maxAccessTime));
        }

        assert valid;
    }

    @Test
    public void directoryAccessedTime()
    {

    }
}
