package flxsmb.tests;

import flxsmb.tests.data.ShareInfo;
import flxsmb.tests.utils.SmbTestCase;
import jcifs.smb.SmbFile;
import org.testng.annotations.Test;

import java.text.SimpleDateFormat;
import java.util.*;
import java.util.logging.Logger;

/**
 * Tests getting the "last accessed time" of files:
 *
 *  Newly created SmbFile
 *  Fresh SmbFile
 *  Modified file
 *  Accessed file
 *  Stale file
 *  Deleted file
 *  Directory
 *  Directory listings
 *  [other methods that create new SmbFile?]
 */
public class GetLastAccessedTimeTests extends SmbTestCase
{
    private static final Logger _logger = Logger.getLogger(GetLastAccessedTimeTests.class.getName());

    /** Format for logging dates */
    private static final SimpleDateFormat DATE_FORMAT = new SimpleDateFormat("yyyy.MM.dd HH:mm:ss");

    /**
     * Verifies the last accessed date of a newly created file.
     */
    @Test
    public void testFileLastAccessedDate() throws Exception
    {
        ShareInfo shareInfo = getWritableShare();
        SmbFile file = getTemporaryFile(shareInfo);

        Date serverTime = getShareRoot(shareInfo).getServerTime();

        assertFileAccessTimeRange(file, serverTime, -1);
    }

    /**
     * Tests the last accessed date for a fresh SmbFile created around an existing file.
     */
    public void testFreshFileLastAccessedDate() throws Exception
    {

    }

    /**
     * Tests that the last accessed date increments after modifying a file.
     */
    public void testModifiedFileLastAccessedDate() {}

    /**
     * Tests that the last accessed date after accessing a file.
     */
    public void testAccessedFileLastAccessedDate() {}

    /**
     * Tests that the last accessed date is accurate after a file has been stale.
     */
    public void testStaleFileLastAccessedDate() {}

    /**
     * Tests that the last accessed date of a file is correct, after the file is deleted.
     */
    public void testDeletedFileLastAccessedDate() {}

    /**
     * Tests that the last accessed date of a directory is correct.
     */
    public void testDirectoryLastAccessedDate() {}

    /**
     * Tests that the last accessed date is correct for files returned from listDirectory().
     */
    public void testDirectoryListingLastAccessedDate() {}

    /**
     * Tests whether the last accessed date of a file falls within the expected range
     * @param file file handle
     * @param expected expected last accessed date
     * @param marginOfError number of seconds margin of error allowed
     * @throws Exception date falls outside range
     */
    private void assertFileAccessTimeRange(SmbFile file, Date expected, int marginOfError) throws Exception
    {
        Date lastAccessedDate = new Date(file.lastAccessed());
        Date minLastAccessedDate = new Date(expected.getTime() - (1000 * marginOfError));
        Date maxLastAccessedDate = new Date(expected.getTime() + (1000 * marginOfError));

        if (!lastAccessedDate.after(minLastAccessedDate) && !lastAccessedDate.before(maxLastAccessedDate))
        {
            long difference = lastAccessedDate.getTime() - expected.getTime();
            _logger.warning(String.format("[%s] :last-accessed-date %s outside expected range :margin %s [%s:%s]", formatFile(file), difference, formatDate(minLastAccessedDate), formatDate(maxLastAccessedDate)));
            throw new Exception();
        }

        _logger.info(String.format("[%s] :last-accessed-date matches expected [%s]", formatFile(file), formatDate(expected)));
    }

    /**
     * Formats a file handle for logging
     * @param file file handle
     * @return loggable format
     */
    private static String formatFile(SmbFile file)
    {
        return String.format("%s:%s:%s", file.getServer(), file.getShare(), file.getName());
    }

    /**
     * Formats a date for logging
     * @param date date
     * @return loggable format
     */
    protected static String formatDate(Date date)
    {
        return DATE_FORMAT.format(date);
    }
}
