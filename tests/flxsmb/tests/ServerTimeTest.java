package flxsmb.tests;

import flxsmb.tests.utils.SmbTestCase;
import jcifs.smb.SmbFile;
import org.testng.annotations.Test;

import java.util.Date;

/**
 */
public class ServerTimeTest extends SmbTestCase
{
    @Test
    public void testGetServerTime() throws Exception
    {
        SmbFile shareRoot = getShareRoot(getWritableShare());

        _logger.info(String.format("Testing server time for \"%s\"", shareRoot));

        Date serverTime = shareRoot.getServerTime();

        _logger.info(String.format("Server time: %s (%s)", serverTime, serverTime.getTime()));

        Date now = new Date();
        Date minServerTime = new Date(now.getTime() - 2 * 1000);
        Date maxServerTime = new Date(now.getTime() + 2 * 1000);

        boolean valid = serverTime.after(minServerTime) && serverTime.before(maxServerTime);

        if (!valid)
        {
            _logger.info(String.format("Server time must be between %s and %s", minServerTime, maxServerTime));
        }

        assert valid;
    }


}
