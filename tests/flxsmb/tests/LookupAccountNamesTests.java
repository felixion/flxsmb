package flxsmb.tests;

import flxsmb.tests.utils.SmbTestCase;
import jcifs.smb.NtlmPasswordAuthentication;
import jcifs.smb.SID;
import jcifs.smb.SmbFile;
import org.testng.annotations.Test;

import java.util.Date;

public class LookupAccountNamesTests extends SmbTestCase
{
    @Test
    public void testLookupSIDs() throws Exception
    {
        SmbFile shareRoot = getShareRoot(getWritableShare());

        _logger.info(String.format("Testing server time for \"%s\"", shareRoot));

        SID[] sids = SID.getFromNames("datamaster.storediq.com", new NtlmPasswordAuthentication("storediq", "testadmin", "test123"), new String[] {"storediq\\testadmin"});

        for (SID sid : sids)
        {
            System.out.println(sid + " - " + sid.toDisplayString());
            System.out.println(sid.getRid());
            System.out.println(sid.getTypeText());

        }
    }
}
