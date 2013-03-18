package flxsmb.tests;

import flxsmb.tests.utils.SmbTestCase;
import jcifs.smb.NtlmPasswordAuthentication;
import jcifs.smb.SmbFile;
import org.testng.annotations.Test;

public class OpenWithReadPermissionsTest extends SmbTestCase
{
    @Test
    public void test1() throws Exception
    {
        NtlmPasswordAuthentication auth = new NtlmPasswordAuthentication("storediq", "testadmin", "test123");
        SmbFile file = new SmbFile("smb://datamaster.storediq.com/big4filetypes/docfiles/Months.doc", auth);

        System.out.println(file.exists());
        System.out.println(file.canRead());
        System.out.println(file.canWrite());

        file.getOutputStream();
    }

}
