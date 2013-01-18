package flxsmb.tests;

import flxsmb.tests.data.ShareInfo;
import flxsmb.tests.utils.SmbTestCase;
import jcifs.smb.NtlmPasswordAuthentication;
import jcifs.smb.SID;
import jcifs.smb.SmbFile;
import org.testng.annotations.Test;

public class SetOwnerSidsTest extends SmbTestCase
{
//    @Test
//    public void test() throws Exception
//    {
//        ShareInfo shareInfo = getWritableShare();
//        SmbFile file = getTemporaryFile(shareInfo);
//
//        SID newOwner = new SID("S-1-5-21-640782154-1059231025-666483966-1000");
//        _logger.info(file.getOwnerUser().toString());
//
//        file.setOwner(newOwner);
//    }

    @Test
    public void setOwner1() throws Exception
    {
        NtlmPasswordAuthentication auth = new NtlmPasswordAuthentication("", "test-admin-user", "simplepw");
        SmbFile file1 = new SmbFile("smb://windows2008.home/smbtest1/temp contents/temp-2.txt", auth);

//        file1.createNewFile();
        SID newUser = new SID("S-1-5-21-640782154-1059231025-666483966-1005");
`
        file1.setOwner(newUser);
    }
}
