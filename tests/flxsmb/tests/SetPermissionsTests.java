package flxsmb.tests;

import flxsmb.tests.data.ShareInfo;
import flxsmb.tests.utils.SmbTestCase;
import jcifs.Config;
import jcifs.smb.*;
import org.testng.annotations.Test;

public class SetPermissionsTests extends SmbTestCase
{
    final static int readAccessRight = 0x00020000;
    final static int readAttrsAccessRight = 0x00000080;
    final static int readExtendedAttrsAccessRight = 0x00000008;
    final static int createFileWriteDataAccessRight = 0x00000002;
    private final static int listFolderReadDataAccessRight = 0x00000001;

    @Test
    public void main() throws Exception {

        ShareInfo shareInfo = getWritableShare();
        SmbFile file1 = getTemporaryFile(shareInfo);

        SecurityDescriptor securityDescriptorBefore = file1.getSecurityDescriptor(true);


        ACE[] acesBefore = securityDescriptorBefore.aces;
        System.out.println("ACEs before set: ");
        for (int ai = 0; ai < acesBefore.length; ai++) {
//            System.out.println(acesBefore[ai].access);
        }


        SID sid = file1.getOwnerUser();
        int maskToRevoke  = readAccessRight | readExtendedAttrsAccessRight;
        file1.revokePermission(securityDescriptorBefore, sid, maskToRevoke);


        SecurityDescriptor securityDescriptorAfter = file1.getSecurityDescriptor(true);

        ACE[] acesAfter = securityDescriptorAfter.aces;
        System.out.println("ACEs after set: ");
        for (int ai = 0; ai < acesAfter.length; ai++) {
//            System.out.println(acesAfter[ai].access);
        }
    }
}
