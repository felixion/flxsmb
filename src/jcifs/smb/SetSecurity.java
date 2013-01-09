package jcifs.smb;

import jcifs.Config;

public class SetSecurity {

    final static int readAccessRight = 0x00020000;
    final static int readAttrsAccessRight = 0x00000080;
    final static int readExtendedAttrsAccessRight = 0x00000008;
    final static int createFileWriteDataAccessRight = 0x00000002;
    private final static int listFolderReadDataAccessRight = 0x00000001;

    public static void main(String[] argv) throws Exception {

        // set the jcifs encoding to UTF8 in order to resolve server and file names in this format
        System.setProperty("jcifs.encoding", "UTF8");
        Config.setProperty("jcifs.smb.client.dfs.disabled", Boolean.TRUE.toString());


        NtlmPasswordAuthentication nt = new NtlmPasswordAuthentication("il", "rina", "Zim11mya");
        SmbFile file1 = new SmbFile("smb://10.2.48.85/rina/rina_test.txt", nt);

        SecurityDescriptor securityDescriptorBefore = file1.getSecurityDescriptor(true);


        ACE[] acesBefore = securityDescriptorBefore.aces;
        System.out.println("ACEs before set: ");
        for (int ai = 0; ai < acesBefore.length; ai++) {
            System.out.println(acesBefore[ai].access);
        }


        SID sid = file1.getOwnerUser();
        int maskToRevoke  = readAccessRight | readExtendedAttrsAccessRight;
        file1.revokePermission(securityDescriptorBefore, sid, maskToRevoke);


        SecurityDescriptor securityDescriptorAfter = file1.getSecurityDescriptor(true);

        ACE[] acesAfter = securityDescriptorAfter.aces;
        System.out.println("ACEs after set: ");
        for (int ai = 0; ai < acesAfter.length; ai++) {
            System.out.println(acesAfter[ai].access);
        }
    }
}