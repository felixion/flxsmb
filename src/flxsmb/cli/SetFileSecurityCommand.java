package flxsmb.cli;

import jcifs.smb.NtlmPasswordAuthentication;
import jcifs.smb.SID;
import jcifs.smb.SmbException;
import jcifs.smb.SmbFile;

import java.util.ArrayList;
import java.util.List;

/**
 * CLI command to update a file's security/permissions info.
 *
 * Usage: flxsmb.cli.SetFileSecurityCommand //hostname/share/filePath.txt -u domain/username -p password
 *                                          -u userSid -g groupSid
 *                                          --grant sid:mask
 *                                          --revoke sid:mask
 *
 * The parameters to userSid and groupSid should be specified in the string format for SIDs.
 *
 * When granting or revoking permissions, the permission is specified as follows:
 *
 *      --grant S-1-0-1111:342342343432
 *
 *      Such that you are concatenating a string SID along with an ACE access mask.
 */
public class SetFileSecurityCommand extends BaseCommand
{
    protected SID newOwner;
    protected SID newGroup;

    protected List<PermissionItem> permissionItems = new ArrayList<PermissionItem>();

    /**
     * CLI main.
     */
    public static void main(String[] args) throws Exception
    {
        SetFileSecurityCommand command = new SetFileSecurityCommand();

        try
        {
            command.scanCommandLineArgs(args);
            command.promptForPassword();
            command.validateArguments();
            command.run();
        }
        catch (Exception e)
        {
            System.out.println(String.format("Encountered error listing directory [%s:%s:%s]\n\t - %s", command.hostname, command.sharename, command.dirpath, e.getMessage()));

            if (command.verbose)
                e.printStackTrace();
        }
    }

    public void run() throws Exception
    {
        System.out.println(String.format("new owner: %s group: %s", newOwner, newGroup));
        for (PermissionItem item : permissionItems)
        {
            System.out.println("\t" + item);
        }

        NtlmPasswordAuthentication auth = new NtlmPasswordAuthentication(domain, username, password);
        String url = String.format("smb://%s/%s/%s/", hostname, sharename, dirpath);
        SmbFile file = new SmbFile(url, auth);

        if (!file.exists())
        {
            System.out.println(String.format("invalid file path -- doesn't exist [%s:%s:%s]", hostname, sharename, dirpath));
            return;
        }

        if (newOwner != null)
        {
            file.setOwner(newOwner);
        }

        if (newGroup != null)
        {
            // not available
        }

        // setting DACLs not available yet...
    }

    @Override
    protected void scanCommandLineArgs(String[] args)
    {
        try
        {
            super.scanCommandLineArgs(args);

            for (int i = 1; i < args.length; i++)
            {
                boolean hasAnother = i < args.length - 1;

                String flag = args[i].toUpperCase();
                if (flag.equals("--OWNER") && hasAnother)
                {
                    newOwner = new SID(args[i + 1]);
                }

                else if (flag.equals("--GROUP") && hasAnother)
                {
                    newGroup = new SID(args[i + 1]);
                }

                else if (flag.equals("--GRANT") && hasAnother)
                {
                    String item = args[i + 1];
                    String[] parts = item.split(":");

                    SID sid = new SID(parts[0]);
                    int accessMask = Integer.parseInt(parts[1]);

                    permissionItems.add(new PermissionItem(PermissionItem.GRANT, sid, accessMask));
                }

                else if (flag.equals("--REVOKE") && hasAnother)
                {
                    String item = args[i + 1];
                    String[] parts = item.split(":");

                    SID sid = new SID(parts[0]);
                    int accessMask = Integer.parseInt(parts[1]);

                    permissionItems.add(new PermissionItem(PermissionItem.REVOKE, sid, accessMask));
                }
            }
        }
        catch (SmbException e)
        {
            throw new RuntimeException(e);
        }
    }

    class PermissionItem
    {
        public static final int GRANT = 0x1;
        public static final int REVOKE = 0x1;

        protected int type;
        protected SID sid;
        protected int accessMask;

        PermissionItem(int type, SID sid, int accessMask)
        {
            this.type = type;
            this.sid = sid;
            this.accessMask = accessMask;
        }

        public String toString()
        {
            return String.format("#<permission-item :type %s :sid %s :mask 0x%X>", type, sid, accessMask);
        }
    }
}
