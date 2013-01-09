package flxsmb.cli;

import jcifs.smb.*;

import java.io.IOException;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * CLI command for getting the security descriptors of a file or directory.
 */
public class QueryFileSecurityCommand extends BaseCommand
{
    private static final Logger _logger = Logger.getLogger(QueryFileSecurityCommand.class.getName());

    /**
     * CLI main.
     * @param args
     */
    public static void main(String[] args)
    {
        QueryFileSecurityCommand command = new QueryFileSecurityCommand();

        try
        {
            command.scanCommandLineArgs(args);
            command.promptForPassword();
            command.validateArguments();
            command.run();
        }
        catch (Exception e)
        {
            _logger.log(Level.SEVERE, String.format("uncaught exception running command [%s]", e.getMessage()), e);

            if (command.verbose)
                e.printStackTrace();
        }
    }

    /**
     * Handles getting and printing the security descriptors, once the command-line parameters
     * are handled.
     * @throws Exception
     */
    public void run() throws Exception
    {
        String url = String.format("smb://%s/%s/%s", hostname, sharename, dirpath);
        NtlmPasswordAuthentication auth = new NtlmPasswordAuthentication(domain, username, password);
        SmbFile file = new SmbFile(url, auth);

        if (!file.exists())
        {
            String errorMessage = String.format("invalid file - does not exist [%s]", file);
            _logger.severe(errorMessage);
            throw new IllegalArgumentException(errorMessage);
        }

        if (file.isFile() || !recurse)
        {
            printSecurityInformation(file);
        }
        else
        {
            for (SmbFile f : file.listFiles())
            {
                printSecurityInformation(f);
            }
        }
    }

    /**
     * Prints security information for one file.
     * @param file a single (valid) file
     * @throws IOException
     */
    private void printSecurityInformation(SmbFile file) throws IOException
    {
        SID ownerUser = file.getOwnerUser();
        SID ownerGroup = file.getOwnerGroup();

        SecurityDescriptor securityDescriptor = file.getSecurityDescriptor(true);
        int sdtype = securityDescriptor.type;

        System.out.println(String.format("File \"%s\" [type: %d secdesc revision: %s]\n\towner: %s group: %s",
                file, sdtype, null, ownerUser, ownerGroup));

        for (ACE ace : securityDescriptor.aces)
        {
            SID sid = ace.getSID();
            int type = ace.isAllow() ? 0 : 1;
            int flags = ace.getFlags();
            int accessMask = ace.getAccessMask();

            System.out.println(String.format("\ttrustee: %s flags: %s mask: %s type: %s",
                    sid, flags, accessMask, type));
        }
    }
}
