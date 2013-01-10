package flxsmb.cli;

import jcifs.smb.NtlmPasswordAuthentication;
import jcifs.smb.SID;
import jcifs.smb.SmbException;
import jcifs.smb.SmbFile;

import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * CLI command for looking up account information associated with a SID.
 *
 * Usage: flxsmb.cli.LookupSidsCommand //hostname/share -u domain/username -p password --user S-1-22-1-0 --group S-1-22-2-0
 *
 * Result:
 *
 *      uid: S-1-22-1-0
 *      username: testadmin
 *      gid: S-1-22-2-0
 *      grpname: Administrators
 */
public class LookupSidsCommand extends BaseCommand
{
    private static final Logger _logger = Logger.getLogger(LookupSidsCommand.class.getName());

    protected SID user;
    protected SID group;

    public LookupSidsCommand()
    {
        _filepathRequired = false;
    }

    /**
     * CLI main.
     * @param args
     */
    public static void main(String[] args)
    {
        LookupSidsCommand command = new LookupSidsCommand();

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

    @Override
    public void run() throws Exception
    {
        String url = String.format("smb://%s/%s/%s", hostname, sharename, dirpath);
        NtlmPasswordAuthentication auth = new NtlmPasswordAuthentication(domain, username, password);
        SmbFile file = new SmbFile(url, auth);

        if (user != null)
            user.resolve(hostname, auth);

        if (group != null)
            group.resolve(hostname, auth);

        System.out.println(String.format("user: %s grp: %s", user.toDisplayString(), group.toDisplayString()));
    }

    @Override
    protected void scanCommandLineArgs(String[] args)
    {
        super.scanCommandLineArgs(args);

        try
        {
            for (int i = 1; i < args.length; i++)
            {
                boolean hasAnother = i < args.length - 1;

                String flag = args[i].toUpperCase();
                if (flag.equals("--USER") && hasAnother)
                {
                    user = new SID(args[i + 1]);
                }

                else if (flag.equals("--GROUP") && hasAnother)
                {
                    group = new SID(args[i + 1]);
                }

            }
        }
        catch (SmbException e)
        {
            throw new RuntimeException(e);
        }
    }
}
