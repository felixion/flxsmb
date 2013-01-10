package flxsmb.cli;

import jcifs.smb.NtlmPasswordAuthentication;
import jcifs.smb.SID;
import jcifs.smb.SmbException;
import jcifs.smb.SmbFile;

import java.util.ArrayList;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * CLI command for looking up account information associated with a SID.
 *
 * Usage: flxsmb.cli.LookupAccountInfoCommand //hostname/share -u domain/username -p password
 *                                            --sid S-1-22-1-0
 *                                            --account-name storediq/testadmin
 *
 * Result:
 *
 *      uid: S-1-22-1-0
 *      username: testadmin
 *      gid: S-1-22-2-0
 *      grpname: Administrators
 */
public class LookupAccountInfoCommand extends BaseCommand
{
    private static final Logger _logger = Logger.getLogger(LookupAccountInfoCommand.class.getName());

    protected List<SID> sidList = new ArrayList<SID>();

    protected List<String> accountList = new ArrayList<String>();

    public LookupAccountInfoCommand()
    {
        _filepathRequired = false;
    }

    /**
     * CLI main.
     * @param args
     */
    public static void main(String[] args)
    {
        LookupAccountInfoCommand command = new LookupAccountInfoCommand();

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

        for (SID sid : sidList)
        {
            sid.resolve(hostname, new NtlmPasswordAuthentication(domain, username, password));
//            System.out.println("SID: " + sid + " " + sid.toDisplayString());
            printSID(sid);
        }

        String[] accountNames = new String[accountList.size()];
        for (int i = 0; i < accountNames.length; i++) accountNames[i] = accountList.get(i);

        SID[] sids = SID.getFromNames(hostname, new NtlmPasswordAuthentication(domain, username, password), accountNames);

        for (SID sid : sids)
        {
            printSID(sid);
        }
    }

    protected static void printSID(SID sid)
    {
        int rid = sid.getRid();
        int type = sid.getType();
        String accountName = sid.getAccountName();
        String domainName = sid.getDomainName();
        SID domainSid = sid.getDomainSid();

        System.out.println(String.format("SID [domain: %s account: %s] %s\n\ttype: %s domainSID: %s rid: %s",
                domainName, accountName, sid, type, domainSid, rid));
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
                if (flag.equals("--ACCOUNT-NAME") && hasAnother)
                {
                    accountList.add(args[i + 1]);
                }

                else if (flag.equals("--SID") && hasAnother)
                {
                    sidList.add(new SID(args[i + 1]));
                }

            }
        }
        catch (SmbException e)
        {
            throw new RuntimeException(e);
        }
    }
}
