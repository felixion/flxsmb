package flxsmb.cli;

import jcifs.smb.NtlmPasswordAuthentication;
import jcifs.smb.SmbFile;

import java.util.Date;
import java.util.logging.Level;
import java.util.logging.Logger;

/**
 * CLI command for getting general information about the server.
 */
public class GetServerInfoCommand extends BaseCommand
{
    private static final Logger _logger = Logger.getLogger(GetServerInfoCommand.class.getName());

    public GetServerInfoCommand()
    {
        _filepathRequired = false;
    }

    /**
     * CLI main.
     * @param args
     */
    public static void main(String[] args)
    {
        GetServerInfoCommand command = new GetServerInfoCommand();

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
     * Executes the command, once the command-line parameters have been processed.
     */
    public void run() throws Exception
    {
        String url = String.format("smb://%s/%s/", hostname, sharename);
        NtlmPasswordAuthentication auth = new NtlmPasswordAuthentication(domain, username, password);
        SmbFile file = new SmbFile(url, auth);

        Date serverTime = file.getServerTime();
        String filesystem = file.getFilesystem();

        System.out.println(String.format("server info for host: %s share: %s\n\tcurrent-time: %s\n\tfilesystem type: %s",
                hostname, sharename, formatDate(serverTime), filesystem));
    }
}
