package flxsmb.cli;

import jcifs.smb.NtlmPasswordAuthentication;
import jcifs.smb.SmbFile;

/**
 * CLI command to update metadata for a file.
 *
 * Usage: flxsmb.cli.UpdateFileMetadataCommand //hostname/share/filePath.txt -u domain/username -p password
 *                                             -a accessedTime -m modifiedTime
 *
 * The parameters to atime/mtime/ctime should be specified in milliseconds since 1970.
 */
public class UpdateFileMetadataCommand extends BaseCommand
{
    protected long atime = -1;
    protected long mtime = -1;

    /**
     * CLI main.
     */
    public static void main(String[] args) throws Exception
    {
        UpdateFileMetadataCommand command = new UpdateFileMetadataCommand();

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

    /**
     * Runs the command, once command-line parameters are processed.
     */
    public void run() throws Exception
    {
        NtlmPasswordAuthentication auth = new NtlmPasswordAuthentication(domain, username, password);
        String url = String.format("smb://%s/%s/%s/", hostname, sharename, dirpath);
        SmbFile file = new SmbFile(url, auth);

        if (!file.exists())
        {
            System.out.println(String.format("invalid file path -- doesn't exist [%s:%s:%s]", hostname, sharename, dirpath));
            return;
        }

        if (atime != -1)
        {
            file.setAccessTime(atime);
        }

        if (mtime != -1)
        {
            file.setLastModified(mtime);
        }
    }

    /**
     * Subclasses this method to process additional arguments.
     */
    protected void scanCommandLineArgs(String[] args)
    {
        super.scanCommandLineArgs(args);

        for (int i = 1; i < args.length; i++)
        {
            boolean hasAnother = i < args.length - 1;

            String flag = args[i].toUpperCase();
            if (flag.equals("-A") && hasAnother)
            {
                atime = Long.parseLong(args[i + 1]);
            }

            else if (flag.equals("-M") && hasAnother)
            {
                mtime = Long.parseLong(args[i + 1]);
            }

        }
    }


}
