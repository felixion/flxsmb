package flxsmb.cli;

import jcifs.smb.NtlmPasswordAuthentication;
import jcifs.smb.SmbException;
import jcifs.smb.SmbFile;

import java.io.IOException;
import java.util.Date;

/**
 */
public class StatFileCommand extends BaseCommand
{
    public static void main(String[] args) throws Exception
    {
        StatFileCommand command = new StatFileCommand();

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
        }
    }

    @Override
    public void run() throws Exception
    {
        System.out.println("Running command - " + this.toString());

        NtlmPasswordAuthentication auth = new NtlmPasswordAuthentication(domain, username, password);
        String url = String.format("smb://%s/%s/%s/", hostname, sharename, dirpath);
        SmbFile file = new SmbFile(url, auth);

        if (!file.exists())
        {
            System.out.println(String.format("invalid file path -- doesn't exist [%s:%s:%s]", hostname, sharename, dirpath));
            return;
        }

        if (file.isFile() || !recurse)
        {
            printFileStat(file);
        }
        else
        {
            for (SmbFile f : file.listFiles())
            {
                printFileStat(f);
            }
        }
    }

    private void printFileStat(SmbFile file) throws IOException
    {
        String ownerName = formatUser(file.getOwnerUser());
        String ownerGroup = formatUser(file.getOwnerGroup());

        int size = file.getContentLength();

        Date mtime = new Date(file.lastModified());
        Date ctime = new Date(file.getDate());
        Date atime = new Date(file.lastAccessed());

        String path = file.getCanonicalPath();
        String name = file.getName();

        System.out.println(String.format("file: %s [path: %s]\n\towner: %s group: %s\n\tsize: %s mtime: %s ctime: %s atime: %s",
                name, path, ownerName, ownerGroup, formatSize(size), formatDate(mtime), formatDate(ctime), formatDate(atime)));
    }
}
