package flxsmb.cli;

import jcifs.smb.NtlmPasswordAuthentication;
import jcifs.smb.SID;
import jcifs.smb.SmbException;
import jcifs.smb.SmbFile;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.text.SimpleDateFormat;
import java.util.Date;

/**
 * Implements a CLI command for listing a directory.
 *
 * Usage:
 *  ListDirectoryCommand //hostname/share/dirpath -U username
 */
public class ListDirectoryCommand extends BaseCommand
{

    private static final int MAX_OWNER_COLUMN_WIDTH = 20;

    private static final int MAX_GROUP_COLUMN_WIDTH = 20;

    private int ownerColumnWidth = 0;

    private int groupColumnWidth = 0;

    public static void main(String[] args) throws Exception
    {
        ListDirectoryCommand command = new ListDirectoryCommand();

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
            e.printStackTrace();
        }
    }

    @Override
    public void run() throws Exception
    {
        System.out.println("Running command - " + this.toString());

        NtlmPasswordAuthentication auth = new NtlmPasswordAuthentication(domain, username, password);
        String url = String.format("smb://%s/%s/%s/", hostname, sharename, dirpath);
        SmbFile directory = new SmbFile(url, auth);

        if (!directory.exists())
        {
            System.out.println(String.format("invalid directory path -- doesn't exist [%s:%s:%s]", hostname, sharename, dirpath));
            return;
        }

        if (!directory.isDirectory())
        {
            System.out.println(String.format("invalid directory path -- not a directory [%s:%s:%s]", hostname, sharename, dirpath));
            return;
        }

        SmbFile[] files = directory.listFiles();
        scanColumnWidths(files);

        System.out.println(String.format("%" + ownerColumnWidth + "s %" + groupColumnWidth + "s   %6s   %s                 %s                 %s", "owner", "group", "size", "mtime", "ctime", "name"));

        StringBuilder b = new StringBuilder();
        for (int i = 0; i < ownerColumnWidth; i++)
            b.append("-");
        b.append(" ");
        for (int i = 0; i < groupColumnWidth; i++)
            b.append("-");
        b.append("    -----   -------------------   -------------------   -------------------");

        System.out.println(b.toString());

        for (SmbFile f : files)
        {
            printFileEntry(f);
        }
    }

    protected void printFileEntry(SmbFile file) throws IOException, SmbException
    {
        String owner = formatUser(file.getOwnerUser());
        String group = formatUser(file.getOwnerGroup());

        owner = String.format("%" + ownerColumnWidth + "s", owner);
        group = String.format("%" + groupColumnWidth + "s", group);

        int size = file.getContentLength();

        Date mtime = new Date(file.lastModified());
        Date ctime = new Date(file.createTime());

        String name = file.getName();

        System.out.println(String.format("%s %s   %6s   %s   %s   %s", owner, group, formatSize(size), formatDate(mtime), formatDate(ctime), name));
    }

    protected void scanColumnWidths(SmbFile[] files) throws IOException
    {
        for (SmbFile f : files)
        {
            String owner = formatUser(f.getOwnerUser());
            String group = formatUser(f.getOwnerGroup());

            ownerColumnWidth = Math.max(ownerColumnWidth, owner.length());
            groupColumnWidth = Math.max(groupColumnWidth, group.length());
        }

        ownerColumnWidth = Math.min(ownerColumnWidth + 2, MAX_OWNER_COLUMN_WIDTH);
        groupColumnWidth = Math.min(groupColumnWidth + 2, MAX_GROUP_COLUMN_WIDTH);
    }

}
