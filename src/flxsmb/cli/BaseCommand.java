package flxsmb.cli;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.text.SimpleDateFormat;
import java.util.Date;

public abstract class BaseCommand
{
    public static final SimpleDateFormat DATE_FORMAT = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss");
    protected String hostname;
    protected String sharename;
    protected String domain;
    protected String username;
    protected String password;
    protected String dirpath;

    public abstract void run() throws Exception;

    protected void promptForPassword() throws IOException
    {
        if (password != null)
            return;

        System.out.print("Enter password: ");
        password = new BufferedReader(new InputStreamReader(System.in)).readLine();
        password.trim();
    }

    protected void validateArguments()
    {
        if (hostname == null || sharename == null || dirpath == null)
            throw new IllegalArgumentException(String.format("invalid UNC path //%s/%s/%s", hostname, sharename, dirpath));

        if (domain == null)
            domain = "";

        if (username == null)
            throw new IllegalArgumentException("No username passed");

        if (password == null)
            throw new IllegalArgumentException("Bad password");
    }

    protected void scanCommandLineArgs(String[] args)
    {
        String uncPath = args[0];
        parseUncPath(uncPath);

        for (int i = 1; i < args.length; i++)
        {
            boolean hasAnother = i < args.length - 1;

            String flag = args[i].toUpperCase();
            if (flag.equals("-U") && hasAnother)
            {
                parseUsername(args[i + 1]);
            }

            else if (flag.equals("-P") && hasAnother)
            {
                password = args[i + 1];
            }
        }
    }

    protected void parseUncPath(String uncPath)
    {
        if (!uncPath.startsWith("//"))
            throw new IllegalArgumentException(String.format("invalid UNC path [%s]", uncPath));

        assert uncPath.startsWith("//");

        String[] parts = uncPath.split("/", 5);

        if (parts.length != 5)
            throw new IllegalArgumentException(String.format("invalid UNC path [%s]", uncPath));

        hostname = parts[2];
        sharename = parts[3];
        dirpath = parts[4];
    }

    protected void parseUsername(String username)
    {
        String[] parts = username.split("/");
        if (parts.length == 1)
            domain = "";

        this.username = parts[parts.length - 1];
    }

    protected String formatDate(Date date)
    {
        return DATE_FORMAT.format(date);
    }

    protected String formatSize(int size)
    {
        if (size > 1024 * 1024 * 1024)
            return (size / (1024 * 1024 * 1024)) + "Gb";

        if (size > 1024 * 1024)
            return (size / (1024 * 1024)) + "Mb";

        if (size > 1024)
            return (size / (1024)) + "Kb";

        return Integer.toString(size);
    }
}