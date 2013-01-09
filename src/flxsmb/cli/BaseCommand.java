package flxsmb.cli;

import jcifs.smb.NtlmPasswordAuthentication;
import jcifs.smb.SID;

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

    protected boolean recurse = false;
    protected boolean verbose = false;
    protected boolean _filepathRequired = true;

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
        if (hostname == null || sharename == null || (dirpath == null && _filepathRequired))
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
        if (args.length < 1)
            throw new IllegalArgumentException("no destination UNC path specified");

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

            else if (flag.equals("-R"))
            {
                recurse = true;
            }

            else if (flag.equals("-V"))
            {
                verbose = true;
            }
        }
    }

    protected void parseUncPath(String uncPath)
    {
        if (!uncPath.startsWith("//"))
            throw new IllegalArgumentException(String.format("invalid UNC path [%s]", uncPath));

        assert uncPath.startsWith("//");

        String[] parts = uncPath.split("/", 5);

        if (parts.length < 4 || parts.length > 5)
            throw new IllegalArgumentException(String.format("invalid UNC path [%s]", uncPath));

        hostname = parts[2];
        sharename = parts[3];
        dirpath = parts.length == 5 ? parts[4] : null;
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

    public String toString()
    {
        String hostname = this.hostname != null ? this.hostname : "";
        String sharename = this.sharename != null ? this.sharename : "";
        String domain = this.domain != null ? this.domain : "";
        String username = this.username != null ? this.username : "";
        String password = this.password != null ? this.password : "";

        return String.format("#<%s :hostname %s :share %s :dirpath %s :domain %s :username %s :password %s",
                this.getClass().getName(), hostname, sharename, dirpath, domain, username, password.replaceAll(".", "*"));
    }

    protected String formatUser(SID sid) throws IOException
    {
        sid = resolveSID(sid);

        if (sid.getAccountName() != null)
            return sid.getAccountName();

        return sid.toDisplayString();
    }

    protected SID resolveSID(SID sid) throws IOException
    {
        if (sid.getAccountName() == null)
            sid.resolve(hostname, new NtlmPasswordAuthentication(domain, username, password));

        return sid;
    }
}
