package flxsmb.cli;

import jcifs.smb.NtlmPasswordAuthentication;
import jcifs.smb.SmbFile;

import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.security.MessageDigest;
import java.util.Date;

/**
 */
public class ChecksumFileCommand extends BaseCommand
{
    public static void main(String[] args) throws Exception
    {
        ChecksumFileCommand command = new ChecksumFileCommand();

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
            printFileChecksum(file);
        }
        else
        {
            for (SmbFile f : file.listFiles())
            {
                printFileChecksum(f);
            }
        }
    }

    private void printFileChecksum(SmbFile file) throws Exception
    {
        InputStream inputStream = file.getInputStream();
        byte[] buffer = new byte[file.getContentLength()];

        int bytesRead = inputStream.read(buffer, 0, buffer.length);
        System.out.println(String.format("read %d/%d", bytesRead, buffer.length));

        MessageDigest md5 = MessageDigest.getInstance("MD5");
        byte[] md5sum = md5.digest(buffer);

        BigInteger bigInt = new BigInteger(1, md5sum);
        String hashtext = bigInt.toString(16);

        System.out.println(String.format("file %s [%s]\n\tmd5sum: %s [size: %s]", file.getName(), file.getCanonicalPath(), hashtext,
                formatSize(file.getContentLength())));
    }
}
