package flxsmb.tests.utils;

public class ShareInfo
{
    public final String hostname;
    public final String sharename;
    public final String domain;
    public final String username;
    public final String password;

    public ShareInfo(String hostname, String sharename, String domain, String username, String password)
    {
        this.hostname = hostname;
        this.sharename = sharename;
        this.domain = domain;
        this.username = username;
        this.password = password;
    }

    @Override
    public boolean equals(Object o)
    {
        if (this == o) return true;
        if (o == null || getClass() != o.getClass()) return false;

        ShareInfo that = (ShareInfo) o;

        if (!domain.equals(that.domain)) return false;
        if (!hostname.equals(that.hostname)) return false;
        if (!password.equals(that.password)) return false;
        if (!sharename.equals(that.sharename)) return false;
        if (!username.equals(that.username)) return false;

        return true;
    }

    @Override
    public int hashCode()
    {
        int result = hostname.hashCode();
        result = 31 * result + sharename.hashCode();
        result = 31 * result + domain.hashCode();
        result = 31 * result + username.hashCode();
        result = 31 * result + password.hashCode();
        return result;
    }

    @Override
    public String toString()
    {
        return String.format("#<ShareInfo :hostname %s :sharename %s :domain %s :username %s>", hostname, sharename, domain, username);
    }

    public String getDomain()
    {
        return domain;
    }

    public String getHostname()
    {
        return hostname;
    }

    public String getPassword()
    {
        return password;
    }

    public String getSharename()
    {
        return sharename;
    }

    public String getUsername()
    {
        return username;
    }
}
