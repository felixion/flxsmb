package flxsmb.cli;

/**
 * CLI command to update a file's security/permissions info.
 *
 * Usage: flxsmb.cli.SetFileSecurityCommand //hostname/share/filePath.txt -u domain/username -p password
 *                                          -u userSid -g groupSid
 *                                          --grant sid:mask
 *                                          --revoke sid:mask
 *
 * The parameters to userSid and groupSid should be specified in the string format for SIDs.
 *
 * When granting or revoking permissions, the permission is specified as follows:
 *
 *      --grant S-1-0-1111:342342343432
 *
 *      Such that you are concatenating a string SID along with an ACE access mask.
 */
public class SetFileSecurityCommand
{
}
