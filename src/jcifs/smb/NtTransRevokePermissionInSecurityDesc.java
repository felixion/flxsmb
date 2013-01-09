package jcifs.smb;

import jcifs.util.Hexdump;

/**
 * -------------- MPRV PATCH -------------
 * Implements permission revocation on a given file. <p>
 * Input:
 * <li>fid - file id</li>
 * <li>securityInformation - defines the operation. In revocation securityInformation = 0x04</li>
 * <li>securityDescriptor - security descriptor that will be updated and sent in revocation tx</li>
 * <li>sid - user/group for whom the permission should be revoked</li>
 * <li>mask - the permissions that should be revoked</li>
 *
 */
class NtTransRevokePermissionInSecurityDesc extends NtTransSetSecurityDesc {

    NtTransRevokePermissionInSecurityDesc(int fid, int securityInformation, SecurityDescriptor securityDescriptor, SID sid, int mask) {
        super(fid, securityInformation, securityDescriptor, sid, mask);
    }

    protected int updateAccess(ACE ace) {
        return ace.getAccessMask() & ~mask;
    }

    public String toString() {
        return new String("Revoke ----->  NtTransRevokePermissionInSecurityDesc[" + super.toString() +
                ",fid=0x" + Hexdump.toHexString(fid, 4) +
                ",securityInformation=0x" + Hexdump.toHexString(securityInformation, 8) + "]");
    }
}