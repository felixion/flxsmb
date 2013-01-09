/*
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 *
 */

package jcifs.smb;


/**
 * Implements permission change on a given file. <p>
 * Any class that inherits from NtTransSetSecurityDescAccess should implement the @see updateAccess() method
 *
 * Input:
 * <li>fid - file id</li>
 * <li>securityInformation - defines the operation
 * <li>securityDescriptor - security descriptor that will be updated </li>
 * <li>sid - user/group for whom the permission should be changed</li>
 * <li>mask - the permissions that should be changed</li>
 *
 */
class NtTransSetSecurityDescOwner extends SmbComNtTransaction {

    protected final static long NO_OFFSET = 0l;
    protected final static long OWNER_OFFSET = 20l;//DACL_OFFSET  = 2 (revision) + 2 (control) + 4*4 (4*offset)  =  20 bytes
    protected final static long SET_OWNER_CONTROL_FLAGS = 32770;//todo: explain the flags

    /**
     * File encoding
     */
    int fid;

    /**
     * Fields of security descriptor to be set
     * In our case 0x04 = DACL  (we write DACLs)
     */
    int securityInformation = 0x01;

//    /**
//     * Security descriptor that will be revoked
//     */
//    SecurityDescriptor securityDescriptor;

    /**
     * Sid for which the permission should be revoked
     */
    SID owner;

    NtTransSetSecurityDescOwner() {
    }

    NtTransSetSecurityDescOwner(int fid, SID owner) {
        this.fid = fid;
        this.owner = owner;

        command = SMB_COM_NT_TRANSACT;

        //initialization for the revoke tx
        function = NT_TRANSACT_SET_SECURITY_DESC;
        maxSetupCount = (byte) 0x00;
        maxParameterCount = 0;
        maxDataCount = 0;
        setupCount = 0;

    }

    int writeSetupWireFormat(byte[] dst, int dstIndex) {
        return 0;
    }

    /**
     * Allocates and writes parameters in the buffer(=transaction package)
     * The parameters appears as follows:
     * 1. fid (2 bytes)
     * 2. reserved (2 bytes)
     * 3. securityInfo (4 bytes)
     *
     * @param dst      buffer
     * @param dstIndex start index of the parameters
     * @return size of the parameters in the buffer
     */
    int writeParametersWireFormat(byte[] dst, int dstIndex) {
        int start = dstIndex;
        writeInt2(fid, dst, dstIndex);
        dstIndex += 2;
        dst[dstIndex++] = (byte) 0x00; // Reserved
        dst[dstIndex++] = (byte) 0x00; // Reserved
        writeInt4(securityInformation, dst, dstIndex);
        dstIndex += 4;

        return dstIndex - start;
    }

    /**
     * Allocates and writes data (=security descriptor):
     * 1. Revision (1 byte) = 0x01
     * 2. Sbz1 (1 byte)  = 0x00
     * 3. Control (2 bytes)
     * 4. offsets (4 x 4 bytes) --> (there is only offset for Dacl)
     * 5. writing the dacl
     *
     * @param dst      buffer
     * @param dstIndex start index of the data
     * @return size of the data in the buffer
     */
    int writeDataWireFormat(byte[] dst, int dstIndex) {
        int start = dstIndex;

        // Revision
        dst[dstIndex++] = (byte) 0x01;

        // Sbz1
        dst[dstIndex++] = (byte) 0x00; // Sbz1

        // Control
        writeInt2(SET_OWNER_CONTROL_FLAGS, dst, dstIndex);
        dstIndex += 2;

        //-------- writting offsets --------

        //offset owner
        //OWNER_OFFSET  = 2 (revision) + 2 (control) + 4*4 (4*offset)  =  20 bytes
        writeInt4(OWNER_OFFSET, dst, dstIndex);
        dstIndex += 4;

        //offset group
        writeInt4(NO_OFFSET, dst, dstIndex);
        dstIndex += 4;

        //offset Sacl
        writeInt4(NO_OFFSET, dst, dstIndex);
        dstIndex += 4;

        //DACL_OFFSET  = 2 (revision) + 2 (control) + 4*4 (4*offset)  =  20 bytes
        writeInt4(NO_OFFSET, dst, dstIndex);
        dstIndex += 4;

        //--- write owner SID ---
        byte[] sidArr = SID.toByteArray(owner);

        ServerMessageBlock.writeByteArr(sidArr, dst, dstIndex);
        dstIndex+=sidArr.length;

        return dstIndex - start;

    }

    int readSetupWireFormat(byte[] buffer, int bufferIndex, int len) {
        return 0;
    }

    int readParametersWireFormat(byte[] buffer, int bufferIndex, int len) {
        return 0;
    }

    int readDataWireFormat(byte[] buffer, int bufferIndex, int len) {
        return 0;
    }
}
