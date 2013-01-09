Index: src/jcifs/smb/NtTransRevokePermissionInSecurityDesc.java
===================================================================
--- src/jcifs/smb/NtTransRevokePermissionInSecurityDesc.java	(revision )
+++ src/jcifs/smb/NtTransRevokePermissionInSecurityDesc.java	(revision )
@@ -0,0 +1,32 @@
+
+package jcifs.smb;
+
+import jcifs.util.Hexdump;
+
+/**
+ * -------------- MPRV PATCH -------------
+ * Implements permission revocation on a given file. <p>
+ * Input:
+ * <li>fid - file id</li>
+ * <li>securityInformation - defines the operation. In revocation securityInformation = 0x04</li>
+ * <li>securityDescriptor - security descriptor that will be updated and sent in revocation tx</li>
+ * <li>sid - user/group for whom the permission should be revoked</li>
+ * <li>mask - the permissions that should be revoked</li>
+ *
+ */
+class NtTransRevokePermissionInSecurityDesc extends NtTransSetSecurityDesc {
+
+    NtTransRevokePermissionInSecurityDesc(int fid, int securityInformation, SecurityDescriptor securityDescriptor, SID sid, int mask) {
+        super(fid, securityInformation, securityDescriptor, sid, mask);
+    }
+
+    protected int updateAccess(ACE ace) {
+        return ace.getAccessMask() & ~mask;
+    }
+
+    public String toString() {
+        return new String("Revoke ----->  NtTransRevokePermissionInSecurityDesc[" + super.toString() +
+                ",fid=0x" + Hexdump.toHexString(fid, 4) +
+                ",securityInformation=0x" + Hexdump.toHexString(securityInformation, 8) + "]");
+    }
+}
\ No newline at end of file
Index: src/jcifs/smb/SetSecurity.java
===================================================================
--- src/jcifs/smb/SetSecurity.java	(revision )
+++ src/jcifs/smb/SetSecurity.java	(revision )
@@ -0,0 +1,46 @@
+package jcifs.smb;
+
+import jcifs.Config;
+
+public class SetSecurity {
+
+    final static int readAccessRight = 0x00020000;
+    final static int readAttrsAccessRight = 0x00000080;
+    final static int readExtendedAttrsAccessRight = 0x00000008;
+    final static int createFileWriteDataAccessRight = 0x00000002;
+    private final static int listFolderReadDataAccessRight = 0x00000001;
+
+    public static void main(String[] argv) throws Exception {
+
+        // set the jcifs encoding to UTF8 in order to resolve server and file names in this format
+        System.setProperty("jcifs.encoding", "UTF8");
+        Config.setProperty("jcifs.smb.client.dfs.disabled", Boolean.TRUE.toString());
+
+
+        NtlmPasswordAuthentication nt = new NtlmPasswordAuthentication("il", "rina", "Zim11mya");
+        SmbFile file1 = new SmbFile("smb://10.2.48.85/rina/rina_test.txt", nt);
+
+        SecurityDescriptor securityDescriptorBefore = file1.getSecurityDescriptor(true);
+
+
+        ACE[] acesBefore = securityDescriptorBefore.aces;
+        System.out.println("ACEs before set: ");
+        for (int ai = 0; ai < acesBefore.length; ai++) {
+            System.out.println(acesBefore[ai].access);
+        }
+
+
+        SID sid = file1.getOwnerUser();
+        int maskToRevoke  = readAccessRight | readExtendedAttrsAccessRight;
+        file1.revokePermission(securityDescriptorBefore, sid, maskToRevoke);
+
+
+        SecurityDescriptor securityDescriptorAfter = file1.getSecurityDescriptor(true);
+
+        ACE[] acesAfter = securityDescriptorAfter.aces;
+        System.out.println("ACEs after set: ");
+        for (int ai = 0; ai < acesAfter.length; ai++) {
+            System.out.println(acesAfter[ai].access);
+        }
+    }
+}
\ No newline at end of file
Index: src/jcifs/smb/NtTransSetSecurityDescResponse.java
===================================================================
--- src/jcifs/smb/NtTransSetSecurityDescResponse.java	(revision )
+++ src/jcifs/smb/NtTransSetSecurityDescResponse.java	(revision )
@@ -0,0 +1,60 @@
+/* jcifs smb client library in Java
+ * Copyright (C) 2005  "Michael B. Allen" <jcifs at samba dot org>
+ *
+ * This library is free software; you can redistribute it and/or
+ * modify it under the terms of the GNU Lesser General Public
+ * License as published by the Free Software Foundation; either
+ * version 2.1 of the License, or (at your option) any later version.
+ *
+ * This library is distributed in the hope that it will be useful,
+ * but WITHOUT ANY WARRANTY; without even the implied warranty of
+ * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
+ * Lesser General Public License for more details.
+ *
+ * You should have received a copy of the GNU Lesser General Public
+ * License along with this library; if not, write to the Free Software
+ * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
+ */
+
+package jcifs.smb;
+
+
+/**
+ * -------------- MPRV PATCH -------------
+ * Implements response  for permission revocation <p>
+ */
+class NtTransSetSecurityDescResponse extends SmbComNtTransactionResponse {
+
+    NtTransSetSecurityDescResponse() {
+        super();
+    }
+
+    int writeSetupWireFormat( byte[] dst, int dstIndex ) {
+        return 0;
+    }
+    int writeParametersWireFormat( byte[] dst, int dstIndex ) {
+        return 0;
+    }
+    int writeDataWireFormat( byte[] dst, int dstIndex ) {
+        return 0;
+    }
+    int readSetupWireFormat( byte[] buffer, int bufferIndex, int len ) {
+        return 0;
+    }
+    int readParametersWireFormat( byte[] buffer, int bufferIndex, int len ) {
+        return 0;         // no parameters
+    }
+    int readDataWireFormat( byte[] buffer, int bufferIndex, int len ) {
+        int start = bufferIndex;
+
+        if (errorCode != 0)
+            return 4;
+
+
+        return 0;//no data
+    }
+    public String toString() {
+        return new String( "NtTransSetSecurityDescResponse[" +
+             super.toString() + "]" );
+    }
+}
\ No newline at end of file
Index: src/jcifs/smb/NtTransSetSecurityDesc.java
===================================================================
--- src/jcifs/smb/NtTransSetSecurityDesc.java	(revision )
+++ src/jcifs/smb/NtTransSetSecurityDesc.java	(revision )
@@ -0,0 +1,202 @@
+/*
+ *
+ *
+ *
+ *
+ *
+ *
+ *
+ *
+ *
+ *
+ *
+ */
+
+package jcifs.smb;
+
+
+/**
+ * Implements permission change on a given file. <p>
+ * Any class that inherits from NtTransSetSecurityDesc should implement the @see updateAccess() method
+ *
+ * Input:
+ * <li>fid - file id</li>
+ * <li>securityInformation - defines the operation
+ * <li>securityDescriptor - security descriptor that will be updated </li>
+ * <li>sid - user/group for whom the permission should be changed</li>
+ * <li>mask - the permissions that should be changed</li>
+ *
+ */
+abstract class NtTransSetSecurityDesc extends SmbComNtTransaction {
+
+    protected final static long NO_OFFSET = 0l;
+    protected final static long DACL_OFFSET = 20l;//DACL_OFFSET  = 2 (revision) + 2 (control) + 4*4 (4*offset)  =  20 bytes
+    protected final static long SET_DACL_CONTROL_FLAGS = 0x9407;//todo: explain the flags
+
+
+    /**
+     * File encoding
+     */
+    int fid;
+
+    /**
+     * Fields of security descriptor to be set
+     * In our case 0x04 = DACL  (we write DACLs)
+     */
+    int securityInformation;
+
+    /**
+     * Security descriptor that will be revoked
+     */
+    SecurityDescriptor securityDescriptor;
+
+    /**
+     * Sid for which the permission should be revoked
+     */
+    SID sid;//todo: change name
+
+    /**
+     * Permission that should be changed
+     */
+    int mask;
+
+
+    NtTransSetSecurityDesc() {
+    }
+
+    NtTransSetSecurityDesc(int fid, int securityInformation, SecurityDescriptor securityDescriptor, SID sid, int mask) {
+        this.fid = fid;
+        this.securityInformation = securityInformation;
+        this.securityDescriptor = securityDescriptor;
+        this.sid = sid;
+        this.mask = mask;
+
+        command = SMB_COM_NT_TRANSACT;
+
+        //initialization for the revoke tx
+        function = NT_TRANSACT_SET_SECURITY_DESC;
+        maxSetupCount = (byte) 0x00;
+        maxParameterCount = 0;
+        maxDataCount = 0;
+        setupCount = 0;
+
+    }
+
+    int writeSetupWireFormat(byte[] dst, int dstIndex) {
+        return 0;
+    }
+
+    /**
+     * Allocates and writes parameters in the buffer(=transaction package)
+     * The parameters appears as follows:
+     * 1. fid (2 bytes)
+     * 2. reserved (2 bytes)
+     * 3. securityInfo (4 bytes)
+     *
+     * @param dst      buffer
+     * @param dstIndex start index of the parameters
+     * @return size of the parameters in the buffer
+     */
+    int writeParametersWireFormat(byte[] dst, int dstIndex) {
+        int start = dstIndex;
+        writeInt2(fid, dst, dstIndex);
+        dstIndex += 2;
+        dst[dstIndex++] = (byte) 0x00; // Reserved
+        dst[dstIndex++] = (byte) 0x00; // Reserved
+        writeInt4(securityInformation, dst, dstIndex);
+        dstIndex += 4;
+
+        return dstIndex - start;
+    }
+
+    /**
+     * Allocates and writes data (=security descriptor):
+     * 1. Revision (1 byte) = 0x01
+     * 2. Sbz1 (1 byte)  = 0x00
+     * 3. Control (2 bytes)
+     * 4. offsets (4 x 4 bytes) --> (there is only offset for Dacl)
+     * 5. writing the dacl
+     *
+     * @param dst      buffer
+     * @param dstIndex start index of the data
+     * @return size of the data in the buffer
+     */
+    int writeDataWireFormat(byte[] dst, int dstIndex) {
+        int start = dstIndex;
+
+        // Revision
+        dst[dstIndex++] = (byte) 0x01;
+
+        // Sbz1
+        dst[dstIndex++] = (byte) 0x00; // Sbz1
+
+        // Control
+        writeInt2(SET_DACL_CONTROL_FLAGS, dst, dstIndex);
+        dstIndex += 2;
+
+        //-------- writting offsets --------
+
+        //offset owner
+        writeInt4(NO_OFFSET, dst, dstIndex);
+        dstIndex += 4;
+
+        //offset group
+        writeInt4(NO_OFFSET, dst, dstIndex);
+        dstIndex += 4;
+
+        //offset Sacl
+        writeInt4(NO_OFFSET, dst, dstIndex);
+        dstIndex += 4;
+
+        //DACL_OFFSET  = 2 (revision) + 2 (control) + 4*4 (4*offset)  =  20 bytes
+        writeInt4(DACL_OFFSET, dst, dstIndex);
+        dstIndex += 4;
+
+
+        //----------- writing the Dcls --------
+
+        //Revision
+        dst[dstIndex++] = (byte) 0x02;
+        dst[dstIndex++] = (byte) 0x00;
+
+        int acesBlockSize = 1 + 1 + 2 + 4;//revision (2) + size (2) + numOfACEs(4)
+        for (ACE ace : securityDescriptor.aces) {
+            acesBlockSize += ace.getACESize();
+        }
+
+        writeInt2(acesBlockSize, dst, dstIndex);
+        dstIndex += 2;
+
+        writeInt4(securityDescriptor.aces.length, dst, dstIndex);
+        dstIndex += 4;
+
+        for (ACE ace : securityDescriptor.aces) {
+            int size;
+            if(ace.getSID().equals(sid) && ace.allow){
+                int updatedAccess = updateAccess(ace);
+                size = ace.encode(dst, dstIndex, updatedAccess);
+            }else{
+                size = ace.encode(dst, dstIndex);
+            }
+            dstIndex += size;
+        }
+
+        return dstIndex - start;
+
+    }
+
+    int readSetupWireFormat(byte[] buffer, int bufferIndex, int len) {
+        return 0;
+    }
+
+    int readParametersWireFormat(byte[] buffer, int bufferIndex, int len) {
+        return 0;
+    }
+
+    int readDataWireFormat(byte[] buffer, int bufferIndex, int len) {
+        return 0;
+    }
+
+    abstract protected int updateAccess(ACE ace) ;
+
+}
\ No newline at end of file
Index: src/jcifs/smb/SmbFile.java
===================================================================
--- src/jcifs/smb/SmbFile.java	(revision 70223)
+++ src/jcifs/smb/SmbFile.java	(revision )
@@ -47,38 +47,38 @@
  * the well known {@link java.io.File} class. One fundamental difference
  * is the usage of a URL scheme [1] to specify the target files or
  * directory. SmbFile URLs have the following syntax:
- *
+ * <p/>
  * <blockquote><pre>
  *     smb://[[[domain;]username[:password]@]server[:port]/[[share/[dir/]files]]][?[param=value[param2=value2[...]]]
  * </pre></blockquote>
- *
+ * <p/>
  * This example:
- *
+ * <p/>
  * <blockquote><pre>
  *     smb://storage15/public/foo.txt
  * </pre></blockquote>
- *
+ * <p/>
  * would reference the files <code>foo.txt</code> in the share
  * <code>public</code> on the server <code>storage15</code>. In addition
  * to referencing files and directories, jCIFS can also address servers,
  * and workgroups.
- * <p>
+ * <p/>
  * <font color="#800000"><i>Important: all SMB URLs that represent
  * workgroups, servers, shares, or directories require a trailing slash '/'.
  * </i></font>
- * <p>
+ * <p/>
  * When using the <tt>java.net.URL</tt> class with
  * 'smb://' URLs it is necessary to first call the static
  * <tt>jcifs.Config.registerSmbURLHandler();</tt> method. This is required
  * to register the SMB protocol handler.
- * <p>
+ * <p/>
  * The userinfo component of the SMB URL (<tt>domain;user:pass</tt>) must
  * be URL encoded if it contains reserved characters. According to RFC 2396
  * these characters are non US-ASCII characters and most meta characters
  * however jCIFS will work correctly with anything but '@' which is used
  * to delimit the userinfo component from the server and '%' which is the
  * URL escape character itself.
- * <p>
+ * <p/>
  * The server
  * component may a traditional NetBIOS name, a DNS name, or IP
  * address. These name resolution mechanisms and their resolution order
@@ -89,34 +89,34 @@
  * to function (See <a href="../../overview-summary.html#scp">Setting
  * JCIFS Properties</a>). Here are some examples of SMB URLs with brief
  * descriptions of what they do:
- *
+ * <p/>
  * <p>[1] This URL scheme is based largely on the <i>SMB
  * Filesharing URL Scheme</i> IETF draft.
- *
+ * <p/>
  * <p><table border="1" cellpadding="3" cellspacing="0" width="100%">
  * <tr bgcolor="#ccccff">
  * <td colspan="2"><b>SMB URL Examples</b></td>
  * <tr><td width="20%"><b>URL</b></td><td><b>Description</b></td></tr>
- *
+ * <p/>
  * <tr><td width="20%"><code>smb://users-nyc;miallen:mypass@angus/tmp/</code></td><td>
  * This URL references a share called <code>tmp</code> on the server
  * <code>angus</code> as user <code>miallen</code> who's password is
  * <code>mypass</code>.
  * </td></tr>
- *
+ * <p/>
  * <tr><td width="20%">
  * <code>smb://Administrator:P%40ss@msmith1/c/WINDOWS/Desktop/foo.txt</code></td><td>
  * A relativly sophisticated example that references a files
  * <code>msmith1</code>'s desktop as user <code>Administrator</code>. Notice the '@' is URL encoded with the '%40' hexcode escape.
  * </td></tr>
- *
+ * <p/>
  * <tr><td width="20%"><code>smb://angus/</code></td><td>
  * This references only a server. The behavior of some methods is different
  * in this context(e.g. you cannot <code>delete</code> a server) however
  * as you might expect the <code>list</code> method will list the available
  * shares on this server.
  * </td></tr>
- *
+ * <p/>
  * <tr><td width="20%"><code>smb://myworkgroup/</code></td><td>
  * This syntactically is identical to the above example. However if
  * <code>myworkgroup</code> happends to be a workgroup(which is indeed
@@ -124,7 +124,7 @@
  * a list of servers that have registered themselves as members of
  * <code>myworkgroup</code>.
  * </td></tr>
- *
+ * <p/>
  * <tr><td width="20%"><code>smb://</code></td><td>
  * Just as <code>smb://server/</code> lists shares and
  * <code>smb://workgroup/</code> lists servers, the <code>smb://</code>
@@ -132,34 +132,34 @@
  * in this context many methods are not valid and return default
  * values(e.g. <code>isHidden</code> will always return false).
  * </td></tr>
- *
+ * <p/>
  * <tr><td width="20%"><code>smb://angus.foo.net/d/jcifs/pipes.doc</code></td><td>
  * The server name may also be a DNS name as it is in this example. See
  * <a href="../../../resolver.html">Setting Name Resolution Properties</a>
  * for details.
  * </td></tr>
- *
+ * <p/>
  * <tr><td width="20%"><code>smb://192.168.1.15/ADMIN$/</code></td><td>
  * The server name may also be an IP address. See <a
  * href="../../../resolver.html">Setting Name Resolution Properties</a>
  * for details.
  * </td></tr>
- *
+ * <p/>
  * <tr><td width="20%">
  * <code>smb://domain;username:password@server/share/path/to/files.txt</code></td><td>
  * A prototypical example that uses all the fields.
  * </td></tr>
- *
+ * <p/>
  * <tr><td width="20%"><code>smb://myworkgroup/angus/ &lt;-- ILLEGAL </code></td><td>
  * Despite the hierarchial relationship between workgroups, servers, and
  * filesystems this example is not valid.
  * </td></tr>
- *
+ * <p/>
  * <tr><td width="20%">
  * <code>smb://server/share/path/to/dir &lt;-- ILLEGAL </code></td><td>
  * URLs that represent workgroups, servers, shares, or directories require a trailing slash '/'.
  * </td></tr>
- *
+ * <p/>
  * <tr><td width="20%">
  * <code>smb://MYGROUP/?SERVER=192.168.10.15</code></td><td>
  * SMB URLs support some query string parameters. In this example
@@ -168,9 +168,9 @@
  * (presumably known to be a master
  * browser) for the server list in workgroup <code>MYGROUP</code>.
  * </td></tr>
- *
+ * <p/>
  * </table>
- *
+ * <p/>
  * <p>A second constructor argument may be specified to augment the URL
  * for better programmatic control when processing many files under
  * a common base. This is slightly different from the corresponding
@@ -178,183 +178,183 @@
  * parameter will still use the server component of the first parameter. The
  * examples below illustrate the resulting URLs when this second contructor
  * argument is used.
- *
+ * <p/>
  * <p><table border="1" cellpadding="3" cellspacing="0" width="100%">
  * <tr bgcolor="#ccccff">
  * <td colspan="3">
  * <b>Examples Of SMB URLs When Augmented With A Second Constructor Parameter</b></td>
  * <tr><td width="20%">
  * <b>First Parameter</b></td><td><b>Second Parameter</b></td><td><b>Result</b></td></tr>
- *
+ * <p/>
  * <tr><td width="20%"><code>
- *  smb://host/share/a/b/
+ * smb://host/share/a/b/
  * </code></td><td width="20%"><code>
- *  c/d/
+ * c/d/
  * </code></td><td><code>
- *  smb://host/share/a/b/c/d/
+ * smb://host/share/a/b/c/d/
  * </code></td></tr>
- *
+ * <p/>
  * <tr><td width="20%"><code>
- *  smb://host/share/foo/bar/
+ * smb://host/share/foo/bar/
  * </code></td><td width="20%"><code>
- *  /share2/zig/zag
+ * /share2/zig/zag
  * </code></td><td><code>
- *  smb://host/share2/zig/zag
+ * smb://host/share2/zig/zag
  * </code></td></tr>
- *
+ * <p/>
  * <tr><td width="20%"><code>
- *  smb://host/share/foo/bar/
+ * smb://host/share/foo/bar/
  * </code></td><td width="20%"><code>
- *  ../zip/
+ * ../zip/
  * </code></td><td><code>
- *  smb://host/share/foo/zip/
+ * smb://host/share/foo/zip/
  * </code></td></tr>
- *
+ * <p/>
  * <tr><td width="20%"><code>
- *  smb://host/share/zig/zag
+ * smb://host/share/zig/zag
  * </code></td><td width="20%"><code>
- *  smb://foo/bar/
+ * smb://foo/bar/
  * </code></td><td><code>
- *  smb://foo/bar/
+ * smb://foo/bar/
  * </code></td></tr>
- *
+ * <p/>
  * <tr><td width="20%"><code>
- *  smb://host/share/foo/
+ * smb://host/share/foo/
  * </code></td><td width="20%"><code>
- *  ../.././.././../foo/
+ * ../.././.././../foo/
  * </code></td><td><code>
- *  smb://host/foo/
+ * smb://host/foo/
  * </code></td></tr>
- *
+ * <p/>
  * <tr><td width="20%"><code>
- *  smb://host/share/zig/zag
+ * smb://host/share/zig/zag
  * </code></td><td width="20%"><code>
- *  /
+ * /
  * </code></td><td><code>
- *  smb://host/
+ * smb://host/
  * </code></td></tr>
- *
+ * <p/>
  * <tr><td width="20%"><code>
- *  smb://server/
+ * smb://server/
  * </code></td><td width="20%"><code>
- *  ../
+ * ../
  * </code></td><td><code>
- *  smb://server/
+ * smb://server/
  * </code></td></tr>
- *
+ * <p/>
  * <tr><td width="20%"><code>
- *  smb://
+ * smb://
  * </code></td><td width="20%"><code>
- *  myworkgroup/
+ * myworkgroup/
  * </code></td><td><code>
- *  smb://myworkgroup/
+ * smb://myworkgroup/
  * </code></td></tr>
- *
+ * <p/>
  * <tr><td width="20%"><code>
- *  smb://myworkgroup/
+ * smb://myworkgroup/
  * </code></td><td width="20%"><code>
- *  angus/
+ * angus/
  * </code></td><td><code>
- *  smb://myworkgroup/angus/ &lt;-- ILLEGAL<br>(But if you first create an <tt>SmbFile</tt> with 'smb://workgroup/' and use and use it as the first parameter to a constructor that accepts it with a second <tt>String</tt> parameter jCIFS will factor out the 'workgroup'.)
+ * smb://myworkgroup/angus/ &lt;-- ILLEGAL<br>(But if you first create an <tt>SmbFile</tt> with 'smb://workgroup/' and use and use it as the first parameter to a constructor that accepts it with a second <tt>String</tt> parameter jCIFS will factor out the 'workgroup'.)
  * </code></td></tr>
- *
+ * <p/>
  * </table>
- *
+ * <p/>
  * <p>Instances of the <code>SmbFile</code> class are immutable; that is,
  * once created, the abstract pathname represented by an SmbFile object
  * will never change.
  *
- * @see       java.io.File
+ * @see java.io.File
  */

 public class SmbFile extends URLConnection implements SmbConstants {

     static final int O_RDONLY = 0x01;
     static final int O_WRONLY = 0x02;
-    static final int O_RDWR   = 0x03;
+    static final int O_RDWR = 0x03;
     static final int O_APPEND = 0x04;

     // Open Function Encoding
     // create if the files does not exist
-    static final int O_CREAT  = 0x0010;
+    static final int O_CREAT = 0x0010;
     // fail if the files exists
-    static final int O_EXCL   = 0x0020;
+    static final int O_EXCL = 0x0020;
     // truncate if the files exists
-    static final int O_TRUNC  = 0x0040;
+    static final int O_TRUNC = 0x0040;

     // share access
-/**
- * When specified as the <tt>shareAccess</tt> constructor parameter,
- * other SMB clients (including other threads making calls into jCIFS)
- * will not be permitted to access the target files and will receive "The
- * files is being accessed by another process" message.
- */
+    /**
+     * When specified as the <tt>shareAccess</tt> constructor parameter,
+     * other SMB clients (including other threads making calls into jCIFS)
+     * will not be permitted to access the target files and will receive "The
+     * files is being accessed by another process" message.
+     */
-    public static final int FILE_NO_SHARE     = 0x00;
+    public static final int FILE_NO_SHARE = 0x00;
-/**
- * When specified as the <tt>shareAccess</tt> constructor parameter,
- * other SMB clients will be permitted to read from the target files while
- * this files is open. This constant may be logically OR'd with other share
- * access flags.
- */
+    /**
+     * When specified as the <tt>shareAccess</tt> constructor parameter,
+     * other SMB clients will be permitted to read from the target files while
+     * this files is open. This constant may be logically OR'd with other share
+     * access flags.
+     */
-    public static final int FILE_SHARE_READ   = 0x01;
+    public static final int FILE_SHARE_READ = 0x01;
-/**
- * When specified as the <tt>shareAccess</tt> constructor parameter,
- * other SMB clients will be permitted to write to the target files while
- * this files is open. This constant may be logically OR'd with other share
- * access flags.
- */
+    /**
+     * When specified as the <tt>shareAccess</tt> constructor parameter,
+     * other SMB clients will be permitted to write to the target files while
+     * this files is open. This constant may be logically OR'd with other share
+     * access flags.
+     */
-    public static final int FILE_SHARE_WRITE  = 0x02;
+    public static final int FILE_SHARE_WRITE = 0x02;
-/**
- * When specified as the <tt>shareAccess</tt> constructor parameter,
- * other SMB clients will be permitted to delete the target files while
- * this files is open. This constant may be logically OR'd with other share
- * access flags.
- */
+    /**
+     * When specified as the <tt>shareAccess</tt> constructor parameter,
+     * other SMB clients will be permitted to delete the target files while
+     * this files is open. This constant may be logically OR'd with other share
+     * access flags.
+     */
     public static final int FILE_SHARE_DELETE = 0x04;

     // files attribute encoding
-/**
- * A files with this bit on as returned by <tt>getAttributes()</tt> or set
- * with <tt>setAttributes()</tt> will be read-only
- */
+    /**
+     * A files with this bit on as returned by <tt>getAttributes()</tt> or set
+     * with <tt>setAttributes()</tt> will be read-only
+     */
-    public static final int ATTR_READONLY   = 0x01;
+    public static final int ATTR_READONLY = 0x01;
-/**
- * A files with this bit on as returned by <tt>getAttributes()</tt> or set
- * with <tt>setAttributes()</tt> will be hidden
- */
+    /**
+     * A files with this bit on as returned by <tt>getAttributes()</tt> or set
+     * with <tt>setAttributes()</tt> will be hidden
+     */
-    public static final int ATTR_HIDDEN     = 0x02;
+    public static final int ATTR_HIDDEN = 0x02;
-/**
- * A files with this bit on as returned by <tt>getAttributes()</tt> or set
- * with <tt>setAttributes()</tt> will be a system files
- */
+    /**
+     * A files with this bit on as returned by <tt>getAttributes()</tt> or set
+     * with <tt>setAttributes()</tt> will be a system files
+     */
-    public static final int ATTR_SYSTEM     = 0x04;
+    public static final int ATTR_SYSTEM = 0x04;
-/**
- * A files with this bit on as returned by <tt>getAttributes()</tt> is
- * a volume
- */
+    /**
+     * A files with this bit on as returned by <tt>getAttributes()</tt> is
+     * a volume
+     */
-    public static final int ATTR_VOLUME     = 0x08;
+    public static final int ATTR_VOLUME = 0x08;
-/**
- * A files with this bit on as returned by <tt>getAttributes()</tt> is
- * a directory
- */
+    /**
+     * A files with this bit on as returned by <tt>getAttributes()</tt> is
+     * a directory
+     */
-    public static final int ATTR_DIRECTORY  = 0x10;
+    public static final int ATTR_DIRECTORY = 0x10;
-/**
- * A files with this bit on as returned by <tt>getAttributes()</tt> or set
- * with <tt>setAttributes()</tt> is an archived files
- */
+    /**
+     * A files with this bit on as returned by <tt>getAttributes()</tt> or set
+     * with <tt>setAttributes()</tt> is an archived files
+     */
-    public static final int ATTR_ARCHIVE    = 0x20;
+    public static final int ATTR_ARCHIVE = 0x20;

     // extended files attribute encoding(others same as above)
-    static final int ATTR_COMPRESSED       = 0x800;
+    static final int ATTR_COMPRESSED = 0x800;
-    static final int ATTR_NORMAL           = 0x080;
+    static final int ATTR_NORMAL = 0x080;
-    static final int ATTR_TEMPORARY        = 0x100;
+    static final int ATTR_TEMPORARY = 0x100;

     static final int ATTR_GET_MASK = 0x7FFF; /* orig 0x7fff */
     static final int ATTR_SET_MASK = 0x30A7; /* orig 0x0027 */

     static final int DEFAULT_ATTR_EXPIRATION_PERIOD = 5000;

-    static final int HASH_DOT     = ".".hashCode();
+    static final int HASH_DOT = ".".hashCode();
     static final int HASH_DOT_DOT = "..".hashCode();

     static LogStream log = LogStream.getInstance();
@@ -363,11 +363,11 @@
     static {

         try {
-            Class.forName( "jcifs.Config" );
+            Class.forName("jcifs.Config");
-        } catch( ClassNotFoundException cnfe ) {
+        } catch (ClassNotFoundException cnfe) {
             cnfe.printStackTrace();
         }
-        attrExpirationPeriod = Config.getLong( "jcifs.smb.client.attrExpirationPeriod", DEFAULT_ATTR_EXPIRATION_PERIOD );
+        attrExpirationPeriod = Config.getLong("jcifs.smb.client.attrExpirationPeriod", DEFAULT_ATTR_EXPIRATION_PERIOD);
         dfs = new Dfs();
     }

@@ -431,219 +431,217 @@
     boolean opened;
     int tree_num;

-/**
- * Constructs an SmbFile representing a resource on an SMB network such as
- * a files or directory. See the description and examples of smb URLs above.
- *
+    /**
+     * Constructs an SmbFile representing a resource on an SMB network such as
+     * a files or directory. See the description and examples of smb URLs above.
+     *
- * @param   url A URL string
+     * @param url A URL string
- * @throws  MalformedURLException
- *          If the <code>parent</code> and <code>child</code> parameters
+     * @throws MalformedURLException If the <code>parent</code> and <code>child</code> parameters
- *          do not follow the prescribed syntax
+     *                               do not follow the prescribed syntax
- */
+     */

-    public SmbFile( String url ) throws MalformedURLException {
+    public SmbFile(String url) throws MalformedURLException {
-        this( new URL( null, url, Handler.SMB_HANDLER ));
+        this(new URL(null, url, Handler.SMB_HANDLER));
     }

-/**
- * Constructs an SmbFile representing a resource on an SMB network such
- * as a files or directory. The second parameter is a relative path from
- * the <code>parent SmbFile</code>. See the description above for examples
- * of using the second <code>name</code> parameter.
- *
+    /**
+     * Constructs an SmbFile representing a resource on an SMB network such
+     * as a files or directory. The second parameter is a relative path from
+     * the <code>parent SmbFile</code>. See the description above for examples
+     * of using the second <code>name</code> parameter.
+     *
- * @param   context A base <code>SmbFile</code>
+     * @param context A base <code>SmbFile</code>
- * @param   name A path string relative to the <code>parent</code> paremeter
+     * @param name    A path string relative to the <code>parent</code> paremeter
- * @throws  MalformedURLException
- *          If the <code>parent</code> and <code>child</code> parameters
+     * @throws MalformedURLException If the <code>parent</code> and <code>child</code> parameters
- *          do not follow the prescribed syntax
+     *                               do not follow the prescribed syntax
- * @throws  UnknownHostException
- *          If the server or workgroup of the <tt>context</tt> files cannot be determined
+     * @throws UnknownHostException  If the server or workgroup of the <tt>context</tt> files cannot be determined
- */
+     */

-    public SmbFile( SmbFile context, String name )
+    public SmbFile(SmbFile context, String name)
-                throws MalformedURLException, UnknownHostException {
+            throws MalformedURLException, UnknownHostException {
-        this( context.isWorkgroup0() ?
+        this(context.isWorkgroup0() ?
-            new URL( null, "smb://" + name, Handler.SMB_HANDLER ) :
+                new URL(null, "smb://" + name, Handler.SMB_HANDLER) :
-            new URL( context.url, name, Handler.SMB_HANDLER ), context.auth );
+                new URL(context.url, name, Handler.SMB_HANDLER), context.auth);
     }

-/**
- * Constructs an SmbFile representing a resource on an SMB network such
- * as a files or directory. The second parameter is a relative path from
- * the <code>parent</code>. See the description above for examples of
- * using the second <code>chile</code> parameter.
- *
+    /**
+     * Constructs an SmbFile representing a resource on an SMB network such
+     * as a files or directory. The second parameter is a relative path from
+     * the <code>parent</code>. See the description above for examples of
+     * using the second <code>chile</code> parameter.
+     *
- * @param   context A URL string
+     * @param context A URL string
- * @param   name A path string relative to the <code>context</code> paremeter
+     * @param name    A path string relative to the <code>context</code> paremeter
- * @throws  MalformedURLException
- *          If the <code>context</code> and <code>name</code> parameters
+     * @throws MalformedURLException If the <code>context</code> and <code>name</code> parameters
- *          do not follow the prescribed syntax
+     *                               do not follow the prescribed syntax
- */
+     */

-    public SmbFile( String context, String name ) throws MalformedURLException {
+    public SmbFile(String context, String name) throws MalformedURLException {
-        this( new URL( new URL( null, context, Handler.SMB_HANDLER ),
+        this(new URL(new URL(null, context, Handler.SMB_HANDLER),
-                name, Handler.SMB_HANDLER ));
+                name, Handler.SMB_HANDLER));
     }

-/**
- * Constructs an SmbFile representing a resource on an SMB network such
- * as a files or directory.
- *
+    /**
+     * Constructs an SmbFile representing a resource on an SMB network such
+     * as a files or directory.
+     *
- * @param   url A URL string
+     * @param url  A URL string
- * @param   auth The credentials the client should use for authentication
+     * @param auth The credentials the client should use for authentication
- * @throws  MalformedURLException
- *          If the <code>url</code> parameter does not follow the prescribed syntax
+     * @throws MalformedURLException If the <code>url</code> parameter does not follow the prescribed syntax
- */
+     */
-    public SmbFile( String url, NtlmPasswordAuthentication auth )
+    public SmbFile(String url, NtlmPasswordAuthentication auth)
-                    throws MalformedURLException {
+            throws MalformedURLException {
-        this( new URL( null, url, Handler.SMB_HANDLER ), auth );
+        this(new URL(null, url, Handler.SMB_HANDLER), auth);
     }
+
-/**
- * Constructs an SmbFile representing a files on an SMB network. The
- * <tt>shareAccess</tt> parameter controls what permissions other
- * clients have when trying to access the same files while this instance
- * is still open. This value is either <tt>FILE_NO_SHARE</tt> or any
- * combination of <tt>FILE_SHARE_READ</tt>, <tt>FILE_SHARE_WRITE</tt>,
- * and <tt>FILE_SHARE_DELETE</tt> logically OR'd together.
- *
+    /**
+     * Constructs an SmbFile representing a files on an SMB network. The
+     * <tt>shareAccess</tt> parameter controls what permissions other
+     * clients have when trying to access the same files while this instance
+     * is still open. This value is either <tt>FILE_NO_SHARE</tt> or any
+     * combination of <tt>FILE_SHARE_READ</tt>, <tt>FILE_SHARE_WRITE</tt>,
+     * and <tt>FILE_SHARE_DELETE</tt> logically OR'd together.
+     *
- * @param   url A URL string
+     * @param url         A URL string
- * @param   auth The credentials the client should use for authentication
+     * @param auth        The credentials the client should use for authentication
- * @param   shareAccess Specifies what access other clients have while this files is open.
+     * @param shareAccess Specifies what access other clients have while this files is open.
- * @throws  MalformedURLException
- *          If the <code>url</code> parameter does not follow the prescribed syntax
+     * @throws MalformedURLException If the <code>url</code> parameter does not follow the prescribed syntax
- */
+     */
-    public SmbFile( String url, NtlmPasswordAuthentication auth, int shareAccess )
+    public SmbFile(String url, NtlmPasswordAuthentication auth, int shareAccess)
-                    throws MalformedURLException {
+            throws MalformedURLException {
-        this( new URL( null, url, Handler.SMB_HANDLER ), auth );
+        this(new URL(null, url, Handler.SMB_HANDLER), auth);
         if ((shareAccess & ~(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)) != 0) {
-            throw new RuntimeException( "Illegal shareAccess parameter" );
+            throw new RuntimeException("Illegal shareAccess parameter");
         }
         this.shareAccess = shareAccess;
     }
+
-/**
- * Constructs an SmbFile representing a resource on an SMB network such
- * as a files or directory. The second parameter is a relative path from
- * the <code>context</code>. See the description above for examples of
- * using the second <code>name</code> parameter.
- *
+    /**
+     * Constructs an SmbFile representing a resource on an SMB network such
+     * as a files or directory. The second parameter is a relative path from
+     * the <code>context</code>. See the description above for examples of
+     * using the second <code>name</code> parameter.
+     *
- * @param   context A URL string
+     * @param context A URL string
- * @param   name A path string relative to the <code>context</code> paremeter
+     * @param name    A path string relative to the <code>context</code> paremeter
- * @param   auth The credentials the client should use for authentication
+     * @param auth    The credentials the client should use for authentication
- * @throws  MalformedURLException
- *          If the <code>context</code> and <code>name</code> parameters
+     * @throws MalformedURLException If the <code>context</code> and <code>name</code> parameters
- *          do not follow the prescribed syntax
+     *                               do not follow the prescribed syntax
- */
+     */
-    public SmbFile( String context, String name, NtlmPasswordAuthentication auth )
+    public SmbFile(String context, String name, NtlmPasswordAuthentication auth)
-                    throws MalformedURLException {
+            throws MalformedURLException {
-        this( new URL( new URL( null, context, Handler.SMB_HANDLER ), name, Handler.SMB_HANDLER ), auth );
+        this(new URL(new URL(null, context, Handler.SMB_HANDLER), name, Handler.SMB_HANDLER), auth);
     }
+
-/**
- * Constructs an SmbFile representing a resource on an SMB network such
- * as a files or directory. The second parameter is a relative path from
- * the <code>context</code>. See the description above for examples of
- * using the second <code>name</code> parameter. The <tt>shareAccess</tt>
- * parameter controls what permissions other clients have when trying
- * to access the same files while this instance is still open. This
- * value is either <tt>FILE_NO_SHARE</tt> or any combination
- * of <tt>FILE_SHARE_READ</tt>, <tt>FILE_SHARE_WRITE</tt>, and
- * <tt>FILE_SHARE_DELETE</tt> logically OR'd together.
- *
+    /**
+     * Constructs an SmbFile representing a resource on an SMB network such
+     * as a files or directory. The second parameter is a relative path from
+     * the <code>context</code>. See the description above for examples of
+     * using the second <code>name</code> parameter. The <tt>shareAccess</tt>
+     * parameter controls what permissions other clients have when trying
+     * to access the same files while this instance is still open. This
+     * value is either <tt>FILE_NO_SHARE</tt> or any combination
+     * of <tt>FILE_SHARE_READ</tt>, <tt>FILE_SHARE_WRITE</tt>, and
+     * <tt>FILE_SHARE_DELETE</tt> logically OR'd together.
+     *
- * @param   context A URL string
+     * @param context     A URL string
- * @param   name A path string relative to the <code>context</code> paremeter
+     * @param name        A path string relative to the <code>context</code> paremeter
- * @param   auth The credentials the client should use for authentication
+     * @param auth        The credentials the client should use for authentication
- * @param   shareAccess Specifies what access other clients have while this files is open.
+     * @param shareAccess Specifies what access other clients have while this files is open.
- * @throws  MalformedURLException
- *          If the <code>context</code> and <code>name</code> parameters
+     * @throws MalformedURLException If the <code>context</code> and <code>name</code> parameters
- *          do not follow the prescribed syntax
+     *                               do not follow the prescribed syntax
- */
+     */
-    public SmbFile( String context, String name, NtlmPasswordAuthentication auth, int shareAccess )
+    public SmbFile(String context, String name, NtlmPasswordAuthentication auth, int shareAccess)
-                    throws MalformedURLException {
+            throws MalformedURLException {
-        this( new URL( new URL( null, context, Handler.SMB_HANDLER ), name, Handler.SMB_HANDLER ), auth );
+        this(new URL(new URL(null, context, Handler.SMB_HANDLER), name, Handler.SMB_HANDLER), auth);
         if ((shareAccess & ~(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)) != 0) {
-            throw new RuntimeException( "Illegal shareAccess parameter" );
+            throw new RuntimeException("Illegal shareAccess parameter");
         }
         this.shareAccess = shareAccess;
     }
+
-/**
- * Constructs an SmbFile representing a resource on an SMB network such
- * as a files or directory. The second parameter is a relative path from
- * the <code>context</code>. See the description above for examples of
- * using the second <code>name</code> parameter. The <tt>shareAccess</tt>
- * parameter controls what permissions other clients have when trying
- * to access the same files while this instance is still open. This
- * value is either <tt>FILE_NO_SHARE</tt> or any combination
- * of <tt>FILE_SHARE_READ</tt>, <tt>FILE_SHARE_WRITE</tt>, and
- * <tt>FILE_SHARE_DELETE</tt> logically OR'd together.
- *
+    /**
+     * Constructs an SmbFile representing a resource on an SMB network such
+     * as a files or directory. The second parameter is a relative path from
+     * the <code>context</code>. See the description above for examples of
+     * using the second <code>name</code> parameter. The <tt>shareAccess</tt>
+     * parameter controls what permissions other clients have when trying
+     * to access the same files while this instance is still open. This
+     * value is either <tt>FILE_NO_SHARE</tt> or any combination
+     * of <tt>FILE_SHARE_READ</tt>, <tt>FILE_SHARE_WRITE</tt>, and
+     * <tt>FILE_SHARE_DELETE</tt> logically OR'd together.
+     *
- * @param   context A base <code>SmbFile</code>
+     * @param context     A base <code>SmbFile</code>
- * @param   name A path string relative to the <code>context</code> files path
+     * @param name        A path string relative to the <code>context</code> files path
- * @param   shareAccess Specifies what access other clients have while this files is open.
+     * @param shareAccess Specifies what access other clients have while this files is open.
- * @throws  MalformedURLException
- *          If the <code>context</code> and <code>name</code> parameters
+     * @throws MalformedURLException If the <code>context</code> and <code>name</code> parameters
- *          do not follow the prescribed syntax
+     *                               do not follow the prescribed syntax
- */
+     */
-    public SmbFile( SmbFile context, String name, int shareAccess )
+    public SmbFile(SmbFile context, String name, int shareAccess)
-                    throws MalformedURLException, UnknownHostException {
+            throws MalformedURLException, UnknownHostException {
-        this( context.isWorkgroup0() ?
+        this(context.isWorkgroup0() ?
-            new URL( null, "smb://" + name, Handler.SMB_HANDLER ) :
+                new URL(null, "smb://" + name, Handler.SMB_HANDLER) :
-            new URL( context.url, name, Handler.SMB_HANDLER ), context.auth );
+                new URL(context.url, name, Handler.SMB_HANDLER), context.auth);
         if ((shareAccess & ~(FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE)) != 0) {
-            throw new RuntimeException( "Illegal shareAccess parameter" );
+            throw new RuntimeException("Illegal shareAccess parameter");
         }
         this.shareAccess = shareAccess;
     }
+
-/**
- * Constructs an SmbFile representing a resource on an SMB network such
- * as a files or directory from a <tt>URL</tt> object.
- *
+    /**
+     * Constructs an SmbFile representing a resource on an SMB network such
+     * as a files or directory from a <tt>URL</tt> object.
+     *
- * @param   url The URL of the target resource
+     * @param url The URL of the target resource
- */
+     */
-    public SmbFile( URL url ) {
+    public SmbFile(URL url) {
-        this( url, new NtlmPasswordAuthentication( url.getUserInfo() ));
+        this(url, new NtlmPasswordAuthentication(url.getUserInfo()));
     }
+
-/**
- * Constructs an SmbFile representing a resource on an SMB network such
- * as a files or directory from a <tt>URL</tt> object and an
- * <tt>NtlmPasswordAuthentication</tt> object.
- *
+    /**
+     * Constructs an SmbFile representing a resource on an SMB network such
+     * as a files or directory from a <tt>URL</tt> object and an
+     * <tt>NtlmPasswordAuthentication</tt> object.
+     *
- * @param   url The URL of the target resource
+     * @param url  The URL of the target resource
- * @param   auth The credentials the client should use for authentication
+     * @param auth The credentials the client should use for authentication
- */
+     */
-    public SmbFile( URL url, NtlmPasswordAuthentication auth ) {
+    public SmbFile(URL url, NtlmPasswordAuthentication auth) {
-        super( url );
+        super(url);
-        this.auth = auth == null ? new NtlmPasswordAuthentication( url.getUserInfo() ) : auth;
+        this.auth = auth == null ? new NtlmPasswordAuthentication(url.getUserInfo()) : auth;

         getUncPath0();
     }
+
-    SmbFile( SmbFile context, String name, int type,
+    SmbFile(SmbFile context, String name, int type,
-                int attributes, long createTime, long lastModified, long size )
+            int attributes, long createTime, long lastModified, long size)
-                throws MalformedURLException, UnknownHostException {
+            throws MalformedURLException, UnknownHostException {
-        this( context.isWorkgroup0() ?
+        this(context.isWorkgroup0() ?
-            new URL( null, "smb://" + name + "/", Handler.SMB_HANDLER ) :
+                new URL(null, "smb://" + name + "/", Handler.SMB_HANDLER) :
-            new URL( context.url, name + (( attributes & ATTR_DIRECTORY ) > 0 ? "/" : "" )));
+                new URL(context.url, name + ((attributes & ATTR_DIRECTORY) > 0 ? "/" : "")));

         /* why was this removed before? DFS? copyTo? Am I going around in circles? */
         auth = context.auth;


-        if( context.share != null ) {
+        if (context.share != null) {
             this.tree = context.tree;
             this.dfsReferral = context.dfsReferral;
         }
         int last = name.length() - 1;
-        if( name.charAt( last ) == '/' ) {
+        if (name.charAt(last) == '/') {
-            name = name.substring( 0, last );
+            name = name.substring(0, last);
         }
-        if( context.share == null ) {
+        if (context.share == null) {
             this.unc = "\\";
-        } else if( context.unc.equals( "\\" )) {
+        } else if (context.unc.equals("\\")) {
             this.unc = '\\' + name;
         } else {
             this.unc = context.unc + '\\' + name;
         }
-    /* why? am I going around in circles?
-     *  this.type = type == TYPE_WORKGROUP ? 0 : type;
-     */
+        /* why? am I going around in circles?
+        *  this.type = type == TYPE_WORKGROUP ? 0 : type;
+        */
         this.type = type;
         this.attributes = attributes;
         this.createTime = createTime;
@@ -656,27 +654,28 @@
     }

     private SmbComBlankResponse blank_resp() {
-        if( blank_resp == null ) {
+        if (blank_resp == null) {
             blank_resp = new SmbComBlankResponse();
         }
         return blank_resp;
     }
+
     void resolveDfs(ServerMessageBlock request) throws SmbException {
         connect0();

         DfsReferral dr = dfs.resolve(
-                    tree.session.transport.tconHostName,
-                    tree.share,
-                    unc,
-                    auth);
+                tree.session.transport.tconHostName,
+                tree.share,
+                unc,
+                auth);
         if (dr != null) {
             String service = null;

             if (request != null) {
-                switch( request.command ) {
+                switch (request.command) {
                     case ServerMessageBlock.SMB_COM_TRANSACTION:
                     case ServerMessageBlock.SMB_COM_TRANSACTION2:
-                        switch( ((SmbComTransaction)request).subCommand & 0xFF ) {
+                        switch (((SmbComTransaction) request).subCommand & 0xFF) {
                             case SmbComTransaction.TRANS2_GET_DFS_REFERRAL:
                                 break;
                             default:
@@ -704,7 +703,7 @@
 /* Technically we should also try to authenticate here but that means doing the session setup and tree connect separately. For now a simple connect will at least tell us if the host is alive. That should be sufficient for 99% of the cases. We can revisit this again for 2.0.
  */
                     trans.connect();
-                    tree = trans.getSmbSession( auth ).getSmbTree( dr.share, service );
+                    tree = trans.getSmbSession(auth).getSmbTree(dr.share, service);

                     if (dr != start && dr.key != null) {
                         dr.map.put(dr.key, dr);
@@ -715,7 +714,7 @@
                     break;
                 } catch (IOException ioe) {
                     if (ioe instanceof SmbException) {
-                        se = (SmbException)ioe;
+                        se = (SmbException) ioe;
                     } else {
                         se = new SmbException(dr.server, ioe);
                     }
@@ -728,7 +727,7 @@
                 throw se;

             if (log.level >= 3)
-                log.println( dr );
+                log.println(dr);

             dfsReferral = dr;
             if (dr.pathConsumed < 0) {
@@ -744,9 +743,9 @@

             unc = dunc;
             if (request != null &&
-                        request.path != null &&
-                        request.path.endsWith("\\") &&
-                        dunc.endsWith("\\") == false) {
+                    request.path != null &&
+                    request.path.endsWith("\\") &&
+                    dunc.endsWith("\\") == false) {
                 dunc += "\\";
             }
             if (request != null) {
@@ -754,24 +753,25 @@
                 request.flags2 |= ServerMessageBlock.FLAGS2_RESOLVE_PATHS_IN_DFS;
             }
         } else if (tree.inDomainDfs &&
-                        !(request instanceof NtTransQuerySecurityDesc) &&
-                        !(request instanceof SmbComClose) &&
-                        !(request instanceof SmbComFindClose2)) {
+                !(request instanceof NtTransQuerySecurityDesc) &&
+                !(request instanceof SmbComClose) &&
+                !(request instanceof SmbComFindClose2)) {
             throw new SmbException(NtStatus.NT_STATUS_NOT_FOUND, false);
         } else {
             if (request != null)
                 request.flags2 &= ~ServerMessageBlock.FLAGS2_RESOLVE_PATHS_IN_DFS;
         }
     }
+
-    void send( ServerMessageBlock request,
+    void send(ServerMessageBlock request,
-                    ServerMessageBlock response ) throws SmbException {
+              ServerMessageBlock response) throws SmbException {
-        for( ;; ) {
+        for (; ;) {
             resolveDfs(request);
             try {
-                tree.send( request, response );
+                tree.send(request, response);
                 break;
-            } catch( DfsReferral dre ) {
+            } catch (DfsReferral dre) {
-                if( dre.resolveHashes ) {
+                if (dre.resolveHashes) {
                     throw dre;
                 }
                 request.reset();
@@ -779,45 +779,46 @@
         }
     }

-    static String queryLookup( String query, String param ) {
+    static String queryLookup(String query, String param) {
         char in[] = query.toCharArray();
         int i, ch, st, eq;

         st = eq = 0;
-        for( i = 0; i < in.length; i++) {
+        for (i = 0; i < in.length; i++) {
             ch = in[i];
-            if( ch == '&' ) {
+            if (ch == '&') {
-                if( eq > st ) {
+                if (eq > st) {
-                    String p = new String( in, st, eq - st );
+                    String p = new String(in, st, eq - st);
-                    if( p.equalsIgnoreCase( param )) {
+                    if (p.equalsIgnoreCase(param)) {
                         eq++;
-                        return new String( in, eq, i - eq );
+                        return new String(in, eq, i - eq);
                     }
                 }
                 st = i + 1;
-            } else if( ch == '=' ) {
+            } else if (ch == '=') {
                 eq = i;
             }
         }
-        if( eq > st ) {
+        if (eq > st) {
-            String p = new String( in, st, eq - st );
+            String p = new String(in, st, eq - st);
-            if( p.equalsIgnoreCase( param )) {
+            if (p.equalsIgnoreCase(param)) {
                 eq++;
-                return new String( in, eq, in.length - eq );
+                return new String(in, eq, in.length - eq);
             }
         }

         return null;
     }

-UniAddress[] addresses;
-int addressIndex;
+    UniAddress[] addresses;
+    int addressIndex;

     UniAddress getAddress() throws UnknownHostException {
         if (addressIndex == 0)
             return getFirstAddress();
         return addresses[addressIndex - 1];
     }
+
     UniAddress getFirstAddress() throws UnknownHostException {
         addressIndex = 0;

@@ -825,11 +826,11 @@
         String path = url.getPath();
         String query = url.getQuery();

-        if( query != null ) {
+        if (query != null) {
-            String server = queryLookup( query, "server" );
+            String server = queryLookup(query, "server");
-            if( server != null && server.length() > 0 ) {
+            if (server != null && server.length() > 0) {
                 addresses = new UniAddress[1];
-                addresses[0] = UniAddress.getByName( server );
+                addresses[0] = UniAddress.getByName(server);
                 return getNextAddress();
             }
         }
@@ -839,42 +840,46 @@
                 NbtAddress addr = NbtAddress.getByName(
                         NbtAddress.MASTER_BROWSER_NAME, 0x01, null);
                 addresses = new UniAddress[1];
-                addresses[0] = UniAddress.getByName( addr.getHostAddress() );
+                addresses[0] = UniAddress.getByName(addr.getHostAddress());
-            } catch( UnknownHostException uhe ) {
+            } catch (UnknownHostException uhe) {
                 NtlmPasswordAuthentication.initDefaults();
-                if( NtlmPasswordAuthentication.DEFAULT_DOMAIN.equals( "?" )) {
+                if (NtlmPasswordAuthentication.DEFAULT_DOMAIN.equals("?")) {
                     throw uhe;
                 }
-                addresses = UniAddress.getAllByName( NtlmPasswordAuthentication.DEFAULT_DOMAIN, true );
+                addresses = UniAddress.getAllByName(NtlmPasswordAuthentication.DEFAULT_DOMAIN, true);
             }
-        } else if( path.length() == 0 || path.equals( "/" )) {
+        } else if (path.length() == 0 || path.equals("/")) {
-            addresses = UniAddress.getAllByName( host, true );
+            addresses = UniAddress.getAllByName(host, true);
         } else {
             addresses = UniAddress.getAllByName(host, false);
         }

         return getNextAddress();
     }
+
     UniAddress getNextAddress() {
         UniAddress addr = null;
         if (addressIndex < addresses.length)
             addr = addresses[addressIndex++];
         return addr;
     }
+
     boolean hasNextAddress() {
         return addressIndex < addresses.length;
     }
+
     void connect0() throws SmbException {
         try {
             connect();
-        } catch( UnknownHostException uhe ) {
+        } catch (UnknownHostException uhe) {
-            throw new SmbException( "Failed to connect to server", uhe );
+            throw new SmbException("Failed to connect to server", uhe);
-        } catch( SmbException se ) {
+        } catch (SmbException se) {
             throw se;
-        } catch( IOException ioe ) {
+        } catch (IOException ioe) {
-            throw new SmbException( "Failed to connect to server", ioe );
+            throw new SmbException("Failed to connect to server", ioe);
         }
     }
+
     void doConnect() throws IOException {
         SmbTransport trans;
         UniAddress addr;
@@ -894,8 +899,8 @@
         }

         try {
-            if( log.level >= 3 )
+            if (log.level >= 3)
-                log.println( "doConnect: " + addr );
+                log.println("doConnect: " + addr);

             tree.treeConnect(null, null);
         } catch (SmbAuthException sae) {
@@ -907,7 +912,7 @@
                 tree = ssn.getSmbTree(null, null);
                 tree.treeConnect(null, null);
             } else if ((a = NtlmAuthenticator.requestNtlmPasswordAuthentication(
-                        url.toString(), sae)) != null) {
+                    url.toString(), sae)) != null) {
                 auth = a;
                 ssn = trans.getSmbSession(auth);
                 tree = ssn.getSmbTree(share, null);
@@ -923,26 +928,27 @@
             }
         }
     }
+
-/**
- * It is not necessary to call this method directly. This is the
- * <tt>URLConnection</tt> implementation of <tt>connect()</tt>.
- */
+    /**
+     * It is not necessary to call this method directly. This is the
+     * <tt>URLConnection</tt> implementation of <tt>connect()</tt>.
+     */
     public void connect() throws IOException {
         SmbTransport trans;
         SmbSession ssn;
         UniAddress addr;

-        if( isConnected() ) {
+        if (isConnected()) {
             return;
         }

         getUncPath0();
         getFirstAddress();
-        for ( ;; ) {
+        for (; ;) {
             try {
                 doConnect();
                 return;
-            } catch(SmbException se) {
+            } catch (SmbException se) {
                 if (getNextAddress() == null)
                     throw se;
                 if (log.level >= 3)
@@ -950,214 +956,221 @@
             }
         }
     }
+
     boolean isConnected() {
         return tree != null && tree.treeConnected;
     }
+
-    int open0( int flags, int access, int attrs, int options ) throws SmbException {
+    int open0(int flags, int access, int attrs, int options) throws SmbException {
         int f;

         connect0();

-        if( log.level >= 3 )
+        if (log.level >= 3)
-            log.println( "open0: " + unc );
+            log.println("open0: " + unc);

         /*
          * NT Create AndX / Open AndX Request / Response
          */

-        if( tree.session.transport.hasCapability( ServerMessageBlock.CAP_NT_SMBS )) {
+        if (tree.session.transport.hasCapability(ServerMessageBlock.CAP_NT_SMBS)) {
             SmbComNTCreateAndXResponse response = new SmbComNTCreateAndXResponse();
-SmbComNTCreateAndX request = new SmbComNTCreateAndX( unc, flags, access, shareAccess, attrs, options, null );
+            SmbComNTCreateAndX request = new SmbComNTCreateAndX(unc, flags, access, shareAccess, attrs, options, null);
-if (this instanceof SmbNamedPipe) {
-    request.flags0 |= 0x16;
-    request.desiredAccess |= 0x20000;
-    response.isExtended = true;
-}
+            if (this instanceof SmbNamedPipe) {
+                request.flags0 |= 0x16;
+                request.desiredAccess |= 0x20000;
+                response.isExtended = true;
+            }
-            send( request, response );
+            send(request, response);
             f = response.fid;
             attributes = response.extFileAttributes & ATTR_GET_MASK;
             attrExpiration = System.currentTimeMillis() + attrExpirationPeriod;
             isExists = true;
         } else {
             SmbComOpenAndXResponse response = new SmbComOpenAndXResponse();
-            send( new SmbComOpenAndX( unc, access, flags, null ), response );
+            send(new SmbComOpenAndX(unc, access, flags, null), response);
             f = response.fid;
         }

         return f;
     }
+
-    void open( int flags, int access, int attrs, int options ) throws SmbException {
+    void open(int flags, int access, int attrs, int options) throws SmbException {
-        if( isOpen() ) {
+        if (isOpen()) {
             return;
         }
-        fid = open0( flags, access, attrs, options );
+        fid = open0(flags, access, attrs, options);
         opened = true;
         tree_num = tree.tree_num;
     }
+
     boolean isOpen() {
-        boolean ans =  opened && isConnected() && tree_num == tree.tree_num;
+        boolean ans = opened && isConnected() && tree_num == tree.tree_num;
         return ans;
     }
+
-    void close( int f, long lastWriteTime ) throws SmbException {
+    void close(int f, long lastWriteTime) throws SmbException {

-        if( log.level >= 3 )
+        if (log.level >= 3)
-            log.println( "close: " + f );
+            log.println("close: " + f);

         /*
          * Close Request / Response
          */

-        send( new SmbComClose( f, lastWriteTime ), blank_resp() );
+        send(new SmbComClose(f, lastWriteTime), blank_resp());
     }
+
-    void close( long lastWriteTime ) throws SmbException {
+    void close(long lastWriteTime) throws SmbException {
-        if( isOpen() == false ) {
+        if (isOpen() == false) {
             return;
         }
-        close( fid, lastWriteTime );
+        close(fid, lastWriteTime);
         opened = false;
     }
+
     void close() throws SmbException {
-        close( 0L );
+        close(0L);
     }

-/**
- * Returns the <tt>NtlmPasswordAuthentication</tt> object used as
- * credentials with this files or pipe. This can be used to retrieve the
- * username for example:
- * <tt>
- * String username = f.getPrincipal().getName();
- * </tt>
- * The <tt>Principal</tt> object returned will never be <tt>null</tt>
- * however the username can be <tt>null</tt> indication anonymous
- * credentials were used (e.g. some IPC$ services).
- */
+    /**
+     * Returns the <tt>NtlmPasswordAuthentication</tt> object used as
+     * credentials with this files or pipe. This can be used to retrieve the
+     * username for example:
+     * <tt>
+     * String username = f.getPrincipal().getName();
+     * </tt>
+     * The <tt>Principal</tt> object returned will never be <tt>null</tt>
+     * however the username can be <tt>null</tt> indication anonymous
+     * credentials were used (e.g. some IPC$ services).
+     */

     public Principal getPrincipal() {
         return auth;
     }

-/**
- * Returns the last component of the target URL. This will
- * effectively be the name of the files or directory represented by this
- * <code>SmbFile</code> or in the case of URLs that only specify a server
- * or workgroup, the server or workgroup will be returned. The name of
- * the root URL <code>smb://</code> is also <code>smb://</code>. If this
- * <tt>SmbFile</tt> refers to a workgroup, server, share, or directory,
- * the name will include a trailing slash '/' so that composing new
- * <tt>SmbFile</tt>s will maintain the trailing slash requirement.
- *
+    /**
+     * Returns the last component of the target URL. This will
+     * effectively be the name of the files or directory represented by this
+     * <code>SmbFile</code> or in the case of URLs that only specify a server
+     * or workgroup, the server or workgroup will be returned. The name of
+     * the root URL <code>smb://</code> is also <code>smb://</code>. If this
+     * <tt>SmbFile</tt> refers to a workgroup, server, share, or directory,
+     * the name will include a trailing slash '/' so that composing new
+     * <tt>SmbFile</tt>s will maintain the trailing slash requirement.
+     *
- * @return  The last component of the URL associated with this SMB
+     * @return The last component of the URL associated with this SMB
- *          resource or <code>smb://</code> if the resource is <code>smb://</code>
+     *         resource or <code>smb://</code> if the resource is <code>smb://</code>
- *          itself.
+     *         itself.
- */
+     */

     public String getName() {
         getUncPath0();
-        if( canon.length() > 1 ) {
+        if (canon.length() > 1) {
             int i = canon.length() - 2;
-            while( canon.charAt( i ) != '/' ) {
+            while (canon.charAt(i) != '/') {
                 i--;
             }
-            return canon.substring( i + 1 );
+            return canon.substring(i + 1);
-        } else if( share != null ) {
+        } else if (share != null) {
             return share + '/';
-        } else if( url.getHost().length() > 0 ) {
+        } else if (url.getHost().length() > 0) {
             return url.getHost() + '/';
         } else {
             return "smb://";
         }
     }

-/**
- * Everything but the last component of the URL representing this SMB
- * resource is effectivly it's parent. The root URL <code>smb://</code>
- * does not have a parent. In this case <code>smb://</code> is returned.
- *
+    /**
+     * Everything but the last component of the URL representing this SMB
+     * resource is effectivly it's parent. The root URL <code>smb://</code>
+     * does not have a parent. In this case <code>smb://</code> is returned.
+     *
- * @return   The parent directory of this SMB resource or
+     * @return The parent directory of this SMB resource or
- *           <code>smb://</code> if the resource refers to the root of the URL
+     *         <code>smb://</code> if the resource refers to the root of the URL
- *           hierarchy which incedentally is also <code>smb://</code>.
+     *         hierarchy which incedentally is also <code>smb://</code>.
- */
+     */

     public String getParent() {
         String str = url.getAuthority();

-        if( str.length() > 0 ) {
+        if (str.length() > 0) {
-            StringBuffer sb = new StringBuffer( "smb://" );
+            StringBuffer sb = new StringBuffer("smb://");

-            sb.append( str );
+            sb.append(str);

             getUncPath0();
-            if( canon.length() > 1 ) {
+            if (canon.length() > 1) {
-                sb.append( canon );
+                sb.append(canon);
             } else {
-                sb.append( '/' );
+                sb.append('/');
             }

             str = sb.toString();

             int i = str.length() - 2;
-            while( str.charAt( i ) != '/' ) {
+            while (str.charAt(i) != '/') {
                 i--;
             }

-            return str.substring( 0, i + 1 );
+            return str.substring(0, i + 1);
         }

         return "smb://";
     }

-/**
- * Returns the full uncanonicalized URL of this SMB resource. An
- * <code>SmbFile</code> constructed with the result of this method will
- * result in an <code>SmbFile</code> that is equal to the original.
- *
+    /**
+     * Returns the full uncanonicalized URL of this SMB resource. An
+     * <code>SmbFile</code> constructed with the result of this method will
+     * result in an <code>SmbFile</code> that is equal to the original.
+     *
- * @return  The uncanonicalized full URL of this SMB resource.
+     * @return The uncanonicalized full URL of this SMB resource.
- */
+     */

     public String getPath() {
         return url.toString();
     }

     String getUncPath0() {
-        if( unc == null ) {
+        if (unc == null) {
             char[] in = url.getPath().toCharArray();
             char[] out = new char[in.length];
             int length = in.length, i, o, state, s;

-                              /* The canonicalization routine
-                               */
+            /* The canonicalization routine
+            */
             state = 0;
             o = 0;
-            for( i = 0; i < length; i++ ) {
+            for (i = 0; i < length; i++) {
-                switch( state ) {
+                switch (state) {
                     case 0:
-                        if( in[i] != '/' ) {
+                        if (in[i] != '/') {
                             return null;
                         }
                         out[o++] = in[i];
                         state = 1;
                         break;
                     case 1:
-                        if( in[i] == '/' ) {
+                        if (in[i] == '/') {
                             break;
-                        } else if( in[i] == '.' &&
+                        } else if (in[i] == '.' &&
-                                    (( i + 1 ) >= length || in[i + 1] == '/' )) {
+                                ((i + 1) >= length || in[i + 1] == '/')) {
                             i++;
                             break;
-                        } else if(( i + 1 ) < length &&
+                        } else if ((i + 1) < length &&
-                                    in[i] == '.' &&
-                                    in[i + 1] == '.' &&
+                                in[i] == '.' &&
+                                in[i + 1] == '.' &&
-                                    (( i + 2 ) >= length || in[i + 2] == '/' )) {
+                                ((i + 2) >= length || in[i + 2] == '/')) {
                             i += 2;
-                            if( o == 1 ) break;
+                            if (o == 1) break;
                             do {
                                 o--;
-                            } while( o > 1 && out[o - 1] != '/' );
+                            } while (o > 1 && out[o - 1] != '/');
                             break;
                         }
                         state = 2;
                     case 2:
-                        if( in[i] == '/' ) {
+                        if (in[i] == '/') {
                             state = 1;
                         }
                         out[o++] = in[i];
@@ -1165,21 +1178,21 @@
                 }
             }

-            canon = new String( out, 0, o );
+            canon = new String(out, 0, o);

-            if( o > 1 ) {
+            if (o > 1) {
                 o--;
-                i = canon.indexOf( '/', 1 );
+                i = canon.indexOf('/', 1);
-                if( i < 0 ) {
+                if (i < 0) {
-                    share = canon.substring( 1 );
+                    share = canon.substring(1);
                     unc = "\\";
-                } else if( i == o ) {
+                } else if (i == o) {
-                    share = canon.substring( 1, i );
+                    share = canon.substring(1, i);
                     unc = "\\";
                 } else {
-                    share = canon.substring( 1, i );
+                    share = canon.substring(1, i);
-                    unc = canon.substring( i, out[o] == '/' ? o : o + 1 );
+                    unc = canon.substring(i, out[o] == '/' ? o : o + 1);
-                    unc = unc.replace( '/', '\\' );
+                    unc = unc.replace('/', '\\');
                 }
             } else {
                 share = null;
@@ -1188,44 +1201,46 @@
         }
         return unc;
     }
+
-/**
- * Retuns the Windows UNC style path with backslashs intead of forward slashes.
- *
+    /**
+     * Retuns the Windows UNC style path with backslashs intead of forward slashes.
+     *
- * @return  The UNC path.
+     * @return The UNC path.
- */
+     */
     public String getUncPath() {
         getUncPath0();
-        if( share == null ) {
+        if (share == null) {
             return "\\\\" + url.getHost();
         }
-        return "\\\\" + url.getHost() + canon.replace( '/', '\\' );
+        return "\\\\" + url.getHost() + canon.replace('/', '\\');
     }
+
-/**
- * Returns the full URL of this SMB resource with '.' and '..' components
- * factored out. An <code>SmbFile</code> constructed with the result of
- * this method will result in an <code>SmbFile</code> that is equal to
- * the original.
- *
+    /**
+     * Returns the full URL of this SMB resource with '.' and '..' components
+     * factored out. An <code>SmbFile</code> constructed with the result of
+     * this method will result in an <code>SmbFile</code> that is equal to
+     * the original.
+     *
- * @return  The canonicalized URL of this SMB resource.
+     * @return The canonicalized URL of this SMB resource.
- */
+     */

     public String getCanonicalPath() {
         String str = url.getAuthority();
         getUncPath0();
-        if( str.length() > 0 ) {
+        if (str.length() > 0) {
             return "smb://" + url.getAuthority() + canon;
         }
         return "smb://";
     }

-/**
- * Retrieves the share associated with this SMB resource. In
- * the case of <code>smb://</code>, <code>smb://workgroup/</code>,
- * and <code>smb://server/</code> URLs which do not specify a share,
- * <code>null</code> will be returned.
- *
+    /**
+     * Retrieves the share associated with this SMB resource. In
+     * the case of <code>smb://</code>, <code>smb://workgroup/</code>,
+     * and <code>smb://server/</code> URLs which do not specify a share,
+     * <code>null</code> will be returned.
+     *
- * @return  The share component or <code>null</code> if there is no share
+     * @return The share component or <code>null</code> if there is no share
- */
+     */

     public String getShare() {
         return share;
@@ -1237,57 +1252,59 @@
         }
         return getServer();
     }
+
-/**
- * Retrieve the hostname of the server for this SMB resource. If this
- * <code>SmbFile</code> references a workgroup, the name of the workgroup
- * is returned. If this <code>SmbFile</code> refers to the root of this
- * SMB network hierarchy, <code>null</code> is returned.
- *
+    /**
+     * Retrieve the hostname of the server for this SMB resource. If this
+     * <code>SmbFile</code> references a workgroup, the name of the workgroup
+     * is returned. If this <code>SmbFile</code> refers to the root of this
+     * SMB network hierarchy, <code>null</code> is returned.
+     *
- * @return  The server or workgroup name or <code>null</code> if this
+     * @return The server or workgroup name or <code>null</code> if this
- *          <code>SmbFile</code> refers to the root <code>smb://</code> resource.
+     *         <code>SmbFile</code> refers to the root <code>smb://</code> resource.
- */
+     */

     public String getServer() {
         String str = url.getHost();
-        if( str.length() == 0 ) {
+        if (str.length() == 0) {
             return null;
         }
         return str;
     }

-/**
- * Returns type of of object this <tt>SmbFile</tt> represents.
+    /**
+     * Returns type of of object this <tt>SmbFile</tt> represents.
+     *
- * @return <tt>TYPE_FILESYSTEM, TYPE_WORKGROUP, TYPE_SERVER, TYPE_SHARE,
+     * @return <tt>TYPE_FILESYSTEM, TYPE_WORKGROUP, TYPE_SERVER, TYPE_SHARE,
- * TYPE_PRINTER, TYPE_NAMED_PIPE</tt>, or <tt>TYPE_COMM</tt>.
+     *         TYPE_PRINTER, TYPE_NAMED_PIPE</tt>, or <tt>TYPE_COMM</tt>.
- */
+     */
     public int getType() throws SmbException {
-        if( type == 0 ) {
+        if (type == 0) {
-            if( getUncPath0().length() > 1 ) {
+            if (getUncPath0().length() > 1) {
                 type = TYPE_FILESYSTEM;
-            } else if( share != null ) {
+            } else if (share != null) {
                 // treeConnect good enough to test service type
                 connect0();
-                if( share.equals( "IPC$" )) {
+                if (share.equals("IPC$")) {
                     type = TYPE_NAMED_PIPE;
-                } else if( tree.service.equals( "LPT1:" )) {
+                } else if (tree.service.equals("LPT1:")) {
                     type = TYPE_PRINTER;
-                } else if( tree.service.equals( "COMM" )) {
+                } else if (tree.service.equals("COMM")) {
                     type = TYPE_COMM;
                 } else {
                     type = TYPE_SHARE;
                 }
-            } else if( url.getAuthority() == null || url.getAuthority().length() == 0 ) {
+            } else if (url.getAuthority() == null || url.getAuthority().length() == 0) {
                 type = TYPE_WORKGROUP;
             } else {
                 UniAddress addr;
                 try {
                     addr = getAddress();
-                } catch( UnknownHostException uhe ) {
+                } catch (UnknownHostException uhe) {
-                    throw new SmbException( url.toString(), uhe );
+                    throw new SmbException(url.toString(), uhe);
                 }
-                if( addr.getAddress() instanceof NbtAddress ) {
+                if (addr.getAddress() instanceof NbtAddress) {
-                    int code = ((NbtAddress)addr.getAddress()).getNameType();
+                    int code = ((NbtAddress) addr.getAddress()).getNameType();
-                    if( code == 0x1d || code == 0x1b ) {
+                    if (code == 0x1d || code == 0x1b) {
                         type = TYPE_WORKGROUP;
                         return type;
                     }
@@ -1297,17 +1314,18 @@
         }
         return type;
     }
+
     boolean isWorkgroup0() throws UnknownHostException {
-        if( type == TYPE_WORKGROUP || url.getHost().length() == 0 ) {
+        if (type == TYPE_WORKGROUP || url.getHost().length() == 0) {
             type = TYPE_WORKGROUP;
             return true;
         } else {
             getUncPath0();
-            if( share == null ) {
+            if (share == null) {
                 UniAddress addr = getAddress();
-                if( addr.getAddress() instanceof NbtAddress ) {
+                if (addr.getAddress() instanceof NbtAddress) {
-                    int code = ((NbtAddress)addr.getAddress()).getNameType();
+                    int code = ((NbtAddress) addr.getAddress()).getNameType();
-                    if( code == 0x1d || code == 0x1b ) {
+                    if (code == 0x1d || code == 0x1b) {
                         type = TYPE_WORKGROUP;
                         return true;
                     }
@@ -1318,11 +1336,11 @@
         return false;
     }

-    Info queryPath( String path, int infoLevel ) throws SmbException {
+    Info queryPath(String path, int infoLevel) throws SmbException {
         connect0();

         if (log.level >= 3)
-            log.println( "queryPath: " + path );
+            log.println("queryPath: " + path);

         /* normally we'd check the negotiatedCapabilities for CAP_NT_SMBS
          * however I can't seem to get a good last modified time from
@@ -1339,15 +1357,15 @@
          * to support DFS referral _to_ Win95/98/ME.
          */

-        if( tree.session.transport.hasCapability( ServerMessageBlock.CAP_NT_SMBS )) {
+        if (tree.session.transport.hasCapability(ServerMessageBlock.CAP_NT_SMBS)) {

             /*
              * Trans2 Query Path Information Request / Response
              */

             Trans2QueryPathInformationResponse response =
-                    new Trans2QueryPathInformationResponse( infoLevel );
+                    new Trans2QueryPathInformationResponse(infoLevel);
-            send( new Trans2QueryPathInformation( path, infoLevel ), response );
+            send(new Trans2QueryPathInformation(path, infoLevel), response);

             return response.info;
         } else {
@@ -1358,29 +1376,29 @@

             SmbComQueryInformationResponse response =
                     new SmbComQueryInformationResponse(
-                    tree.session.transport.server.serverTimeZone * 1000 * 60L );
+                            tree.session.transport.server.serverTimeZone * 1000 * 60L);
-            send( new SmbComQueryInformation( path ), response );
+            send(new SmbComQueryInformation(path), response);
             return response;
         }
     }

-/**
- * Tests to see if the SMB resource exists. If the resource refers
- * only to a server, this method determines if the server exists on the
- * network and is advertising SMB services. If this resource refers to
- * a workgroup, this method determines if the workgroup name is valid on
- * the local SMB network. If this <code>SmbFile</code> refers to the root
- * <code>smb://</code> resource <code>true</code> is always returned. If
- * this <code>SmbFile</code> is a traditional files or directory, it will
- * be queried for on the specified server as expected.
- *
- * @return <code>true</code> if the resource exists or is alive or
- *         <code>false</code> otherwise
- */
+    /**
+     * Tests to see if the SMB resource exists. If the resource refers
+     * only to a server, this method determines if the server exists on the
+     * network and is advertising SMB services. If this resource refers to
+     * a workgroup, this method determines if the workgroup name is valid on
+     * the local SMB network. If this <code>SmbFile</code> refers to the root
+     * <code>smb://</code> resource <code>true</code> is always returned. If
+     * this <code>SmbFile</code> is a traditional files or directory, it will
+     * be queried for on the specified server as expected.
+     *
+     * @return <code>true</code> if the resource exists or is alive or
+     *         <code>false</code> otherwise
+     */

     public boolean exists() throws SmbException {

-        if( attrExpiration > System.currentTimeMillis() ) {
+        if (attrExpiration > System.currentTimeMillis()) {
             return isExists;
         }

@@ -1390,19 +1408,19 @@
         isExists = false;

         try {
-            if( url.getHost().length() == 0 ) {
+            if (url.getHost().length() == 0) {
-            } else if( share == null ) {
+            } else if (share == null) {
-                if( getType() == TYPE_WORKGROUP ) {
+                if (getType() == TYPE_WORKGROUP) {
-                    UniAddress.getByName( url.getHost(), true );
+                    UniAddress.getByName(url.getHost(), true);
                 } else {
-                    UniAddress.getByName( url.getHost() ).getHostName();
+                    UniAddress.getByName(url.getHost()).getHostName();
                 }
-            } else if( getUncPath0().length() == 1 ||
+            } else if (getUncPath0().length() == 1 ||
-                                        share.equalsIgnoreCase( "IPC$" )) {
+                    share.equalsIgnoreCase("IPC$")) {
                 connect0(); // treeConnect is good enough
             } else {
-                Info info = queryPath( getUncPath0(),
+                Info info = queryPath(getUncPath0(),
-                    Trans2QueryPathInformationResponse.SMB_QUERY_FILE_BASIC_INFO );
+                        Trans2QueryPathInformationResponse.SMB_QUERY_FILE_BASIC_INFO);
                 attributes = info.getAttributes();
                 createTime = info.getCreateTime();
                 lastModified = info.getLastWriteTime();
@@ -1413,8 +1431,8 @@

             isExists = true;

-        } catch( UnknownHostException uhe ) {
+        } catch (UnknownHostException uhe) {
-        } catch( SmbException se ) {
+        } catch (SmbException se) {
             switch (se.getNtStatus()) {
                 case NtStatus.NT_STATUS_NO_SUCH_FILE:
                 case NtStatus.NT_STATUS_OBJECT_NAME_INVALID:
@@ -1431,285 +1449,291 @@
         return isExists;
     }

-/**
- * Tests to see if the files this <code>SmbFile</code> represents can be
- * read. Because any files, directory, or other resource can be read if it
- * exists, this method simply calls the <code>exists</code> method.
- *
- * @return <code>true</code> if the files is read-only
- */
+    /**
+     * Tests to see if the files this <code>SmbFile</code> represents can be
+     * read. Because any files, directory, or other resource can be read if it
+     * exists, this method simply calls the <code>exists</code> method.
+     *
+     * @return <code>true</code> if the files is read-only
+     */

     public boolean canRead() throws SmbException {
-        if( getType() == TYPE_NAMED_PIPE ) { // try opening the pipe for reading?
+        if (getType() == TYPE_NAMED_PIPE) { // try opening the pipe for reading?
             return true;
         }
         return exists(); // try opening and catch sharing violation?
     }

-/**
- * Tests to see if the files this <code>SmbFile</code> represents
- * exists and is not marked read-only. By default, resources are
- * considered to be read-only and therefore for <code>smb://</code>,
- * <code>smb://workgroup/</code>, and <code>smb://server/</code> resources
- * will be read-only.
- *
+    /**
+     * Tests to see if the files this <code>SmbFile</code> represents
+     * exists and is not marked read-only. By default, resources are
+     * considered to be read-only and therefore for <code>smb://</code>,
+     * <code>smb://workgroup/</code>, and <code>smb://server/</code> resources
+     * will be read-only.
+     *
- * @return  <code>true</code> if the resource exists is not marked
+     * @return <code>true</code> if the resource exists is not marked
- *          read-only
+     *         read-only
- */
+     */

     public boolean canWrite() throws SmbException {
-        if( getType() == TYPE_NAMED_PIPE ) { // try opening the pipe for writing?
+        if (getType() == TYPE_NAMED_PIPE) { // try opening the pipe for writing?
             return true;
         }
-        return exists() && ( attributes & ATTR_READONLY ) == 0;
+        return exists() && (attributes & ATTR_READONLY) == 0;
     }

-/**
- * Tests to see if the files this <code>SmbFile</code> represents is a directory.
- *
- * @return <code>true</code> if this <code>SmbFile</code> is a directory
- */
+    /**
+     * Tests to see if the files this <code>SmbFile</code> represents is a directory.
+     *
+     * @return <code>true</code> if this <code>SmbFile</code> is a directory
+     */

     public boolean isDirectory() throws SmbException {
-        if( getUncPath0().length() == 1 ) {
+        if (getUncPath0().length() == 1) {
             return true;
         }
         if (!exists()) return false;
-        return ( attributes & ATTR_DIRECTORY ) == ATTR_DIRECTORY;
+        return (attributes & ATTR_DIRECTORY) == ATTR_DIRECTORY;
     }

-/**
- * Tests to see if the files this <code>SmbFile</code> represents is not a directory.
- *
- * @return <code>true</code> if this <code>SmbFile</code> is not a directory
- */
+    /**
+     * Tests to see if the files this <code>SmbFile</code> represents is not a directory.
+     *
+     * @return <code>true</code> if this <code>SmbFile</code> is not a directory
+     */

     public boolean isFile() throws SmbException {
-        if( getUncPath0().length() == 1 ) {
+        if (getUncPath0().length() == 1) {
             return false;
         }
         exists();
-        return ( attributes & ATTR_DIRECTORY ) == 0;
+        return (attributes & ATTR_DIRECTORY) == 0;
     }

-/**
- * Tests to see if the files this SmbFile represents is marked as
- * hidden. This method will also return true for shares with names that
- * end with '$' such as <code>IPC$</code> or <code>C$</code>.
- *
- * @return <code>true</code> if the <code>SmbFile</code> is marked as being hidden
- */
+    /**
+     * Tests to see if the files this SmbFile represents is marked as
+     * hidden. This method will also return true for shares with names that
+     * end with '$' such as <code>IPC$</code> or <code>C$</code>.
+     *
+     * @return <code>true</code> if the <code>SmbFile</code> is marked as being hidden
+     */

     public boolean isHidden() throws SmbException {
-        if( share == null ) {
+        if (share == null) {
             return false;
-        } else if( getUncPath0().length() == 1 ) {
+        } else if (getUncPath0().length() == 1) {
-            if( share.endsWith( "$" )) {
+            if (share.endsWith("$")) {
                 return true;
             }
             return false;
         }
         exists();
-        return ( attributes & ATTR_HIDDEN ) == ATTR_HIDDEN;
+        return (attributes & ATTR_HIDDEN) == ATTR_HIDDEN;
     }

-/**
- * If the path of this <code>SmbFile</code> falls within a DFS volume,
- * this method will return the referral path to which it maps. Otherwise
- * <code>null</code> is returned.
- */
+    /**
+     * If the path of this <code>SmbFile</code> falls within a DFS volume,
+     * this method will return the referral path to which it maps. Otherwise
+     * <code>null</code> is returned.
+     */

     public String getDfsPath() throws SmbException {
         resolveDfs(null);
-        if( dfsReferral == null ) {
+        if (dfsReferral == null) {
             return null;
         }
         String path = "smb:/" + dfsReferral.server + "/" + dfsReferral.share + unc;
-        path = path.replace( '\\', '/' );
+        path = path.replace('\\', '/');
         if (isDirectory()) {
             path += '/';
         }
         return path;
     }

-/**
- * Retrieve the time this <code>SmbFile</code> was created. The value
- * returned is suitable for constructing a {@link java.util.Date} object
- * (i.e. seconds since Epoch 1970). Times should be the same as those
- * reported using the properties dialog of the Windows Explorer program.
+    /**
+     * Retrieve the time this <code>SmbFile</code> was created. The value
+     * returned is suitable for constructing a {@link java.util.Date} object
+     * (i.e. seconds since Epoch 1970). Times should be the same as those
+     * reported using the properties dialog of the Windows Explorer program.
- *
+     * <p/>
- * For Win95/98/Me this is actually the last write time. It is currently
- * not possible to retrieve the create time from files on these systems.
- *
- * @return The number of milliseconds since the 00:00:00 GMT, January 1,
- *         1970 as a <code>long</code> value
- */
+     * For Win95/98/Me this is actually the last write time. It is currently
+     * not possible to retrieve the create time from files on these systems.
+     *
+     * @return The number of milliseconds since the 00:00:00 GMT, January 1,
+     *         1970 as a <code>long</code> value
+     */
     public long createTime() throws SmbException {
-        if( getUncPath0().length() > 1 ) {
+        if (getUncPath0().length() > 1) {
             exists();
             return createTime;
         }
         return 0L;
     }
+
-/**
- * Retrieve the last time the files represented by this
- * <code>SmbFile</code> was modified. The value returned is suitable for
- * constructing a {@link java.util.Date} object (i.e. seconds since Epoch
- * 1970). Times should be the same as those reported using the properties
- * dialog of the Windows Explorer program.
- *
- * @return The number of milliseconds since the 00:00:00 GMT, January 1,
- *         1970 as a <code>long</code> value
- */
+    /**
+     * Retrieve the last time the files represented by this
+     * <code>SmbFile</code> was modified. The value returned is suitable for
+     * constructing a {@link java.util.Date} object (i.e. seconds since Epoch
+     * 1970). Times should be the same as those reported using the properties
+     * dialog of the Windows Explorer program.
+     *
+     * @return The number of milliseconds since the 00:00:00 GMT, January 1,
+     *         1970 as a <code>long</code> value
+     */
     public long lastModified() throws SmbException {
-        if( getUncPath0().length() > 1 ) {
+        if (getUncPath0().length() > 1) {
             exists();
             return lastModified;
         }
         return 0L;
     }
+
-/**
- * List the contents of this SMB resource. The list returned by this
- * method will be;
+    /**
+     * List the contents of this SMB resource. The list returned by this
+     * method will be;
- *
+     * <p/>
- * <ul>
- * <li> files and directories contained within this resource if the
- * resource is a normal disk files directory,
- * <li> all available NetBIOS workgroups or domains if this resource is
- * the top level URL <code>smb://</code>,
- * <li> all servers registered as members of a NetBIOS workgroup if this
- * resource refers to a workgroup in a <code>smb://workgroup/</code> URL,
- * <li> all browseable shares of a server including printers, IPC
- * services, or disk volumes if this resource is a server URL in the form
- * <code>smb://server/</code>,
- * <li> or <code>null</code> if the resource cannot be resolved.
- * </ul>
- *
- * @return A <code>String[]</code> array of files and directories,
+     * <ul>
+     * <li> files and directories contained within this resource if the
+     * resource is a normal disk files directory,
+     * <li> all available NetBIOS workgroups or domains if this resource is
+     * the top level URL <code>smb://</code>,
+     * <li> all servers registered as members of a NetBIOS workgroup if this
+     * resource refers to a workgroup in a <code>smb://workgroup/</code> URL,
+     * <li> all browseable shares of a server including printers, IPC
+     * services, or disk volumes if this resource is a server URL in the form
+     * <code>smb://server/</code>,
+     * <li> or <code>null</code> if the resource cannot be resolved.
+     * </ul>
+     *
+     * @return A <code>String[]</code> array of files and directories,
- * workgroups, servers, or shares depending on the context of the
+     *         workgroups, servers, or shares depending on the context of the
- * resource URL
+     *         resource URL
- */
+     */
     public String[] list() throws SmbException {
-        return list( "*", ATTR_DIRECTORY | ATTR_HIDDEN | ATTR_SYSTEM, null, null );
+        return list("*", ATTR_DIRECTORY | ATTR_HIDDEN | ATTR_SYSTEM, null, null);
     }

-/**
- * List the contents of this SMB resource. The list returned will be
- * identical to the list returned by the parameterless <code>list()</code>
- * method minus filenames filtered by the specified filter.
- *
- * @param filter a filename filter to exclude filenames from the results
+    /**
+     * List the contents of this SMB resource. The list returned will be
+     * identical to the list returned by the parameterless <code>list()</code>
+     * method minus filenames filtered by the specified filter.
+     *
+     * @param filter a filename filter to exclude filenames from the results
- * @throws SmbException
- # @return An array of filenames
+     * @throws SmbException # @return An array of filenames
- */
+     */
-    public String[] list( SmbFilenameFilter filter ) throws SmbException {
+    public String[] list(SmbFilenameFilter filter) throws SmbException {
-        return list( "*", ATTR_DIRECTORY | ATTR_HIDDEN | ATTR_SYSTEM, filter, null );
+        return list("*", ATTR_DIRECTORY | ATTR_HIDDEN | ATTR_SYSTEM, filter, null);
     }

-/**
- * List the contents of this SMB resource as an array of
- * <code>SmbFile</code> objects. This method is much more efficient than
- * the regular <code>list</code> method when querying attributes of each
- * files in the result set.
+    /**
+     * List the contents of this SMB resource as an array of
+     * <code>SmbFile</code> objects. This method is much more efficient than
+     * the regular <code>list</code> method when querying attributes of each
+     * files in the result set.
- * <p>
+     * <p/>
- * The list of <code>SmbFile</code>s returned by this method will be;
+     * The list of <code>SmbFile</code>s returned by this method will be;
- *
+     * <p/>
- * <ul>
- * <li> files and directories contained within this resource if the
- * resource is a normal disk files directory,
- * <li> all available NetBIOS workgroups or domains if this resource is
- * the top level URL <code>smb://</code>,
- * <li> all servers registered as members of a NetBIOS workgroup if this
- * resource refers to a workgroup in a <code>smb://workgroup/</code> URL,
- * <li> all browseable shares of a server including printers, IPC
- * services, or disk volumes if this resource is a server URL in the form
- * <code>smb://server/</code>,
- * <li> or <code>null</code> if the resource cannot be resolved.
- * </ul>
- *
- * @return An array of <code>SmbFile</code> objects representing files
+     * <ul>
+     * <li> files and directories contained within this resource if the
+     * resource is a normal disk files directory,
+     * <li> all available NetBIOS workgroups or domains if this resource is
+     * the top level URL <code>smb://</code>,
+     * <li> all servers registered as members of a NetBIOS workgroup if this
+     * resource refers to a workgroup in a <code>smb://workgroup/</code> URL,
+     * <li> all browseable shares of a server including printers, IPC
+     * services, or disk volumes if this resource is a server URL in the form
+     * <code>smb://server/</code>,
+     * <li> or <code>null</code> if the resource cannot be resolved.
+     * </ul>
+     *
+     * @return An array of <code>SmbFile</code> objects representing files
- * and directories, workgroups, servers, or shares depending on the context
+     *         and directories, workgroups, servers, or shares depending on the context
- * of the resource URL
+     *         of the resource URL
- */
+     */
     public SmbFile[] listFiles() throws SmbException {
-        return listFiles( "*", ATTR_DIRECTORY | ATTR_HIDDEN | ATTR_SYSTEM, null, null );
+        return listFiles("*", ATTR_DIRECTORY | ATTR_HIDDEN | ATTR_SYSTEM, null, null);
     }

-/**
- * The CIFS protocol provides for DOS "wildcards" to be used as
- * a performance enhancement. The client does not have to filter
- * the names and the server does not have to return all directory
- * entries.
+    /**
+     * The CIFS protocol provides for DOS "wildcards" to be used as
+     * a performance enhancement. The client does not have to filter
+     * the names and the server does not have to return all directory
+     * entries.
- * <p>
+     * <p/>
- * The wildcard expression may consist of two special meta
- * characters in addition to the normal filename characters. The '*'
- * character matches any number of characters in part of a name. If
- * the expression begins with one or more '?'s then exactly that
- * many characters will be matched whereas if it ends with '?'s
- * it will match that many characters <i>or less</i>.
+     * The wildcard expression may consist of two special meta
+     * characters in addition to the normal filename characters. The '*'
+     * character matches any number of characters in part of a name. If
+     * the expression begins with one or more '?'s then exactly that
+     * many characters will be matched whereas if it ends with '?'s
+     * it will match that many characters <i>or less</i>.
- * <p>
+     * <p/>
- * Wildcard expressions will not filter workgroup names or server names.
+     * Wildcard expressions will not filter workgroup names or server names.
- *
+     * <p/>
- * <blockquote><pre>
- * winnt> ls c?o*
- * clock.avi                  -rw--      82944 Mon Oct 14 1996 1:38 AM
- * Cookies                    drw--          0 Fri Nov 13 1998 9:42 PM
- * 2 items in 5ms
- * </pre></blockquote>
- *
- * @param wildcard a wildcard expression
+     * <blockquote><pre>
+     * winnt> ls c?o*
+     * clock.avi                  -rw--      82944 Mon Oct 14 1996 1:38 AM
+     * Cookies                    drw--          0 Fri Nov 13 1998 9:42 PM
+     * 2 items in 5ms
+     * </pre></blockquote>
+     *
+     * @param wildcard a wildcard expression
- * @throws SmbException
- * @return An array of <code>SmbFile</code> objects representing files
+     * @return An array of <code>SmbFile</code> objects representing files
- * and directories, workgroups, servers, or shares depending on the context
+     *         and directories, workgroups, servers, or shares depending on the context
- * of the resource URL
+     *         of the resource URL
+     * @throws SmbException
- */
+     */

-    public SmbFile[] listFiles( String wildcard ) throws SmbException {
+    public SmbFile[] listFiles(String wildcard) throws SmbException {
-        return listFiles( wildcard, ATTR_DIRECTORY | ATTR_HIDDEN | ATTR_SYSTEM, null, null );
+        return listFiles(wildcard, ATTR_DIRECTORY | ATTR_HIDDEN | ATTR_SYSTEM, null, null);
     }
+
-/**
- * List the contents of this SMB resource. The list returned will be
- * identical to the list returned by the parameterless <code>listFiles()</code>
- * method minus files filtered by the specified filename filter.
- *
- * @param filter a filter to exclude files from the results
- * @return An array of <tt>SmbFile</tt> objects
- * @throws SmbException
- */
+    /**
+     * List the contents of this SMB resource. The list returned will be
+     * identical to the list returned by the parameterless <code>listFiles()</code>
+     * method minus files filtered by the specified filename filter.
+     *
+     * @param filter a filter to exclude files from the results
+     * @return An array of <tt>SmbFile</tt> objects
+     * @throws SmbException
+     */
-    public SmbFile[] listFiles( SmbFilenameFilter filter ) throws SmbException {
+    public SmbFile[] listFiles(SmbFilenameFilter filter) throws SmbException {
-        return listFiles( "*", ATTR_DIRECTORY | ATTR_HIDDEN | ATTR_SYSTEM, filter, null );
+        return listFiles("*", ATTR_DIRECTORY | ATTR_HIDDEN | ATTR_SYSTEM, filter, null);
     }
+
-/**
- * List the contents of this SMB resource. The list returned will be
- * identical to the list returned by the parameterless <code>listFiles()</code>
- * method minus filenames filtered by the specified filter.
- *
- * @param filter a files filter to exclude files from the results
- * @return An array of <tt>SmbFile</tt> objects
- */
+    /**
+     * List the contents of this SMB resource. The list returned will be
+     * identical to the list returned by the parameterless <code>listFiles()</code>
+     * method minus filenames filtered by the specified filter.
+     *
+     * @param filter a files filter to exclude files from the results
+     * @return An array of <tt>SmbFile</tt> objects
+     */
-    public SmbFile[] listFiles( SmbFileFilter filter ) throws SmbException {
+    public SmbFile[] listFiles(SmbFileFilter filter) throws SmbException {
-        return listFiles( "*", ATTR_DIRECTORY | ATTR_HIDDEN | ATTR_SYSTEM, null, filter );
+        return listFiles("*", ATTR_DIRECTORY | ATTR_HIDDEN | ATTR_SYSTEM, null, filter);
     }
+
-    String[] list( String wildcard, int searchAttributes,
+    String[] list(String wildcard, int searchAttributes,
-                SmbFilenameFilter fnf, SmbFileFilter ff ) throws SmbException {
+                  SmbFilenameFilter fnf, SmbFileFilter ff) throws SmbException {
         ArrayList list = new ArrayList();
         doEnum(list, false, wildcard, searchAttributes, fnf, ff);
-        return (String[])list.toArray(new String[list.size()]);
+        return (String[]) list.toArray(new String[list.size()]);
     }
+
-    SmbFile[] listFiles( String wildcard, int searchAttributes,
+    SmbFile[] listFiles(String wildcard, int searchAttributes,
-                SmbFilenameFilter fnf, SmbFileFilter ff ) throws SmbException {
+                        SmbFilenameFilter fnf, SmbFileFilter ff) throws SmbException {
         ArrayList list = new ArrayList();
         doEnum(list, true, wildcard, searchAttributes, fnf, ff);
-        return (SmbFile[])list.toArray(new SmbFile[list.size()]);
+        return (SmbFile[]) list.toArray(new SmbFile[list.size()]);
     }
+
     void doEnum(ArrayList list,
-                    boolean files,
-                    String wildcard,
-                    int searchAttributes,
-                    SmbFilenameFilter fnf,
-                    SmbFileFilter ff) throws SmbException {
+                boolean files,
+                String wildcard,
+                int searchAttributes,
+                SmbFilenameFilter fnf,
+                SmbFileFilter ff) throws SmbException {
         if (ff != null && ff instanceof DosFileFilter) {
-            DosFileFilter dff = (DosFileFilter)ff;
+            DosFileFilter dff = (DosFileFilter) ff;
             if (dff.wildcard != null)
                 wildcard = dff.wildcard;
             searchAttributes = dff.attributes;
@@ -1730,14 +1754,15 @@
             throw new SmbException(url.toString(), mue);
         }
     }
+
     void doShareEnum(ArrayList list,
-                boolean files,
-                String wildcard,
-                int searchAttributes,
-                SmbFilenameFilter fnf,
-                SmbFileFilter ff) throws SmbException,
-                                UnknownHostException,
-                                MalformedURLException {
+                     boolean files,
+                     String wildcard,
+                     int searchAttributes,
+                     SmbFilenameFilter fnf,
+                     SmbFileFilter ff) throws SmbException,
+            UnknownHostException,
+            MalformedURLException {
         String p = url.getPath();
         IOException last = null;
         FileEntry[] entries;
@@ -1775,7 +1800,7 @@
                 doConnect();
                 try {
                     entries = doMsrpcShareEnum();
-                } catch(IOException ioe) {
+                } catch (IOException ioe) {
                     if (log.level >= 3)
                         ioe.printStackTrace(log);
                     entries = doNetShareEnum();
@@ -1786,7 +1811,7 @@
                         map.put(e, e);
                 }
                 break;
-            } catch(IOException ioe) {
+            } catch (IOException ioe) {
                 if (log.level >= 3)
                     ioe.printStackTrace(log);
                 last = ioe;
@@ -1797,19 +1822,19 @@
         if (last != null && map.isEmpty()) {
             if (last instanceof SmbException == false)
                 throw new SmbException(url.toString(), last);
-            throw (SmbException)last;
+            throw (SmbException) last;
         }

         Iterator iter = map.keySet().iterator();
         while (iter.hasNext()) {
-            e = (FileEntry)iter.next();
+            e = (FileEntry) iter.next();
             String name = e.getName();
             if (fnf != null && fnf.accept(this, name) == false)
                 continue;
             if (name.length() > 0) {
                 // if !files we don't need to create SmbFiles here
                 SmbFile f = new SmbFile(this, name, e.getType(),
-                            ATTR_READONLY | ATTR_DIRECTORY, 0L, 0L, 0L );
+                        ATTR_READONLY | ATTR_DIRECTORY, 0L, 0L, 0L);
                 if (ff != null && ff.accept(f) == false)
                     continue;
                 if (files) {
@@ -1820,14 +1845,15 @@
             }
         }
     }
+
     FileEntry[] doDfsRootEnum() throws IOException {
         MsrpcDfsRootEnum rpc;
         DcerpcHandle handle = null;
         FileEntry[] entries;

         handle = DcerpcHandle.getHandle("ncacn_np:" +
-                    getAddress().getHostAddress() +
-                    "[\\PIPE\\netdfs]", auth);
+                getAddress().getHostAddress() +
+                "[\\PIPE\\netdfs]", auth);
         try {
             rpc = new MsrpcDfsRootEnum(getServer());
             handle.sendrecv(rpc);
@@ -1837,12 +1863,13 @@
         } finally {
             try {
                 handle.close();
-            } catch(IOException ioe) {
+            } catch (IOException ioe) {
                 if (log.level >= 4)
                     ioe.printStackTrace(log);
             }
         }
     }
+
     FileEntry[] doMsrpcShareEnum() throws IOException {
         MsrpcShareEnum rpc;
         DcerpcHandle handle;
@@ -1857,8 +1884,8 @@
          */

         handle = DcerpcHandle.getHandle("ncacn_np:" +
-                    getAddress().getHostAddress() +
-                    "[\\PIPE\\srvsvc]", auth);
+                getAddress().getHostAddress() +
+                "[\\PIPE\\srvsvc]", auth);

         try {
             handle.sendrecv(rpc);
@@ -1868,12 +1895,13 @@
         } finally {
             try {
                 handle.close();
-            } catch(IOException ioe) {
+            } catch (IOException ioe) {
                 if (log.level >= 4)
                     ioe.printStackTrace(log);
             }
         }
     }
+
     FileEntry[] doNetShareEnum() throws SmbException {
         SmbComTransaction req = new NetShareEnum();
         SmbComTransactionResponse resp = new NetShareEnumResponse();
@@ -1885,14 +1913,15 @@

         return resp.results;
     }
+
     void doNetServerEnum(ArrayList list,
-                boolean files,
-                String wildcard,
-                int searchAttributes,
-                SmbFilenameFilter fnf,
-                SmbFileFilter ff) throws SmbException,
-                                UnknownHostException,
-                                MalformedURLException {
+                         boolean files,
+                         String wildcard,
+                         int searchAttributes,
+                         SmbFilenameFilter fnf,
+                         SmbFileFilter ff) throws SmbException,
+            UnknownHostException,
+            MalformedURLException {
         int listType = url.getHost().length() == 0 ? 0 : getType();
         SmbComTransaction req;
         SmbComTransactionResponse resp;
@@ -1900,13 +1929,13 @@
         if (listType == 0) {
             connect0();
             req = new NetServerEnum2(tree.session.transport.server.oemDomainName,
-                        NetServerEnum2.SV_TYPE_DOMAIN_ENUM );
+                    NetServerEnum2.SV_TYPE_DOMAIN_ENUM);
             resp = new NetServerEnum2Response();
         } else if (listType == TYPE_WORKGROUP) {
             req = new NetServerEnum2(url.getHost(), NetServerEnum2.SV_TYPE_ALL);
             resp = new NetServerEnum2Response();
         } else {
-            throw new SmbException( "The requested list operations is invalid: " + url.toString() );
+            throw new SmbException("The requested list operations is invalid: " + url.toString());
         }

         boolean more;
@@ -1917,7 +1946,7 @@

             if (resp.status != SmbException.ERROR_SUCCESS &&
                     resp.status != SmbException.ERROR_MORE_DATA) {
-                throw new SmbException( resp.status, true );
+                throw new SmbException(resp.status, true);
             }
             more = resp.status == SmbException.ERROR_MORE_DATA;

@@ -1930,7 +1959,7 @@
                 if (name.length() > 0) {
                     // if !files we don't need to create SmbFiles here
                     SmbFile f = new SmbFile(this, name, e.getType(),
-                                ATTR_READONLY | ATTR_DIRECTORY, 0L, 0L, 0L );
+                            ATTR_READONLY | ATTR_DIRECTORY, 0L, 0L, 0L);
                     if (ff != null && ff.accept(f) == false)
                         continue;
                     if (files) {
@@ -1943,115 +1972,115 @@
             if (getType() != TYPE_WORKGROUP) {
                 break;
             }
-            req.subCommand = (byte)SmbComTransaction.NET_SERVER_ENUM3;
+            req.subCommand = (byte) SmbComTransaction.NET_SERVER_ENUM3;
-            req.reset(0, ((NetServerEnum2Response)resp).lastName);
+            req.reset(0, ((NetServerEnum2Response) resp).lastName);
             resp.reset();
-        } while(more);
+        } while (more);
     }
+
-    void doFindFirstNext( ArrayList list,
+    void doFindFirstNext(ArrayList list,
-                boolean files,
-                String wildcard,
-                int searchAttributes,
-                SmbFilenameFilter fnf,
+                         boolean files,
+                         String wildcard,
+                         int searchAttributes,
+                         SmbFilenameFilter fnf,
-                SmbFileFilter ff ) throws SmbException, UnknownHostException, MalformedURLException {
+                         SmbFileFilter ff) throws SmbException, UnknownHostException, MalformedURLException {
         SmbComTransaction req;
         Trans2FindFirst2Response resp;
         int sid;
         String path = getUncPath0();
         String p = url.getPath();

-        if( p.lastIndexOf( '/' ) != ( p.length() - 1 )) {
+        if (p.lastIndexOf('/') != (p.length() - 1)) {
-            throw new SmbException( url.toString() + " directory must end with '/'" );
+            throw new SmbException(url.toString() + " directory must end with '/'");
         }

-        req = new Trans2FindFirst2( path, wildcard, searchAttributes );
+        req = new Trans2FindFirst2(path, wildcard, searchAttributes);
         resp = new Trans2FindFirst2Response();

-        if( log.level >= 3 )
+        if (log.level >= 3)
-            log.println( "doFindFirstNext: " + req.path );
+            log.println("doFindFirstNext: " + req.path);

-        send( req, resp );
+        send(req, resp);

         sid = resp.sid;
-        req = new Trans2FindNext2( sid, resp.resumeKey, resp.lastName );
+        req = new Trans2FindNext2(sid, resp.resumeKey, resp.lastName);

         /* The only difference between first2 and next2 responses is subCommand
          * so let's recycle the response object.
          */
         resp.subCommand = SmbComTransaction.TRANS2_FIND_NEXT2;

-        for( ;; ) {
+        for (; ;) {
-            for( int i = 0; i < resp.numEntries; i++ ) {
+            for (int i = 0; i < resp.numEntries; i++) {
                 FileEntry e = resp.results[i];
                 String name = e.getName();
-                if( name.length() < 3 ) {
+                if (name.length() < 3) {
                     int h = name.hashCode();
-                    if( h == HASH_DOT || h == HASH_DOT_DOT ) {
+                    if (h == HASH_DOT || h == HASH_DOT_DOT) {
                         if (name.equals(".") || name.equals(".."))
                             continue;
                     }
                 }
-                if( fnf != null && fnf.accept( this, name ) == false ) {
+                if (fnf != null && fnf.accept(this, name) == false) {
                     continue;
                 }
-                if( name.length() > 0 ) {
+                if (name.length() > 0) {
-                    SmbFile f = new SmbFile( this, name, TYPE_FILESYSTEM,
+                    SmbFile f = new SmbFile(this, name, TYPE_FILESYSTEM,
-                            e.getAttributes(), e.createTime(), e.lastModified(), e.length() );
+                            e.getAttributes(), e.createTime(), e.lastModified(), e.length());
-                    if( ff != null && ff.accept( f ) == false ) {
+                    if (ff != null && ff.accept(f) == false) {
                         continue;
                     }
-                    if( files ) {
+                    if (files) {
-                        list.add( f );
+                        list.add(f);
                     } else {
-                        list.add( name );
+                        list.add(name);
                     }
                 }
             }

-            if( resp.isEndOfSearch || resp.numEntries == 0 ) {
+            if (resp.isEndOfSearch || resp.numEntries == 0) {
                 break;
             }

-            req.reset( resp.resumeKey, resp.lastName );
+            req.reset(resp.resumeKey, resp.lastName);
             resp.reset();
-            send( req, resp );
+            send(req, resp);
         }

         try {
-            send( new SmbComFindClose2( sid ), blank_resp() );
+            send(new SmbComFindClose2(sid), blank_resp());
         } catch (SmbException se) {
-            if( log.level >= 4 )
+            if (log.level >= 4)
-                se.printStackTrace( log );
+                se.printStackTrace(log);
         }
     }

-/**
- * Changes the name of the files this <code>SmbFile</code> represents to the name
- * designated by the <code>SmbFile</code> argument.
- * <p/>
- * <i>Remember: <code>SmbFile</code>s are immutible and therefore
- * the path associated with this <code>SmbFile</code> object will not
- * change). To access the renamed files it is necessary to construct a
- * new <tt>SmbFile</tt></i>.
- *
+    /**
+     * Changes the name of the files this <code>SmbFile</code> represents to the name
+     * designated by the <code>SmbFile</code> argument.
+     * <p/>
+     * <i>Remember: <code>SmbFile</code>s are immutible and therefore
+     * the path associated with this <code>SmbFile</code> object will not
+     * change). To access the renamed files it is necessary to construct a
+     * new <tt>SmbFile</tt></i>.
+     *
- * @param  dest  An <code>SmbFile</code> that represents the new pathname
+     * @param dest An <code>SmbFile</code> that represents the new pathname
- * @throws NullPointerException
- *         If the <code>dest</code> argument is <code>null</code>
+     * @throws NullPointerException If the <code>dest</code> argument is <code>null</code>
- */
+     */
-    public void renameTo( SmbFile dest ) throws SmbException {
+    public void renameTo(SmbFile dest) throws SmbException {
-        if( getUncPath0().length() == 1 || dest.getUncPath0().length() == 1 ) {
+        if (getUncPath0().length() == 1 || dest.getUncPath0().length() == 1) {
-            throw new SmbException( "Invalid operation for workgroups, servers, or shares" );
+            throw new SmbException("Invalid operation for workgroups, servers, or shares");
         }

         resolveDfs(null);
         dest.resolveDfs(null);

         if (!tree.equals(dest.tree)) {
-            throw new SmbException( "Invalid operation for workgroups, servers, or shares" );
+            throw new SmbException("Invalid operation for workgroups, servers, or shares");
         }

-        if( log.level >= 3 )
+        if (log.level >= 3)
-            log.println( "renameTo: " + unc + " -> " + dest.unc );
+            log.println("renameTo: " + unc + " -> " + dest.unc);

         attrExpiration = sizeExpiration = 0;
         dest.attrExpiration = 0;
@@ -2060,7 +2089,7 @@
          * Rename Request / Response
          */

-        send( new SmbComRename( unc, dest.unc ), blank_resp() );
+        send(new SmbComRename(unc, dest.unc), blank_resp());
     }

     class WriterThread extends Thread {
@@ -2076,9 +2105,9 @@
         ServerMessageBlock resp;

         WriterThread() throws SmbException {
-            super( "JCIFS-WriterThread" );
+            super("JCIFS-WriterThread");
-            useNTSmbs = tree.session.transport.hasCapability( ServerMessageBlock.CAP_NT_SMBS );
+            useNTSmbs = tree.session.transport.hasCapability(ServerMessageBlock.CAP_NT_SMBS);
-            if( useNTSmbs ) {
+            if (useNTSmbs) {
                 reqx = new SmbComWriteAndX();
                 resp = new SmbComWriteAndXResponse();
             } else {
@@ -2088,7 +2117,7 @@
             ready = false;
         }

-        synchronized void write( byte[] b, int n, SmbFile dest, long off ) {
+        synchronized void write(byte[] b, int n, SmbFile dest, long off) {
             this.b = b;
             this.n = n;
             this.dest = dest;
@@ -2098,46 +2127,47 @@
         }

         public void run() {
-            synchronized( this ) {
+            synchronized (this) {
                 try {
-                    for( ;; ) {
+                    for (; ;) {
                         notify();
                         ready = true;
-                        while( ready ) {
+                        while (ready) {
                             wait();
                         }
-                        if( n == -1 ) {
+                        if (n == -1) {
                             return;
                         }
-                        if( useNTSmbs ) {
+                        if (useNTSmbs) {
-                            reqx.setParam( dest.fid, off, n, b, 0, n );
+                            reqx.setParam(dest.fid, off, n, b, 0, n);
-                            dest.send( reqx, resp );
+                            dest.send(reqx, resp);
                         } else {
-                            req.setParam( dest.fid, off, n, b, 0, n );
+                            req.setParam(dest.fid, off, n, b, 0, n);
-                            dest.send( req, resp );
+                            dest.send(req, resp);
                         }
                     }
-                } catch( SmbException e ) {
+                } catch (SmbException e) {
                     this.e = e;
-                } catch( Exception x ) {
+                } catch (Exception x) {
-                    this.e = new SmbException( "WriterThread", x );
+                    this.e = new SmbException("WriterThread", x);
                 }
                 notify();
             }
         }
     }
+
-    void copyTo0( SmbFile dest, byte[][] b, int bsize, WriterThread w,
+    void copyTo0(SmbFile dest, byte[][] b, int bsize, WriterThread w,
-            SmbComReadAndX req, SmbComReadAndXResponse resp ) throws SmbException {
+                 SmbComReadAndX req, SmbComReadAndXResponse resp) throws SmbException {
         int i;

-        if( attrExpiration < System.currentTimeMillis() ) {
+        if (attrExpiration < System.currentTimeMillis()) {
             attributes = ATTR_READONLY | ATTR_DIRECTORY;
             createTime = 0L;
             lastModified = 0L;
             isExists = false;

-            Info info = queryPath( getUncPath0(),
+            Info info = queryPath(getUncPath0(),
-                    Trans2QueryPathInformationResponse.SMB_QUERY_FILE_BASIC_INFO );
+                    Trans2QueryPathInformationResponse.SMB_QUERY_FILE_BASIC_INFO);
             attributes = info.getAttributes();
             createTime = info.getCreateTime();
             lastModified = info.getLastWriteTime();
@@ -2149,57 +2179,57 @@
             attrExpiration = System.currentTimeMillis() + attrExpirationPeriod;
         }

-        if( isDirectory() ) {
+        if (isDirectory()) {
             SmbFile[] files;
             SmbFile ndest;

             String path = dest.getUncPath0();
-            if( path.length() > 1 ) {
+            if (path.length() > 1) {
                 try {
                     dest.mkdir();
-                    dest.setPathInformation( attributes, createTime, lastModified );
+                    dest.setPathInformation(attributes, createTime, lastModified);
-                } catch( SmbException se ) {
+                } catch (SmbException se) {
-                    if( se.getNtStatus() != NtStatus.NT_STATUS_ACCESS_DENIED &&
+                    if (se.getNtStatus() != NtStatus.NT_STATUS_ACCESS_DENIED &&
-                            se.getNtStatus() != NtStatus.NT_STATUS_OBJECT_NAME_COLLISION ) {
+                            se.getNtStatus() != NtStatus.NT_STATUS_OBJECT_NAME_COLLISION) {
                         throw se;
                     }
                 }
             }

-            files = listFiles( "*", ATTR_DIRECTORY | ATTR_HIDDEN | ATTR_SYSTEM, null, null );
+            files = listFiles("*", ATTR_DIRECTORY | ATTR_HIDDEN | ATTR_SYSTEM, null, null);
             try {
-                for( i = 0; i < files.length; i++ ) {
+                for (i = 0; i < files.length; i++) {
-                    ndest = new SmbFile( dest,
+                    ndest = new SmbFile(dest,
-                                    files[i].getName(),
-                                    files[i].type,
-                                    files[i].attributes,
-                                    files[i].createTime,
-                                    files[i].lastModified,
+                            files[i].getName(),
+                            files[i].type,
+                            files[i].attributes,
+                            files[i].createTime,
+                            files[i].lastModified,
-                                    files[i].size );
+                            files[i].size);
-                    files[i].copyTo0( ndest, b, bsize, w, req, resp );
+                    files[i].copyTo0(ndest, b, bsize, w, req, resp);
                 }
-            } catch( UnknownHostException uhe ) {
+            } catch (UnknownHostException uhe) {
-                throw new SmbException( url.toString(), uhe );
+                throw new SmbException(url.toString(), uhe);
-            } catch( MalformedURLException mue ) {
+            } catch (MalformedURLException mue) {
-                throw new SmbException( url.toString(), mue );
+                throw new SmbException(url.toString(), mue);
             }
         } else {
             long off;

             try {
-                open( SmbFile.O_RDONLY, 0, ATTR_NORMAL, 0 );
+                open(SmbFile.O_RDONLY, 0, ATTR_NORMAL, 0);
                 try {
-                    dest.open( SmbFile.O_CREAT | SmbFile.O_WRONLY | SmbFile.O_TRUNC,
+                    dest.open(SmbFile.O_CREAT | SmbFile.O_WRONLY | SmbFile.O_TRUNC,
                             FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES,
-                            attributes, 0 );
+                            attributes, 0);
-                } catch( SmbAuthException sae ) {
+                } catch (SmbAuthException sae) {
-                    if(( dest.attributes & ATTR_READONLY ) != 0 ) {
+                    if ((dest.attributes & ATTR_READONLY) != 0) {
-                                                /* Remove READONLY and try again
-                                                 */
+                        /* Remove READONLY and try again
+                        */
-                        dest.setPathInformation( dest.attributes & ~ATTR_READONLY, 0L, 0L );
+                        dest.setPathInformation(dest.attributes & ~ATTR_READONLY, 0L, 0L);
-                        dest.open( SmbFile.O_CREAT | SmbFile.O_WRONLY | SmbFile.O_TRUNC,
+                        dest.open(SmbFile.O_CREAT | SmbFile.O_WRONLY | SmbFile.O_TRUNC,
                                 FILE_WRITE_DATA | FILE_WRITE_ATTRIBUTES,
-                                attributes, 0 );
+                                attributes, 0);
                     } else {
                         throw sae;
                     }
@@ -2207,64 +2237,65 @@

                 i = 0;
                 off = 0L;
-                for( ;; ) {
+                for (; ;) {
-                    req.setParam( fid, off, bsize );
+                    req.setParam(fid, off, bsize);
-                    resp.setParam( b[i], 0 );
+                    resp.setParam(b[i], 0);
-                    send( req, resp );
+                    send(req, resp);

-                    synchronized( w ) {
+                    synchronized (w) {
-                        if( w.e != null ) {
+                        if (w.e != null) {
                             throw w.e;
                         }
-                        while( !w.ready ) {
+                        while (!w.ready) {
                             try {
                                 w.wait();
-                            } catch( InterruptedException ie ) {
+                            } catch (InterruptedException ie) {
-                                throw new SmbException( dest.url.toString(), ie );
+                                throw new SmbException(dest.url.toString(), ie);
                             }
                         }
-                        if( w.e != null ) {
+                        if (w.e != null) {
                             throw w.e;
                         }
-                        if( resp.dataLength <= 0 ) {
+                        if (resp.dataLength <= 0) {
                             break;
                         }
-                        w.write( b[i], resp.dataLength, dest, off );
+                        w.write(b[i], resp.dataLength, dest, off);
                     }

                     i = i == 1 ? 0 : 1;
                     off += resp.dataLength;
                 }

-                dest.send( new Trans2SetFileInformation(
+                dest.send(new Trans2SetFileInformation(
-                        dest.fid, attributes, createTime, lastModified ),
+                        dest.fid, attributes, createTime, lastModified),
-                        new Trans2SetFileInformationResponse() );
+                        new Trans2SetFileInformationResponse());
-                dest.close( 0L );
+                dest.close(0L);
-            } catch( Exception ex ) {
+            } catch (Exception ex) {
-                if( log.level > 1 )
+                if (log.level > 1)
-                    ex.printStackTrace( log );
+                    ex.printStackTrace(log);
             } finally {
                 close();
             }
         }
     }
+
-/**
- * This method will copy the files or directory represented by this
- * <tt>SmbFile</tt> and it's sub-contents to the location specified by the
- * <tt>dest</tt> parameter. This files and the destination files do not
- * need to be on the same host. This operation does not copy extended
- * files attibutes such as ACLs but it does copy regular attributes as
- * well as create and last write times. This method is almost twice as
- * efficient as manually copying as it employs an additional write
- * thread to read and write data concurrently.
- * <p/>
- * It is not possible (nor meaningful) to copy entire workgroups or
- * servers.
- *
- * @param dest the destination files or directory
- * @throws SmbException
- */
+    /**
+     * This method will copy the files or directory represented by this
+     * <tt>SmbFile</tt> and it's sub-contents to the location specified by the
+     * <tt>dest</tt> parameter. This files and the destination files do not
+     * need to be on the same host. This operation does not copy extended
+     * files attibutes such as ACLs but it does copy regular attributes as
+     * well as create and last write times. This method is almost twice as
+     * efficient as manually copying as it employs an additional write
+     * thread to read and write data concurrently.
+     * <p/>
+     * It is not possible (nor meaningful) to copy entire workgroups or
+     * servers.
+     *
+     * @param dest the destination files or directory
+     * @throws SmbException
+     */
-    public void copyTo( SmbFile dest ) throws SmbException {
+    public void copyTo(SmbFile dest) throws SmbException {
         SmbComReadAndX req;
         SmbComReadAndXResponse resp;
         WriterThread w;
@@ -2273,8 +2304,8 @@

         /* Should be able to copy an entire share actually
          */
-        if( share == null || dest.share == null) {
+        if (share == null || dest.share == null) {
-            throw new SmbException( "Invalid operation for workgroups or servers" );
+            throw new SmbException("Invalid operation for workgroups or servers");
         }

         req = new SmbComReadAndX();
@@ -2283,31 +2314,31 @@
         connect0();
         dest.connect0();

-                /* At this point the maxBufferSize values are from the server
-                 * exporting the volumes, not the one that we will actually
-                 * end up performing IO with. If the server hosting the
-                 * actual files has a smaller maxBufSize this could be
-                 * incorrect. To handle this properly it is necessary
-                 * to redirect the tree to the target server first before
-                 * establishing buffer size. These exists() calls facilitate
-                 * that.
-                 */
+        /* At this point the maxBufferSize values are from the server
+        * exporting the volumes, not the one that we will actually
+        * end up performing IO with. If the server hosting the
+        * actual files has a smaller maxBufSize this could be
+        * incorrect. To handle this properly it is necessary
+        * to redirect the tree to the target server first before
+        * establishing buffer size. These exists() calls facilitate
+        * that.
+        */
         resolveDfs(null);

         /* It is invalid for the source path to be a child of the destination
          * path or visa versa.
          */
         try {
-            if (getAddress().equals( dest.getAddress() ) &&
+            if (getAddress().equals(dest.getAddress()) &&
-                        canon.regionMatches( true, 0, dest.canon, 0,
+                    canon.regionMatches(true, 0, dest.canon, 0,
-                                Math.min( canon.length(), dest.canon.length() ))) {
+                            Math.min(canon.length(), dest.canon.length()))) {
-                throw new SmbException( "Source and destination paths overlap." );
+                throw new SmbException("Source and destination paths overlap.");
             }
         } catch (UnknownHostException uhe) {
         }

         w = new WriterThread();
-        w.setDaemon( true );
+        w.setDaemon(true);
         w.start();

         /* Downgrade one transport to the lower of the negotiated buffer sizes
@@ -2317,49 +2348,50 @@
         SmbTransport t1 = tree.session.transport;
         SmbTransport t2 = dest.tree.session.transport;

-        if( t1.snd_buf_size < t2.snd_buf_size ) {
+        if (t1.snd_buf_size < t2.snd_buf_size) {
             t2.snd_buf_size = t1.snd_buf_size;
         } else {
             t1.snd_buf_size = t2.snd_buf_size;
         }

-        bsize = Math.min( t1.rcv_buf_size - 70, t1.snd_buf_size - 70 );
+        bsize = Math.min(t1.rcv_buf_size - 70, t1.snd_buf_size - 70);
         b = new byte[2][bsize];

         try {
-            copyTo0( dest, b, bsize, w, req, resp );
+            copyTo0(dest, b, bsize, w, req, resp);
         } finally {
-            w.write( null, -1, null, 0 );
+            w.write(null, -1, null, 0);
         }
     }

-/**
- * This method will delete the files or directory specified by this
- * <code>SmbFile</code>. If the target is a directory, the contents of
- * the directory will be deleted as well. If a files within the directory or
- * it's sub-directories is marked read-only, the read-only status will
- * be removed and the files will be deleted.
- *
- * @throws SmbException
- */
+    /**
+     * This method will delete the files or directory specified by this
+     * <code>SmbFile</code>. If the target is a directory, the contents of
+     * the directory will be deleted as well. If a files within the directory or
+     * it's sub-directories is marked read-only, the read-only status will
+     * be removed and the files will be deleted.
+     *
+     * @throws SmbException
+     */
     public void delete() throws SmbException {
         exists();
         getUncPath0();
-        delete( unc );
+        delete(unc);
     }
+
-    void delete( String fileName ) throws SmbException {
+    void delete(String fileName) throws SmbException {
-        if( getUncPath0().length() == 1 ) {
+        if (getUncPath0().length() == 1) {
-            throw new SmbException( "Invalid operation for workgroups, servers, or shares" );
+            throw new SmbException("Invalid operation for workgroups, servers, or shares");
         }

-        if( System.currentTimeMillis() > attrExpiration ) {
+        if (System.currentTimeMillis() > attrExpiration) {
             attributes = ATTR_READONLY | ATTR_DIRECTORY;
             createTime = 0L;
             lastModified = 0L;
             isExists = false;

-            Info info = queryPath( getUncPath0(),
+            Info info = queryPath(getUncPath0(),
-                    Trans2QueryPathInformationResponse.SMB_QUERY_FILE_BASIC_INFO );
+                    Trans2QueryPathInformationResponse.SMB_QUERY_FILE_BASIC_INFO);
             attributes = info.getAttributes();
             createTime = info.getCreateTime();
             lastModified = info.getLastWriteTime();
@@ -2368,7 +2400,7 @@
             isExists = true;
         }

-        if(( attributes & ATTR_READONLY ) != 0 ) {
+        if ((attributes & ATTR_READONLY) != 0) {
             setReadWrite();
         }

@@ -2376,64 +2408,64 @@
          * Delete or Delete Directory Request / Response
          */

-        if( log.level >= 3 )
+        if (log.level >= 3)
-            log.println( "delete: " + fileName );
+            log.println("delete: " + fileName);

-        if(( attributes & ATTR_DIRECTORY ) != 0 ) {
+        if ((attributes & ATTR_DIRECTORY) != 0) {

             /* Recursively delete directory contents
              */

             try {
-                SmbFile[] l = listFiles( "*", ATTR_DIRECTORY | ATTR_HIDDEN | ATTR_SYSTEM, null, null );
+                SmbFile[] l = listFiles("*", ATTR_DIRECTORY | ATTR_HIDDEN | ATTR_SYSTEM, null, null);
-                for( int i = 0; i < l.length; i++ ) {
+                for (int i = 0; i < l.length; i++) {
                     l[i].delete();
                 }
-            } catch( SmbException se ) {
+            } catch (SmbException se) {
                 /* Oracle FilesOnline version 9.0.4 doesn't send '.' and '..' so
                  * listFiles may generate undesireable "cannot find
                  * the files specified".
                  */
-                if( se.getNtStatus() != SmbException.NT_STATUS_NO_SUCH_FILE ) {
+                if (se.getNtStatus() != SmbException.NT_STATUS_NO_SUCH_FILE) {
                     throw se;
                 }
             }

-            send( new SmbComDeleteDirectory( fileName ), blank_resp() );
+            send(new SmbComDeleteDirectory(fileName), blank_resp());
         } else {
-            send( new SmbComDelete( fileName ), blank_resp() );
+            send(new SmbComDelete(fileName), blank_resp());
         }

         attrExpiration = sizeExpiration = 0;
     }

-/**
- * Returns the length of this <tt>SmbFile</tt> in bytes. If this object
- * is a <tt>TYPE_SHARE</tt> the total capacity of the disk shared in
- * bytes is returned. If this object is a directory or a type other than
- * <tt>TYPE_SHARE</tt>, 0L is returned.
- *
- * @return The length of the files in bytes or 0 if this
+    /**
+     * Returns the length of this <tt>SmbFile</tt> in bytes. If this object
+     * is a <tt>TYPE_SHARE</tt> the total capacity of the disk shared in
+     * bytes is returned. If this object is a directory or a type other than
+     * <tt>TYPE_SHARE</tt>, 0L is returned.
+     *
+     * @return The length of the files in bytes or 0 if this
- * <code>SmbFile</code> is not a files.
+     *         <code>SmbFile</code> is not a files.
- * @throws SmbException
- */
+     * @throws SmbException
+     */

     public long length() throws SmbException {
-        if( sizeExpiration > System.currentTimeMillis() ) {
+        if (sizeExpiration > System.currentTimeMillis()) {
             return size;
         }

-        if( getType() == TYPE_SHARE ) {
+        if (getType() == TYPE_SHARE) {
             Trans2QueryFSInformationResponse response;
             int level = Trans2QueryFSInformationResponse.SMB_INFO_ALLOCATION;

-            response = new Trans2QueryFSInformationResponse( level );
+            response = new Trans2QueryFSInformationResponse(level);
-            send( new Trans2QueryFSInformation( level ), response );
+            send(new Trans2QueryFSInformation(level), response);

             size = response.info.getCapacity();
-        } else if( getUncPath0().length() > 1 && type != TYPE_NAMED_PIPE ) {
+        } else if (getUncPath0().length() > 1 && type != TYPE_NAMED_PIPE) {
-            Info info = queryPath( getUncPath0(),
+            Info info = queryPath(getUncPath0(),
-                    Trans2QueryPathInformationResponse.SMB_QUERY_FILE_STANDARD_INFO );
+                    Trans2QueryPathInformationResponse.SMB_QUERY_FILE_STANDARD_INFO);
             size = info.getSize();
         } else {
             size = 0L;
@@ -2442,21 +2474,21 @@
         return size;
     }

-/**
- * This method returns the free disk space in bytes of the drive this share
- * represents or the drive on which the directory or files resides. Objects
- * other than <tt>TYPE_SHARE</tt> or <tt>TYPE_FILESYSTEM</tt> will result
- * in 0L being returned.
- *
- * @return the free disk space in bytes of the drive on which this files or
+    /**
+     * This method returns the free disk space in bytes of the drive this share
+     * represents or the drive on which the directory or files resides. Objects
+     * other than <tt>TYPE_SHARE</tt> or <tt>TYPE_FILESYSTEM</tt> will result
+     * in 0L being returned.
+     *
+     * @return the free disk space in bytes of the drive on which this files or
- * directory resides
+     *         directory resides
- */
+     */
     public long getDiskFreeSpace() throws SmbException {
-        if( getType() == TYPE_SHARE || type == TYPE_FILESYSTEM ) {
+        if (getType() == TYPE_SHARE || type == TYPE_FILESYSTEM) {
             int level = Trans2QueryFSInformationResponse.SMB_FS_FULL_SIZE_INFORMATION;
             try {
                 return queryFSInformation(level);
-            } catch( SmbException ex ) {
+            } catch (SmbException ex) {
                 switch (ex.getNtStatus()) {
                     case NtStatus.NT_STATUS_INVALID_INFO_CLASS:
                     case NtStatus.NT_STATUS_UNSUCCESSFUL: // NetApp Filer
@@ -2470,13 +2502,13 @@
         return 0L;
     }

-    private long queryFSInformation( int level ) throws SmbException {
+    private long queryFSInformation(int level) throws SmbException {
         Trans2QueryFSInformationResponse response;

-        response = new Trans2QueryFSInformationResponse( level );
+        response = new Trans2QueryFSInformationResponse(level);
-        send( new Trans2QueryFSInformation( level ), response );
+        send(new Trans2QueryFSInformation(level), response);

-        if( type == TYPE_SHARE ) {
+        if (type == TYPE_SHARE) {
             size = response.info.getCapacity();
             sizeExpiration = System.currentTimeMillis() + attrExpirationPeriod;
         }
@@ -2484,203 +2516,205 @@
         return response.info.getFree();
     }

-/**
- * Creates a directory with the path specified by this
- * <code>SmbFile</code>. For this method to be successful, the target
- * must not already exist. This method will fail when
- * used with <code>smb://</code>, <code>smb://workgroup/</code>,
- * <code>smb://server/</code>, or <code>smb://server/share/</code> URLs
- * because workgroups, servers, and shares cannot be dynamically created
- * (although in the future it may be possible to create shares).
- *
- * @throws SmbException
- */
+    /**
+     * Creates a directory with the path specified by this
+     * <code>SmbFile</code>. For this method to be successful, the target
+     * must not already exist. This method will fail when
+     * used with <code>smb://</code>, <code>smb://workgroup/</code>,
+     * <code>smb://server/</code>, or <code>smb://server/share/</code> URLs
+     * because workgroups, servers, and shares cannot be dynamically created
+     * (although in the future it may be possible to create shares).
+     *
+     * @throws SmbException
+     */
     public void mkdir() throws SmbException {
         String path = getUncPath0();

-        if( path.length() == 1 ) {
+        if (path.length() == 1) {
-            throw new SmbException( "Invalid operation for workgroups, servers, or shares" );
+            throw new SmbException("Invalid operation for workgroups, servers, or shares");
         }

         /*
          * Create Directory Request / Response
          */

-        if( log.level >= 3 )
+        if (log.level >= 3)
-            log.println( "mkdir: " + path );
+            log.println("mkdir: " + path);

-        send( new SmbComCreateDirectory( path ), blank_resp() );
+        send(new SmbComCreateDirectory(path), blank_resp());

         attrExpiration = sizeExpiration = 0;
     }

-/**
- * Creates a directory with the path specified by this <tt>SmbFile</tt>
- * and any parent directories that do not exist. This method will fail
- * when used with <code>smb://</code>, <code>smb://workgroup/</code>,
- * <code>smb://server/</code>, or <code>smb://server/share/</code> URLs
- * because workgroups, servers, and shares cannot be dynamically created
- * (although in the future it may be possible to create shares).
- *
- * @throws SmbException
- */
+    /**
+     * Creates a directory with the path specified by this <tt>SmbFile</tt>
+     * and any parent directories that do not exist. This method will fail
+     * when used with <code>smb://</code>, <code>smb://workgroup/</code>,
+     * <code>smb://server/</code>, or <code>smb://server/share/</code> URLs
+     * because workgroups, servers, and shares cannot be dynamically created
+     * (although in the future it may be possible to create shares).
+     *
+     * @throws SmbException
+     */
     public void mkdirs() throws SmbException {
         SmbFile parent;

         try {
-            parent = new SmbFile( getParent(), auth );
+            parent = new SmbFile(getParent(), auth);
-        } catch( IOException ioe ) {
+        } catch (IOException ioe) {
             return;
         }
-        if( parent.exists() == false ) {
+        if (parent.exists() == false) {
             parent.mkdirs();
         }
         mkdir();
     }

-/**
- * Create a new files but fail if it already exists. The check for
- * existance of the files and it's creation are an atomic operation with
- * respect to other filesystem activities.
- */
+    /**
+     * Create a new files but fail if it already exists. The check for
+     * existance of the files and it's creation are an atomic operation with
+     * respect to other filesystem activities.
+     */
     public void createNewFile() throws SmbException {
-        if( getUncPath0().length() == 1 ) {
+        if (getUncPath0().length() == 1) {
-            throw new SmbException( "Invalid operation for workgroups, servers, or shares" );
+            throw new SmbException("Invalid operation for workgroups, servers, or shares");
         }
-        close( open0( O_RDWR | O_CREAT | O_EXCL, 0, ATTR_NORMAL, 0 ), 0L );
+        close(open0(O_RDWR | O_CREAT | O_EXCL, 0, ATTR_NORMAL, 0), 0L);
     }

-    void setPathInformation( int attrs, long ctime, long mtime ) throws SmbException {
+    void setPathInformation(int attrs, long ctime, long mtime) throws SmbException {
         int f, dir;

         exists();
         dir = attributes & ATTR_DIRECTORY;

-        f = open0( O_RDONLY, FILE_WRITE_ATTRIBUTES,
+        f = open0(O_RDONLY, FILE_WRITE_ATTRIBUTES,
-                dir, dir != 0 ? 0x0001 : 0x0040 );
+                dir, dir != 0 ? 0x0001 : 0x0040);
-        send( new Trans2SetFileInformation( f, attrs | dir, ctime, mtime ),
+        send(new Trans2SetFileInformation(f, attrs | dir, ctime, mtime),
-                new Trans2SetFileInformationResponse() );
+                new Trans2SetFileInformationResponse());
-        close( f, 0L );
+        close(f, 0L);

         attrExpiration = 0;
     }

-/**
- * Set the create time of the files. The time is specified as milliseconds
- * from Jan 1, 1970 which is the same as that which is returned by the
- * <tt>createTime()</tt> method.
- * <p/>
- * This method does not apply to workgroups, servers, or shares.
- *
- * @param time the create time as milliseconds since Jan 1, 1970
- */
+    /**
+     * Set the create time of the files. The time is specified as milliseconds
+     * from Jan 1, 1970 which is the same as that which is returned by the
+     * <tt>createTime()</tt> method.
+     * <p/>
+     * This method does not apply to workgroups, servers, or shares.
+     *
+     * @param time the create time as milliseconds since Jan 1, 1970
+     */
-    public void setCreateTime( long time ) throws SmbException {
+    public void setCreateTime(long time) throws SmbException {
-        if( getUncPath0().length() == 1 ) {
+        if (getUncPath0().length() == 1) {
-            throw new SmbException( "Invalid operation for workgroups, servers, or shares" );
+            throw new SmbException("Invalid operation for workgroups, servers, or shares");
         }

-        setPathInformation( 0, time, 0L );
+        setPathInformation(0, time, 0L);
     }
+
-/**
- * Set the last modified time of the files. The time is specified as milliseconds
- * from Jan 1, 1970 which is the same as that which is returned by the
- * <tt>lastModified()</tt>, <tt>getLastModified()</tt>, and <tt>getDate()</tt> methods.
- * <p/>
- * This method does not apply to workgroups, servers, or shares.
- *
- * @param time the last modified time as milliseconds since Jan 1, 1970
- */
+    /**
+     * Set the last modified time of the files. The time is specified as milliseconds
+     * from Jan 1, 1970 which is the same as that which is returned by the
+     * <tt>lastModified()</tt>, <tt>getLastModified()</tt>, and <tt>getDate()</tt> methods.
+     * <p/>
+     * This method does not apply to workgroups, servers, or shares.
+     *
+     * @param time the last modified time as milliseconds since Jan 1, 1970
+     */
-    public void setLastModified( long time ) throws SmbException {
+    public void setLastModified(long time) throws SmbException {
-        if( getUncPath0().length() == 1 ) {
+        if (getUncPath0().length() == 1) {
-            throw new SmbException( "Invalid operation for workgroups, servers, or shares" );
+            throw new SmbException("Invalid operation for workgroups, servers, or shares");
         }

-        setPathInformation( 0, 0L, time );
+        setPathInformation(0, 0L, time);
     }

-/**
- * Return the attributes of this files. Attributes are represented as a
- * bitset that must be masked with <tt>ATTR_*</tt> constants to determine
- * if they are set or unset. The value returned is suitable for use with
- * the <tt>setAttributes()</tt> method.
- *
- * @return the <tt>ATTR_*</tt> attributes associated with this files
- * @throws SmbException
- */
+    /**
+     * Return the attributes of this files. Attributes are represented as a
+     * bitset that must be masked with <tt>ATTR_*</tt> constants to determine
+     * if they are set or unset. The value returned is suitable for use with
+     * the <tt>setAttributes()</tt> method.
+     *
+     * @return the <tt>ATTR_*</tt> attributes associated with this files
+     * @throws SmbException
+     */
     public int getAttributes() throws SmbException {
-        if( getUncPath0().length() == 1 ) {
+        if (getUncPath0().length() == 1) {
             return 0;
         }
         exists();
         return attributes & ATTR_GET_MASK;
     }

-/**
- * Set the attributes of this files. Attributes are composed into a
- * bitset by bitwise ORing the <tt>ATTR_*</tt> constants. Setting the
- * value returned by <tt>getAttributes</tt> will result in both files
- * having the same attributes.
+    /**
+     * Set the attributes of this files. Attributes are composed into a
+     * bitset by bitwise ORing the <tt>ATTR_*</tt> constants. Setting the
+     * value returned by <tt>getAttributes</tt> will result in both files
+     * having the same attributes.
+     *
- * @throws SmbException
- */
+     * @throws SmbException
+     */
-    public void setAttributes( int attrs ) throws SmbException {
+    public void setAttributes(int attrs) throws SmbException {
-        if( getUncPath0().length() == 1 ) {
+        if (getUncPath0().length() == 1) {
-            throw new SmbException( "Invalid operation for workgroups, servers, or shares" );
+            throw new SmbException("Invalid operation for workgroups, servers, or shares");
         }
-        setPathInformation( attrs & ATTR_SET_MASK, 0L, 0L );
+        setPathInformation(attrs & ATTR_SET_MASK, 0L, 0L);
     }

-/**
- * Make this files read-only. This is shorthand for <tt>setAttributes(
- * getAttributes() | ATTR_READ_ONLY )</tt>.
- *
- * @throws SmbException
- */
+    /**
+     * Make this files read-only. This is shorthand for <tt>setAttributes(
+     * getAttributes() | ATTR_READ_ONLY )</tt>.
+     *
+     * @throws SmbException
+     */
     public void setReadOnly() throws SmbException {
-        setAttributes( getAttributes() | ATTR_READONLY );
+        setAttributes(getAttributes() | ATTR_READONLY);
     }

-/**
- * Turn off the read-only attribute of this files. This is shorthand for
- * <tt>setAttributes( getAttributes() & ~ATTR_READONLY )</tt>.
- *
- * @throws SmbException
- */
+    /**
+     * Turn off the read-only attribute of this files. This is shorthand for
+     * <tt>setAttributes( getAttributes() & ~ATTR_READONLY )</tt>.
+     *
+     * @throws SmbException
+     */
     public void setReadWrite() throws SmbException {
-        setAttributes( getAttributes() & ~ATTR_READONLY );
+        setAttributes(getAttributes() & ~ATTR_READONLY);
     }

-/**
- * Returns a {@link java.net.URL} for this <code>SmbFile</code>. The
- * <code>URL</code> may be used as any other <code>URL</code> might to
- * access an SMB resource. Currently only retrieving data and information
- * is supported (i.e. no <tt>doOutput</tt>).
- *
+    /**
+     * Returns a {@link java.net.URL} for this <code>SmbFile</code>. The
+     * <code>URL</code> may be used as any other <code>URL</code> might to
+     * access an SMB resource. Currently only retrieving data and information
+     * is supported (i.e. no <tt>doOutput</tt>).
+     *
- * @deprecated Use getURL() instead
- * @return A new <code>{@link java.net.URL}</code> for this <code>SmbFile</code>
- * @throws MalformedURLException
+     * @return A new <code>{@link java.net.URL}</code> for this <code>SmbFile</code>
+     * @throws MalformedURLException
+     * @deprecated Use getURL() instead
- */
+     */
     public URL toURL() throws MalformedURLException {
         return url;
     }

-/**
- * Computes a hashCode for this files based on the URL string and IP
- * address if the server. The hashing function uses the hashcode of the
- * server address, the canonical representation of the URL, and does not
- * compare authentication information. In essance, two
- * <code>SmbFile</code> objects that refer to
- * the same files should generate the same hashcode provided it is possible
- * to make such a determination.
- *
+    /**
+     * Computes a hashCode for this files based on the URL string and IP
+     * address if the server. The hashing function uses the hashcode of the
+     * server address, the canonical representation of the URL, and does not
+     * compare authentication information. In essance, two
+     * <code>SmbFile</code> objects that refer to
+     * the same files should generate the same hashcode provided it is possible
+     * to make such a determination.
+     *
- * @return  A hashcode for this abstract files
+     * @return A hashcode for this abstract files
- * @throws SmbException
- */
+     * @throws SmbException
+     */

     public int hashCode() {
         int hash;
         try {
             hash = getAddress().hashCode();
-        } catch( UnknownHostException uhe ) {
+        } catch (UnknownHostException uhe) {
             hash = getServer().toUpperCase().hashCode();
         }
         getUncPath0();
@@ -2705,32 +2739,33 @@

         return l1 == l2 && path1.regionMatches(true, p1, path2, p2, l1);
     }
+
-/**
- * Tests to see if two <code>SmbFile</code> objects are equal. Two
- * SmbFile objects are equal when they reference the same SMB
- * resource. More specifically, two <code>SmbFile</code> objects are
- * equals if their server IP addresses are equal and the canonicalized
- * representation of their URLs, minus authentication parameters, are
- * case insensitivly and lexographically equal.
- * <p/>
- * For example, assuming the server <code>angus</code> resolves to the
- * <code>192.168.1.15</code> IP address, the below URLs would result in
- * <code>SmbFile</code>s that are equal.
+    /**
+     * Tests to see if two <code>SmbFile</code> objects are equal. Two
+     * SmbFile objects are equal when they reference the same SMB
+     * resource. More specifically, two <code>SmbFile</code> objects are
+     * equals if their server IP addresses are equal and the canonicalized
+     * representation of their URLs, minus authentication parameters, are
+     * case insensitivly and lexographically equal.
+     * <p/>
+     * For example, assuming the server <code>angus</code> resolves to the
+     * <code>192.168.1.15</code> IP address, the below URLs would result in
+     * <code>SmbFile</code>s that are equal.
- *
+     * <p/>
- * <p><blockquote><pre>
- * smb://192.168.1.15/share/DIR/foo.txt
- * smb://angus/share/data/../dir/foo.txt
- * </pre></blockquote>
- *
+     * <p><blockquote><pre>
+     * smb://192.168.1.15/share/DIR/foo.txt
+     * smb://angus/share/data/../dir/foo.txt
+     * </pre></blockquote>
+     *
- * @param   obj Another <code>SmbFile</code> object to compare for equality
+     * @param obj Another <code>SmbFile</code> object to compare for equality
- * @return  <code>true</code> if the two objects refer to the same SMB resource
+     * @return <code>true</code> if the two objects refer to the same SMB resource
- *          and <code>false</code> otherwise
+     *         and <code>false</code> otherwise
- * @throws SmbException
- */
+     * @throws SmbException
+     */

-    public boolean equals( Object obj ) {
+    public boolean equals(Object obj) {
         if (obj instanceof SmbFile) {
-            SmbFile f = (SmbFile)obj;
+            SmbFile f = (SmbFile) obj;
             boolean ret;

             if (this == f)
@@ -2747,7 +2782,7 @@
                 if (canon.equalsIgnoreCase(f.canon)) {
                     try {
                         ret = getAddress().equals(f.getAddress());
-                    } catch( UnknownHostException uhe ) {
+                    } catch (UnknownHostException uhe) {
                         ret = getServer().equalsIgnoreCase(f.getServer());
                     }
                     return ret;
@@ -2763,77 +2798,78 @@
     }
 */

-/**
- * Returns the string representation of this SmbFile object. This will
- * be the same as the URL used to construct this <code>SmbFile</code>.
- * This method will return the same value
- * as <code>getPath</code>.
- *
+    /**
+     * Returns the string representation of this SmbFile object. This will
+     * be the same as the URL used to construct this <code>SmbFile</code>.
+     * This method will return the same value
+     * as <code>getPath</code>.
+     *
- * @return  The original URL representation of this SMB resource
+     * @return The original URL representation of this SMB resource
- * @throws SmbException
- */
+     * @throws SmbException
+     */

     public String toString() {
         return url.toString();
     }

 /* URLConnection implementation */
+
-/**
- * This URLConnection method just returns the result of <tt>length()</tt>.
- *
- * @return the length of this files or 0 if it refers to a directory
- */
+    /**
+     * This URLConnection method just returns the result of <tt>length()</tt>.
+     *
+     * @return the length of this files or 0 if it refers to a directory
+     */

     public int getContentLength() {
         try {
-            return (int)(length() & 0xFFFFFFFFL);
+            return (int) (length() & 0xFFFFFFFFL);
-        } catch( SmbException se ) {
+        } catch (SmbException se) {
         }
         return 0;
     }

-/**
- * This URLConnection method just returns the result of <tt>lastModified</tt>.
- *
- * @return the last modified data as milliseconds since Jan 1, 1970
- */
+    /**
+     * This URLConnection method just returns the result of <tt>lastModified</tt>.
+     *
+     * @return the last modified data as milliseconds since Jan 1, 1970
+     */
     public long getDate() {
         try {
             return lastModified();
-        } catch( SmbException se ) {
+        } catch (SmbException se) {
         }
         return 0L;
     }

-/**
- * This URLConnection method just returns the result of <tt>lastModified</tt>.
- *
- * @return the last modified data as milliseconds since Jan 1, 1970
- */
+    /**
+     * This URLConnection method just returns the result of <tt>lastModified</tt>.
+     *
+     * @return the last modified data as milliseconds since Jan 1, 1970
+     */
     public long getLastModified() {
         try {
             return lastModified();
-        } catch( SmbException se ) {
+        } catch (SmbException se) {
         }
         return 0L;
     }

-/**
- * This URLConnection method just returns a new <tt>SmbFileInputStream</tt> created with this files.
- *
- * @throws IOException thrown by <tt>SmbFileInputStream</tt> constructor
- */
+    /**
+     * This URLConnection method just returns a new <tt>SmbFileInputStream</tt> created with this files.
+     *
+     * @throws IOException thrown by <tt>SmbFileInputStream</tt> constructor
+     */
     public InputStream getInputStream() throws IOException {
-        return new SmbFileInputStream( this );
+        return new SmbFileInputStream(this);
     }

-/**
- * This URLConnection method just returns a new <tt>SmbFileOutputStream</tt> created with this files.
- *
- * @throws IOException thrown by <tt>SmbFileOutputStream</tt> constructor
- */
+    /**
+     * This URLConnection method just returns a new <tt>SmbFileOutputStream</tt> created with this files.
+     *
+     * @throws IOException thrown by <tt>SmbFileOutputStream</tt> constructor
+     */
     public OutputStream getOutputStream() throws IOException {
-        return new SmbFileOutputStream( this );
+        return new SmbFileOutputStream(this);
     }

     private void processAces(ACE[] aces, boolean resolveSids) throws IOException {
@@ -2861,55 +2897,103 @@
             }
         }
     }
+
+
-/**
+    /**
- * Return an array of Access Control Entry (ACE) objects representing
- * the security descriptor associated with this files or directory.
- * If no DACL is present, null is returned. If the DACL is empty, an array with 0 elements is returned.
- * @param resolveSids Attempt to resolve the SIDs within each ACE form
- * their numeric representation to their corresponding account names.
+     * -------------- MPRV PATCH -------------
+     * Get security descriptor
+     * @param resolveSids     true if the sids are resolved
+     * @return security descriptor
+     * @throws IOException
- */
+     */
-    public ACE[] getSecurity(boolean resolveSids) throws IOException {
+    public SecurityDescriptor getSecurityDescriptor(boolean resolveSids) throws IOException {
         int f;
         ACE[] aces;

-        f = open0( O_RDONLY, READ_CONTROL, 0, isDirectory() ? 1 : 0 );
+        f = open0(O_RDONLY, READ_CONTROL, 0, isDirectory() ? 1 : 0);

         /*
          * NtTrans Query Security Desc Request / Response
          */

-        NtTransQuerySecurityDesc request = new NtTransQuerySecurityDesc( f, 0x04 );
+        NtTransQuerySecurityDesc request = new NtTransQuerySecurityDesc(f, 0x04);
         NtTransQuerySecurityDescResponse response = new NtTransQuerySecurityDescResponse();

         try {
-            send( request, response );
+            send(request, response);
         } finally {
-            close( f, 0L );
+            close(f, 0L);
         }

-        aces = response.securityDescriptor.aces;
+        return response.securityDescriptor;
+    }
+
+    /**
+     * Return an array of Access Control Entry (ACE) objects representing
+     * the security descriptor associated with this files or directory.
+     * If no DACL is present, null is returned. If the DACL is empty, an array with 0 elements is returned.
+     *
+     * @param resolveSids Attempt to resolve the SIDs within each ACE form
+     *                    their numeric representation to their corresponding account names.
+     */
+    public ACE[] getSecurity(boolean resolveSids) throws IOException {
+        SecurityDescriptor sd = getSecurityDescriptor(resolveSids);
+        ACE[] aces = sd.aces;
         if (aces != null)
             processAces(aces, resolveSids);

         return aces;
     }
+
+
-/**
+    /**
+     * -------------- MPRV PATCH -------------
+     * @param sd security descriptor that will be revoked
+     * @param sid user/group for which the permission will be revoked
+     * @param maskToRevoke mask to revoke
+     * @return error code
+     * @throws IOException
+     */
+    public int revokePermission(SecurityDescriptor sd, SID sid, int maskToRevoke) throws IOException {
+        int f;
+
+        f = open0(O_RDWR, WRITE_DAC, 0, isDirectory() ? 1 : 0);
+
+        /*
+         * NtTrans Update Security Desc Request / Response
+         */
+
+        NtTransRevokePermissionInSecurityDesc request = new NtTransRevokePermissionInSecurityDesc(f, 0x04, sd, sid, maskToRevoke);
+        NtTransSetSecurityDescResponse response = new NtTransSetSecurityDescResponse();
+
+        try {
+            send(request, response);
+        } finally {
+            close(f, 0L);
+        }
+
+        return response.errorCode;
+
+    }
+
+    /**
- * Return an array of Access Control Entry (ACE) objects representing
- * the share permissions on the share exporting this files or directory.
- * If no DACL is present, null is returned. If the DACL is empty, an array with 0 elements is returned.
+     * Return an array of Access Control Entry (ACE) objects representing
+     * the share permissions on the share exporting this files or directory.
+     * If no DACL is present, null is returned. If the DACL is empty, an array with 0 elements is returned.
- * <p>
+     * <p/>
- * Note that this is different from calling <tt>getSecurity</tt> on a
- * share. There are actually two different ACLs for shares - the ACL on
- * the share and the ACL on the folder being shared.
- * Go to <i>Computer Management</i>
- * &gt; <i>System Tools</i> &gt; <i>Shared Folders</i> &gt <i>Shares</i> and
- * look at the <i>Properties</i> for a share. You will see two tabs - one
- * for "Share Permissions" and another for "Security". These correspond to
- * the ACLs returned by <tt>getShareSecurity</tt> and <tt>getSecurity</tt>
- * respectively.
+     * Note that this is different from calling <tt>getSecurity</tt> on a
+     * share. There are actually two different ACLs for shares - the ACL on
+     * the share and the ACL on the folder being shared.
+     * Go to <i>Computer Management</i>
+     * &gt; <i>System Tools</i> &gt; <i>Shared Folders</i> &gt <i>Shares</i> and
+     * look at the <i>Properties</i> for a share. You will see two tabs - one
+     * for "Share Permissions" and another for "Security". These correspond to
+     * the ACLs returned by <tt>getShareSecurity</tt> and <tt>getSecurity</tt>
+     * respectively.
+     *
- * @param resolveSids Attempt to resolve the SIDs within each ACE form
+     * @param resolveSids Attempt to resolve the SIDs within each ACE form
- * their numeric representation to their corresponding account names.
+     *                    their numeric representation to their corresponding account names.
- */
+     */
     public ACE[] getShareSecurity(boolean resolveSids) throws IOException {
         String p = url.getPath();
         MsrpcShareGetInfo rpc;
@@ -2932,7 +3016,7 @@
         } finally {
             try {
                 handle.close();
-            } catch(IOException ioe) {
+            } catch (IOException ioe) {
                 if (log.level >= 1)
                     ioe.printStackTrace(log);
             }
@@ -2940,62 +3024,60 @@

         return aces;
     }
+
-/**
- * Return an array of Access Control Entry (ACE) objects representing
- * the security descriptor associated with this files or directory.
+    /**
+     * Return an array of Access Control Entry (ACE) objects representing
+     * the security descriptor associated with this files or directory.
- * <p>
+     * <p/>
- * Initially, the SIDs within each ACE will not be resolved however when
- * <tt>getType()</tt>, <tt>getDomainName()</tt>, <tt>getAccountName()</tt>,
- * or <tt>toString()</tt> is called, the names will attempt to be
- * resolved. If the names cannot be resolved (e.g. due to temporary
- * network failure), the said methods will return default values (usually
- * <tt>S-X-Y-Z</tt> strings of fragments of).
+     * Initially, the SIDs within each ACE will not be resolved however when
+     * <tt>getType()</tt>, <tt>getDomainName()</tt>, <tt>getAccountName()</tt>,
+     * or <tt>toString()</tt> is called, the names will attempt to be
+     * resolved. If the names cannot be resolved (e.g. due to temporary
+     * network failure), the said methods will return default values (usually
+     * <tt>S-X-Y-Z</tt> strings of fragments of).
- * <p>
+     * <p/>
- * Alternatively <tt>getSecurity(true)</tt> may be used to resolve all
- * SIDs together and detect network failures.
- */
+     * Alternatively <tt>getSecurity(true)</tt> may be used to resolve all
+     * SIDs together and detect network failures.
+     */
     public ACE[] getSecurity() throws IOException {
         return getSecurity(false);
     }


-
     public SID getOwnerUser() throws IOException {
-      int f = open0( O_RDONLY, READ_CONTROL, 0, isDirectory() ? 1 : 0 );
+        int f = open0(O_RDONLY, READ_CONTROL, 0, isDirectory() ? 1 : 0);
-      try {
-          /*
-           * NtTrans Query Security Desc Request / Response
-           */
+        try {
+            /*
+            * NtTrans Query Security Desc Request / Response
+            */

-          NtTransQuerySecurityDesc request = new NtTransQuerySecurityDesc( f, 0x01 );
+            NtTransQuerySecurityDesc request = new NtTransQuerySecurityDesc(f, 0x01);
-          NtTransQuerySecurityDescResponse response = new NtTransQuerySecurityDescResponse();
+            NtTransQuerySecurityDescResponse response = new NtTransQuerySecurityDescResponse();
-          send( request, response );
+            send(request, response);
-          return response.securityDescriptor.owner_user;
-      }
-      finally {
+            return response.securityDescriptor.owner_user;
+        }
+        finally {
-        close( f, 0L );
+            close(f, 0L);
-      }
-  }
+        }
+    }

-  public SID getOwnerGroup() throws IOException {
+    public SID getOwnerGroup() throws IOException {
-      int f = open0( O_RDONLY, READ_CONTROL, 0, isDirectory() ? 1 : 0 );
+        int f = open0(O_RDONLY, READ_CONTROL, 0, isDirectory() ? 1 : 0);

-      try {
-          /*
-           * NtTrans Query Security Desc Request / Response
-           */
+        try {
+            /*
+            * NtTrans Query Security Desc Request / Response
+            */

-          NtTransQuerySecurityDesc request = new NtTransQuerySecurityDesc( f, 0x02 );
+            NtTransQuerySecurityDesc request = new NtTransQuerySecurityDesc(f, 0x02);
-          NtTransQuerySecurityDescResponse response = new NtTransQuerySecurityDescResponse();
+            NtTransQuerySecurityDescResponse response = new NtTransQuerySecurityDescResponse();
-          send( request, response );
+            send(request, response);

-          close( f, 0L );
-
-          return response.securityDescriptor.owner_group;
-      }
-      finally {
+            return response.securityDescriptor.owner_group;
+        }
+        finally {
-          close( f, 0L );
+            close(f, 0L);
-      }
-  }
+        }
+    }

 }
Index: src/jcifs/smb/ServerMessageBlock.java
===================================================================
--- src/jcifs/smb/ServerMessageBlock.java	(revision 67850)
+++ src/jcifs/smb/ServerMessageBlock.java	(revision )
@@ -52,6 +52,21 @@
         dst[++dstIndex] = (byte)(val >>= 8);
         dst[++dstIndex] = (byte)(val >> 8);
     }
+
+    /**
+     * -------------- MPRV PATCH -------------
+     * Write bytes from source arrayace to destination array
+     * @param src source byte array
+     * @param dst destination byte array
+     * @param dstIndex starting index in destination array
+     * @return number of written bytes
+     */
+    static int writeByteArr( byte[] src, byte[] dst, int dstIndex ) {
+        for(int i = 0; i < src.length; i++){
+            dst[dstIndex + i] = src[i];
+        }
+        return src.length;
+    }
     static int readInt2( byte[] src, int srcIndex ) {
         return ( src[srcIndex] & 0xFF ) +
                 (( src[srcIndex + 1] & 0xFF ) << 8 );
Index: src/jcifs/smb/SmbComNtTransaction.java
===================================================================
--- src/jcifs/smb/SmbComNtTransaction.java	(revision 67850)
+++ src/jcifs/smb/SmbComNtTransaction.java	(revision )
@@ -25,6 +25,11 @@
     private static final int NTT_SECONDARY_PARAMETER_OFFSET  = 51;

     static final int NT_TRANSACT_QUERY_SECURITY_DESC = 6;
+    //-------------- MPRV PATCH -------------
+    /**
+     * set security transaction code
+     */
+    static final int NT_TRANSACT_SET_SECURITY_DESC = 3;

     int function;

Index: src/jcifs/smb/ACE.java
===================================================================
--- src/jcifs/smb/ACE.java	(revision 67850)
+++ src/jcifs/smb/ACE.java	(revision )
@@ -152,6 +152,60 @@
         return size;
     }

+    /**
+     * -------------- MPRV PATCH -------------
+     * Encode ACE into byte array
+     * @param buf destination array
+     * @param bi starting index in the destination array
+     * @return size of the ace (number of bytes)
+     */
+    int encode( byte[] buf, int bi ) {
+        return encode(buf,bi,null);
+    }
+
+    /**
+     * * -------------- MPRV PATCH -------------
+     * Encode ACE into byte array
+     * @param buf destination array
+     * @param bi starting index in the destination array
+     * @param aceAccess ace access mask to be encoded. In case of null, original ace access will be incoded
+     * @return size of the ace (number of bytes)
+     */
+    int encode( byte[] buf, int bi, Integer aceAccess ) {
+
+        buf[bi++] = allow ? (byte)0x00 : (byte)0x01;
+        buf[bi++] = (byte)flags;
+
+        int size = getACESize();
+        ServerMessageBlock.writeInt2(size,buf,bi);
+        bi+=2;
+
+        ServerMessageBlock.writeInt4(aceAccess != null ? aceAccess : access,buf,bi);
+        bi+=4;
+
+        byte[] sidArr = SID.toByteArray(sid);
+        ServerMessageBlock.writeByteArr(SID.toByteArray(sid),buf,bi);
+        bi+=sidArr.length;
+
+        return size;
+    }
+
+    /**
+     * -------------- MPRV PATCH -------------
+     * Get ACE size. ACE size is:
+     * isAllow - 1 byte
+     * flags - 1 byte
+     * size - 2 bytes
+     * access - 4 bytes
+     * sid - sizeOf(SID)
+     * ------------------------
+     * @return ACE size = num of bytes
+     */
+    int getACESize(){
+        byte[] sidArr = SID.toByteArray(sid);
+        return 1 + 1 + 2 + 4 + sidArr.length;
+    }
+
     void appendCol(StringBuffer sb, String str, int width) {
         sb.append(str);
         int count = width - str.length();