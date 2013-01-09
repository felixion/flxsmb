/* jcifs smb client library in Java
 * Copyright (C) 2000  "Michael B. Allen" <jcifs at samba dot org>
 * 
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 * 
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 */

package jcifs.smb;

import java.io.UnsupportedEncodingException;

class SmbComTreeConnectAndXResponse extends AndXServerMessageBlock {

    private static final int SMB_SUPPORT_SEARCH_BITS = 0x0001;
    private static final int SMB_SHARE_IS_IN_DFS     = 0x0002;

    boolean supportSearchBits, shareIsInDfs;
    String service, nativeFileSystem = "";
    String filesystemType;

    SmbComTreeConnectAndXResponse( ServerMessageBlock andx ) {
        super( andx );
    }

    int writeParameterWordsWireFormat( byte[] dst, int dstIndex ) {
        return 0;
    }
    int writeBytesWireFormat( byte[] dst, int dstIndex ) {
        return 0;
    }
    int readParameterWordsWireFormat( byte[] buffer, int bufferIndex ) {
        supportSearchBits = ( buffer[bufferIndex] & SMB_SUPPORT_SEARCH_BITS ) == SMB_SUPPORT_SEARCH_BITS;
        shareIsInDfs = ( buffer[bufferIndex] & SMB_SHARE_IS_IN_DFS ) == SMB_SHARE_IS_IN_DFS;
        return 2;
    }
    int readBytesWireFormat( byte[] buffer, int bufferIndex ) {
        int start = bufferIndex;

        int len = readStringLength( buffer, bufferIndex, 32 );
        try {
            service = new String( buffer, bufferIndex, len, "ASCII" );

            bufferIndex += len + 1;

            int filesystemTypeLength = readUnicodeLength(buffer, bufferIndex, 32);
            filesystemType = new String(buffer, bufferIndex, filesystemTypeLength, UNI_ENCODING);

            bufferIndex += filesystemTypeLength + 2;

        } catch( UnsupportedEncodingException uee ) {
            return 0;
        }

        // win98 observed not returning nativeFileSystem
/* Problems here with iSeries returning ASCII even though useUnicode = true
 * Fortunately we don't really need nativeFileSystem for anything.
        if( byteCount > bufferIndex - start ) {
            nativeFileSystem = readString( buffer, bufferIndex );
            bufferIndex += stringWireLength( nativeFileSystem, bufferIndex );
        }
*/

        return bufferIndex - start;
    }
    public String toString() {
        String result = new String( "SmbComTreeConnectAndXResponse[" +
            super.toString() +
            ",supportSearchBits=" + supportSearchBits +
            ",shareIsInDfs=" + shareIsInDfs +
            ",service=" + service +
            ",nativeFileSystem=" + nativeFileSystem + "]" );
        return result;
    }

    /**
     * Determines the length of a unicode string by reading forward to find the 0x0000
     */
    int readUnicodeLength( byte[] src, int srcIndex, int max ) {

        for (int i = 0; i < max - 1; i++)
        {
            if (src[srcIndex + i] == (byte)0x00 && src[srcIndex + i + 1] == (byte)0x00)
            {
                return i + 1;
            }
        }

        throw new RuntimeException( "zero termination not found: " + this );
    }
}

