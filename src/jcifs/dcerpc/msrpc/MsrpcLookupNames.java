package jcifs.dcerpc.msrpc;


public class MsrpcLookupNames extends lsarpc.LsarLookupNames {
    public MsrpcLookupNames(LsaPolicyHandle policyHandle, String names[]) {
   super(
       policyHandle,
       names,
       (short)1,
       0
   );

        ptype = 0;
        flags = DCERPC_FIRST_FRAG | DCERPC_LAST_FRAG;
    }
}
