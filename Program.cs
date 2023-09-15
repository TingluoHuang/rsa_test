using System.Runtime.Serialization;
using System.Security.Cryptography;
using System.Text.Json;
using System;
using System.Diagnostics;
using System.IO;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;

#pragma warning disable CA1416

unsafe {
    // Do this first so we get the bare modules needed loaded.
    Console.WriteLine($"{SafeEvpPKeyHandle.OpenSslVersion:X8}");

    ProcessModule libShim = null;
    ProcessModule libCrypto = null;

    using Process currentProcess = Process.GetCurrentProcess();

    foreach (ProcessModule module in currentProcess.Modules) {
        Console.WriteLine(module.FileName);
        string fileName = Path.GetFileName(module.FileName);

        if (fileName.Equals("libSystem.Security.Cryptography.Native.OpenSsl.so", StringComparison.Ordinal)) {
            libShim = module;
        }
        else if (fileName.StartsWith("libcrypto.so", StringComparison.Ordinal)) {
            libCrypto = module;
        }
    }

    if (libShim is null) {
        throw new Exception("Crypto shim is not loaded.");
    }
    else {
        Console.WriteLine($"Shim path: {libShim.FileName}");
    }

    if (libCrypto is null) {
        throw new Exception("libcrypto is not loaded.");
    }
    else {
        Console.WriteLine($"libcrypto path: {libCrypto.FileName}");
    }

    IntPtr pLibCrypto = NativeLibrary.Load(libCrypto.FileName);
    IntPtr pLibShim = NativeLibrary.Load(libShim.FileName);

    // First, make sure we can reproduce the original problem.
    IntPtr pGetPkcs8PrivateKeySize = NativeLibrary.GetExport(pLibShim, "CryptoNative_GetPkcs8PrivateKeySize");
    IntPtr pEvpPkey2Pkcs8 = NativeLibrary.GetExport(pLibCrypto, "EVP_PKEY2PKCS8");
    IntPtr pErrPrintErrorCb = NativeLibrary.GetExport(pLibCrypto, "ERR_print_errors_cb");

    var funcGetPkcs8PrivateKeySize = (delegate* unmanaged[Cdecl]<IntPtr, out int, int>)pGetPkcs8PrivateKeySize;
    var funcEvpPkey2Pkcs8 = (delegate* unmanaged[Cdecl]<IntPtr, IntPtr>)pEvpPkey2Pkcs8;
    var funcErrPrintErrorCb = (delegate* unmanaged[Cdecl]<delegate* unmanaged[Cdecl]<byte*, IntPtr, void*, int>, void*, void>)pErrPrintErrorCb;

    Console.WriteLine("\nAttempting to reproduce original error.");
    Console.WriteLine(new string('-', 32));

    using (RSAOpenSsl rsaOpenSsl = new RSAOpenSsl(2048)) {
        using SafeEvpPKeyHandle keyHandle = rsaOpenSsl.DuplicateKeyHandle();
        IntPtr pKeyHandle = keyHandle.DangerousGetHandle();

        int result = funcGetPkcs8PrivateKeySize(pKeyHandle, out int p8Size);
        const int Success = 1;
        const int Error = -1;
        const int MissingPrivateKey = -2;

        switch (result) {
            case Success:
                Console.WriteLine("CryptoNative_GetPkcs8PrivateKeySize was successful.");
                Console.WriteLine($"The PKCS8 size is {p8Size}.");
                break;
            case Error:
                Console.WriteLine("CryptoNative_GetPkcs8PrivateKeySize errored.");
                break;
            case MissingPrivateKey:
                Console.WriteLine("CryptoNative_GetPkcs8PrivateKeySize reported no private key.");
                break;
        }
    }

    Console.WriteLine("\nAttempting native OpenSSL invocations.");
    Console.WriteLine(new string('-', 32));

    using (RSAOpenSsl rsaOpenSsl = new RSAOpenSsl(2048)) {
        // RSA dummy = RSA.Create(2048);
        // rsaOpenSsl.ImportParameters(dummy.ExportParameters(false));
        using SafeEvpPKeyHandle keyHandle = rsaOpenSsl.DuplicateKeyHandle();
        IntPtr pKeyHandle = keyHandle.DangerousGetHandle();

        IntPtr result = funcEvpPkey2Pkcs8(pKeyHandle);

        if (result == IntPtr.Zero) {
            Console.WriteLine("Export failed. Dumping OpenSSL error queue.");
            funcErrPrintErrorCb(&Callback, null);
        }
        else {
            Console.WriteLine($"Export succeeded. Handle is {result:X16}");
        }
    }
}

Console.WriteLine("Creating new ECDsa key");
using ECDsa ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
ECParameters p = ecdsa.ExportParameters(true);
Console.WriteLine($"ECDSA private key length: {p.D.Length}"); // Expecting 32

Console.WriteLine("Creating new RSA key using 2048-bit key length");

var rsa = RSA.Create(2048);
var rsaParameter = new RSAParametersSerializable(rsa.ExportParameters(true));
Console.WriteLine($"RSA private key length: {rsaParameter.D.Length}");


[UnmanagedCallersOnly(CallConvs = new[] { typeof(CallConvCdecl) })]
static unsafe int Callback(byte* str, IntPtr len, void* u) {
    string val = System.Text.Encoding.UTF8.GetString(str, len.ToInt32());
    Console.Write(val);
    return 1;
}


[Serializable]
internal class RSAParametersSerializable : ISerializable
{
    private RSAParameters _rsaParameters;

    public RSAParameters RSAParameters
    {
        get
        {
            return _rsaParameters;
        }
    }

    public RSAParametersSerializable(RSAParameters rsaParameters)
    {
        _rsaParameters = rsaParameters;
    }

    private RSAParametersSerializable()
    {
    }

    public byte[] D { get { return _rsaParameters.D; } set { _rsaParameters.D = value; } }

    public byte[] DP { get { return _rsaParameters.DP; } set { _rsaParameters.DP = value; } }

    public byte[] DQ { get { return _rsaParameters.DQ; } set { _rsaParameters.DQ = value; } }

    public byte[] Exponent { get { return _rsaParameters.Exponent; } set { _rsaParameters.Exponent = value; } }

    public byte[] InverseQ { get { return _rsaParameters.InverseQ; } set { _rsaParameters.InverseQ = value; } }

    public byte[] Modulus { get { return _rsaParameters.Modulus; } set { _rsaParameters.Modulus = value; } }

    public byte[] P { get { return _rsaParameters.P; } set { _rsaParameters.P = value; } }

    public byte[] Q { get { return _rsaParameters.Q; } set { _rsaParameters.Q = value; } }

    public RSAParametersSerializable(SerializationInfo information, StreamingContext context)
    {
        _rsaParameters = new RSAParameters()
        {
            D = (byte[])information.GetValue("d", typeof(byte[])),
            DP = (byte[])information.GetValue("dp", typeof(byte[])),
            DQ = (byte[])information.GetValue("dq", typeof(byte[])),
            Exponent = (byte[])information.GetValue("exponent", typeof(byte[])),
            InverseQ = (byte[])information.GetValue("inverseQ", typeof(byte[])),
            Modulus = (byte[])information.GetValue("modulus", typeof(byte[])),
            P = (byte[])information.GetValue("p", typeof(byte[])),
            Q = (byte[])information.GetValue("q", typeof(byte[]))
        };
    }

    public void GetObjectData(SerializationInfo info, StreamingContext context)
    {
        info.AddValue("d", _rsaParameters.D);
        info.AddValue("dp", _rsaParameters.DP);
        info.AddValue("dq", _rsaParameters.DQ);
        info.AddValue("exponent", _rsaParameters.Exponent);
        info.AddValue("inverseQ", _rsaParameters.InverseQ);
        info.AddValue("modulus", _rsaParameters.Modulus);
        info.AddValue("p", _rsaParameters.P);
        info.AddValue("q", _rsaParameters.Q);
    }
}
