Imports System.IO
Imports System.Security.Cryptography
Imports System.Text

Public Class KeyProtector
    Public Function Protect(entropy As Byte(), valueToEncrypt As Byte(), handle As String) As Integer
        Dim fStream As New FileStream(handle, FileMode.OpenOrCreate)
        Dim bytesWritten As Integer = EncryptDataToStream(valueToEncrypt, entropy, DataProtectionScope.LocalMachine,
                                                          fStream)
        fStream.Close()

        Return bytesWritten
    End Function
    Public Function UnProtect(entropy As Byte(), handle As String, bytesWritten as Integer) As Byte()
        Dim fStream As New FileStream(handle, FileMode.OpenOrCreate)
        Return DecryptDataFromStream(entropy, DataProtectionScope.LocalMachine, fStream, bytesWritten)
    End Function
    Private Function EncryptDataToStream(buffer() As Byte, entropy() As Byte, scope As DataProtectionScope, s As Stream) _
        As Integer
        If buffer.Length <= 0 Then
            Throw New ArgumentException("Buffer")
        End If
        If buffer Is Nothing Then
            Throw New ArgumentNullException("buffer")
        End If
        If Entropy.Length <= 0 Then
            Throw New ArgumentException("Entropy")
        End If
        If Entropy Is Nothing Then
            Throw New ArgumentNullException("entropy")
        End If
        If S Is Nothing Then
            Throw New ArgumentNullException("s")
        End If
        Dim length As Integer = 0

        ' Protect the data in memory. The result is stored in the same same array as the original data.
        Dim encrptedData As Byte() = ProtectedData.Protect(Buffer, Entropy, Scope)

        ' Write the encrypted data to a stream.
        If S.CanWrite AndAlso Not (encrptedData Is Nothing) Then
            S.Write(encrptedData, 0, encrptedData.Length)

            length = encrptedData.Length
        End If

        ' Return the length that was written to the stream. 
        Return length
    End Function 'EncryptDataToStream
    Function DecryptDataFromStream(ByVal Entropy() As Byte, ByVal Scope As DataProtectionScope, ByVal S As Stream,
                                   ByVal Length As Integer) As Byte()
        If S Is Nothing Then
            Throw New ArgumentNullException("S")
        End If
        If Length <= 0 Then
            Throw New ArgumentException("Length")
        End If
        If Entropy Is Nothing Then
            Throw New ArgumentNullException("Entropy")
        End If
        If Entropy.Length <= 0 Then
            Throw New ArgumentException("Entropy")
        End If


        Dim inBuffer(Length) As Byte
        Dim outBuffer() As Byte

        ' Read the encrypted data from a stream.
        If S.CanRead Then
            S.Read(inBuffer, 0, Length)

            outBuffer = ProtectedData.Unprotect(inBuffer, Entropy, Scope)
        Else
            Throw New IOException("Could not read the stream.")
        End If

        ' Return the length that was written to the stream. 
        Return outBuffer
    End Function 'DecryptDataFromStream 
End Class
