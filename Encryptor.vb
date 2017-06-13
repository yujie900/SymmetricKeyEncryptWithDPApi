Imports System.IO
Imports System.Security.Cryptography
Imports System.Text

Public Class Encryptor
    Public Function Encrypt(valueToEncrypt As String, handle As String) As Integer
        Dim toEncrypt As Byte() = Encoding.ASCII.GetBytes(valueToEncrypt)
        Dim entropy(15) As Byte
        Dim provider As New RNGCryptoServiceProvider()
        provider.GetBytes(entropy)
        Dim fStream As New FileStream(handle, FileMode.OpenOrCreate)
        Dim bytesWritten As Integer = EncryptDataToStream(toEncrypt, entropy, DataProtectionScope.LocalMachine, fStream)
        fStream.Close()

        Return bytesWritten
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

        ' Encrypt the data in memory. The result is stored in the same same array as the original data.
        Dim encrptedData As Byte() = ProtectedData.Protect(Buffer, Entropy, Scope)

        ' Write the encrypted data to a stream.
        If S.CanWrite AndAlso Not (encrptedData Is Nothing) Then
            S.Write(encrptedData, 0, encrptedData.Length)

            length = encrptedData.Length
        End If

        ' Return the length that was written to the stream. 
        Return length
    End Function 'EncryptDataToStream
End Class
