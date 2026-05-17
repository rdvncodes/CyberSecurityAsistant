using System;
using System.Security.Cryptography;
using System.Text;

namespace CyberSecurityAssistant.Services
{
    /// <summary>
    /// Hassas verileri (API key, app password vb.) Windows DPAPI ile şifreler.
    /// Şifrelenmiş veri yalnızca aynı kullanıcı hesabıyla çözülebilir.
    /// Disk üzerinde Base64 olarak saklanır.
    ///
    /// Migration: eski (şifrelenmemiş) verileri ilk okumada otomatik algılar
    /// ve düz metin gibi geri döndürür. Çağıran taraf isterse hemen yeni
    /// formatla yeniden kaydedebilir.
    /// </summary>
    public static class SecureStore
    {
        // DPAPI'ye ek entropi — saldırgan başka bir uygulamadan çağırsa
        // bile yanlış key olur. Kaynak kodda olması güvenliği büyük ölçüde
        // azaltmaz çünkü DPAPI zaten kullanıcı oturumuna bağlıdır.
        private static readonly byte[] Entropy = Encoding.UTF8.GetBytes("SiberBelediye.Kalkani.v1");

        // Şifrelenmiş veriyi ayırt etmek için magic prefix
        private const string EncryptedPrefix = "ENC:v1:";

        public static string Encrypt(string plainText)
        {
            if (string.IsNullOrEmpty(plainText))
                return string.Empty;
            try
            {
                byte[] plainBytes = Encoding.UTF8.GetBytes(plainText);
                byte[] encBytes = ProtectedData.Protect(plainBytes, Entropy, DataProtectionScope.CurrentUser);
                return EncryptedPrefix + Convert.ToBase64String(encBytes);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"SecureStore.Encrypt failed: {ex.Message}");
                return plainText; // fallback — güvenlik gerilemesi ama veri kaybı olmaz
            }
        }

        /// <summary>
        /// Şifrelenmiş veriyi çözer. Eğer veri eski (şifrelenmemiş) formatta ise
        /// olduğu gibi döner — bu sayede mevcut kullanıcı verisi bozulmadan
        /// kademeli olarak yeni formata geçer.
        /// </summary>
        public static string Decrypt(string storedValue)
        {
            if (string.IsNullOrEmpty(storedValue))
                return string.Empty;

            if (!storedValue.StartsWith(EncryptedPrefix, StringComparison.Ordinal))
                return storedValue; // legacy / migration

            try
            {
                string base64 = storedValue.Substring(EncryptedPrefix.Length);
                byte[] encBytes = Convert.FromBase64String(base64);
                byte[] plainBytes = ProtectedData.Unprotect(encBytes, Entropy, DataProtectionScope.CurrentUser);
                return Encoding.UTF8.GetString(plainBytes);
            }
            catch (Exception ex)
            {
                System.Diagnostics.Debug.WriteLine($"SecureStore.Decrypt failed: {ex.Message}");
                return string.Empty;
            }
        }

        public static bool IsEncrypted(string storedValue)
        {
            return !string.IsNullOrEmpty(storedValue)
                && storedValue.StartsWith(EncryptedPrefix, StringComparison.Ordinal);
        }
    }
}
